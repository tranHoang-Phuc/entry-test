package com.dts.entry.identityservice.service.impl;

import com.dts.entry.event.EmailSendingRequest;
import com.dts.entry.event.RecipientUser;
import com.dts.entry.event.VerificationRequest;
import com.dts.entry.identityservice.consts.Error;
import com.dts.entry.identityservice.exception.AppException;
import com.dts.entry.identityservice.model.Account;
import com.dts.entry.identityservice.model.Role;
import com.dts.entry.identityservice.model.enumerable.Status;
import com.dts.entry.identityservice.repository.AccountRepository;
import com.dts.entry.identityservice.repository.RoleRepository;
import com.dts.entry.identityservice.service.AuthService;
import com.dts.entry.identityservice.service.EmailTemplateService;
import com.dts.entry.identityservice.service.ForgotPasswordRateLimiter;
import com.dts.entry.identityservice.service.VerifyEmailRateLimiter;
import com.dts.entry.identityservice.viewmodel.IntrospectRequest;
import com.dts.entry.identityservice.viewmodel.request.SignUpRequest;
import com.dts.entry.identityservice.viewmodel.request.VerifiedStatus;
import com.dts.entry.identityservice.viewmodel.response.IntrospectResponse;
import com.dts.entry.identityservice.viewmodel.response.SignInResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;
import java.util.StringJoiner;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class AuthServiceImpl implements AuthService {

    @NonFinal
    @Value("${jwt.signerKey}")
    String SIGNER_KEY;

    @NonFinal
    @Value("${jwt.refreshable-duration}")
    long REFRESHABLE_DURATION;

    @NonFinal
    @Value("${jwt.issuer}")
    String ISSUER;

    @NonFinal
    @Value("${jwt.valid-duration}")
    long VALID_DURATION;

    @Value("${kafka.topic.user-verification}")
    @NonFinal
    String userVerificationTopic;

    @Value("${client.domain}")
    @NonFinal
    String clientDomain;

    AccountRepository accountRepository;
    RoleRepository roleRepository;
    ObjectProvider<PasswordEncoder> passwordEncoder;
    VerifyEmailRateLimiter verifyEmailRateLimiter;
    ForgotPasswordRateLimiter forgotPasswordRateLimiter;
    RedisService redisService;
    EmailTemplateService emailTemplateService;
    KafkaTemplate<String, Object> kafkaTemplate;


    @Override
    public SignInResponse signIn(String username, String password) {
        Account account = accountRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(Error.ErrorCode.USER_NOT_FOUND,
                        Error.ErrorCodeMessage.USER_NOT_FOUND, HttpStatus.NOT_FOUND.value()));
        if(account.getStatus() == Status.UNVERIFIED) {
            throw new AppException(Error.ErrorCode.USER_UNVERIFIED,
                    Error.ErrorCodeMessage.USER_UNVERIFIED, HttpStatus.FORBIDDEN.value());
        }

        if(account.getStatus() == Status.BLOCKED || account.getStatus() == Status.DELETED) {
            throw new AppException(Error.ErrorCode.USER_BLOCKED,
                    Error.ErrorCodeMessage.USER_BLOCKED, HttpStatus.FORBIDDEN.value());
        }

        if (!passwordEncoder.getIfAvailable().matches(password, account.getPassword())) {
            throw new AppException(Error.ErrorCode.UNAUTHORIZED,
                    Error.ErrorCodeMessage.UNAUTHORIZED, HttpStatus.UNAUTHORIZED.value());
        }
        var accessToken = generateAccessToken(account);
        var refreshToken = generateRefeshToken(account);

        return SignInResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(VALID_DURATION)
                .build();
    }

    @Override
    public IntrospectResponse introspect(IntrospectRequest request) throws ParseException, JOSEException {
        var token = request.accessToken();
        boolean isValid = true;

        try {
            verifyToken(token, false);
        } catch (AppException e) {
            isValid = false;
        }

        return IntrospectResponse.builder().isValid(isValid).build();
    }



    @Override
    public void signUp(SignUpRequest request) {
        Role userRole = roleRepository.findByName("USER").orElseThrow(
                () -> new AppException(Error.ErrorCode.ROLE_NOT_FOUND,
                        Error.ErrorCodeMessage.ROLE_NOT_FOUND, HttpStatus.NOT_FOUND.value()));


        if (accountRepository.existsByUsername((request.username()))) {
            throw new AppException(Error.ErrorCode.USERNAME_ALREADY_EXISTS,
                    Error.ErrorCodeMessage.USERNAME_ALREADY_EXISTS, HttpStatus.CONFLICT.value());
        }

        Account account = Account.builder()
                .username(request.username())
                .password(passwordEncoder.getIfAvailable().encode(request.password()))
                .roles(Set.of(userRole))
                .status(Status.UNVERIFIED)
                .build();

        accountRepository.save(account);

        log.info("Account {} created successfully", account.getUsername());
    }

    @Override
    public void sendOtp(String email) throws JsonProcessingException {
        if (verifyEmailRateLimiter.isBlocked(email)) {
            throw new AppException(Error.ErrorCodeMessage.VERIFY_EMAIL_RATE_LIMIT,
                    Error.ErrorCode.VERIFY_EMAIL_RATE_LIMIT, HttpStatus.TOO_MANY_REQUESTS.value());
        }

        var account = accountRepository.findByUsername(email)
                .orElseThrow(() -> new AppException(Error.ErrorCode.USER_NOT_FOUND,
                        Error.ErrorCodeMessage.USER_NOT_FOUND, HttpStatus.NOT_FOUND.value()));

        if(account.getStatus() == Status.BLOCKED || account.getStatus() == Status.DELETED) {
            throw new AppException(Error.ErrorCode.USER_BLOCKED,
                    Error.ErrorCodeMessage.USER_BLOCKED, HttpStatus.FORBIDDEN.value());
        }

        if (account.getStatus() == Status.VERIFIED) {
            // Set cookie
            return;
        }

        String otp = generateAndStoreOtp(email);
        verifyEmailRateLimiter.recordAttempt(email);

        // gui vao kafka de consume
        VerificationRequest verificationRequest = VerificationRequest.builder()
                .token(otp)
                .build();
        String htmlContent = emailTemplateService.buildVerificationEmail(otp);

        RecipientUser recipientUser = RecipientUser.builder()
                .email(email)
                .firstName(account.getFirstName())
                .lastName(account.getLastName())
                .userId(account.getAccountId())
                .build();
        EmailSendingRequest<VerificationRequest> emailSendingRequest = EmailSendingRequest.<VerificationRequest>builder()
                .recipientUser(recipientUser)
                .htmlContent(htmlContent).subject("Verify email")
                .data(verificationRequest)
                .build();
        log.info("Sending email verification request {}", email);
        kafkaTemplate.send(userVerificationTopic, emailSendingRequest);
    }

    @Override
    public SignInResponse verifyOtp(String email, String otp) throws JsonProcessingException {
        String otpInCache = redisService.getValue("otp:" + email, String.class);
        if (otpInCache == null) {
            throw new AppException(Error.ErrorCodeMessage.INVALID_VERIFIED_TOKEN,
                    Error.ErrorCode.INVALID_VERIFIED_TOKEN, HttpStatus.CONFLICT.value());
        }
        if (!otpInCache.equals(otp)) {
            throw new AppException(Error.ErrorCodeMessage.INVALID_VERIFIED_TOKEN,
                    Error.ErrorCode.INVALID_VERIFIED_TOKEN,  HttpStatus.CONFLICT.value());
        }

        Account account = accountRepository.findByUsername(email)
                .orElseThrow(() -> new AppException(Error.ErrorCode.USER_NOT_FOUND,
                        Error.ErrorCodeMessage.USER_NOT_FOUND, HttpStatus.NOT_FOUND.value()));
        if(account.getStatus() == Status.UNVERIFIED) {
            account.setStatus(Status.VERIFIED);
            accountRepository.save(account);
            log.info("Account {} verified successfully", account.getUsername());

            String accessToken = generateAccessToken(account);
            String refreshToken = generateRefeshToken(account);

            return SignInResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(VALID_DURATION)
                    .build();
        }
        throw new AppException(Error.ErrorCodeMessage.USER_BLOCKED,
                Error.ErrorCode.USER_BLOCKED, HttpStatus.CONFLICT.value());
    }

    @Override
    public VerifiedStatus isEmailVerified(String email) {
        Account account = accountRepository.findByUsername(email)
                .orElseThrow(() -> new AppException(Error.ErrorCode.USER_NOT_FOUND,
                        Error.ErrorCodeMessage.USER_NOT_FOUND, HttpStatus.NOT_FOUND.value()));
        return VerifiedStatus.builder()
                .email(email)
                .verified(account.getStatus() == Status.VERIFIED)
                .build();
    }

    @Override
    public void forgotPassword(String email) throws JsonProcessingException {
        Account account = accountRepository.findByUsername(email)
                .orElseThrow(() -> new AppException(Error.ErrorCode.USER_NOT_FOUND,
                        Error.ErrorCodeMessage.USER_NOT_FOUND, HttpStatus.NOT_FOUND.value()));
        if (account.getStatus() == Status.BLOCKED || account.getStatus() == Status.DELETED) {
            throw new AppException(Error.ErrorCode.USER_BLOCKED,
                    Error.ErrorCodeMessage.USER_BLOCKED, HttpStatus.FORBIDDEN.value());
        }
        if (account.getStatus() == Status.UNVERIFIED) {
            throw new AppException(Error.ErrorCode.USER_UNVERIFIED,
                    Error.ErrorCodeMessage.USER_UNVERIFIED, HttpStatus.FORBIDDEN.value());
        }

        if (forgotPasswordRateLimiter.isBlocked(email)) {
            throw new AppException(Error.ErrorCodeMessage.FORGOT_PASSWORD_RATE_LIMIT,
                    Error.ErrorCode.FORGOT_PASSWORD_RATE_LIMIT, HttpStatus.TOO_MANY_REQUESTS.value());
        }

        String token = generateAndStoreForgotPasswordToken(email);
        forgotPasswordRateLimiter.recordAttempt(email);
        String url = clientDomain + "/reset?token=" + token + "&email=" + email ;

        VerificationRequest verificationRequest = VerificationRequest.builder()
                .token(token)
                .build();
        String htmlContent = emailTemplateService.buildForgotPasswordEmail(url);
        RecipientUser recipientUser = RecipientUser.builder()
                .email(email)
                .firstName(account.getFirstName())
                .lastName(account.getLastName())
                .userId(account.getAccountId())
                .build();
        EmailSendingRequest<VerificationRequest> emailSendingRequest = EmailSendingRequest.<VerificationRequest>builder()
                .recipientUser(recipientUser)
                .htmlContent(htmlContent).subject("Forgot password")
                .data(verificationRequest)
                .build();
        log.info("Sending forgot password email to {}", email);
        kafkaTemplate.send(userVerificationTopic, emailSendingRequest);
        log.info("Forgot password token generated and sent to {}", email);
    }

    private String generateAndStoreForgotPasswordToken(String email) {
        String token = generateForgotPasswordToken(email);
        String redisKey = "forgot-password-token:" + email;
        try {
            redisService.saveValue(redisKey, token, Duration.ofMinutes(VALID_DURATION));
        } catch (JsonProcessingException e) {
            throw new AppException(
                    Error.ErrorCodeMessage.UNCATEGORIZED_EXCEPTION,
                    Error.ErrorCodeMessage.UNCATEGORIZED_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR.value()
            );
        }
        return token;
    }
    private String generateForgotPasswordToken(String email) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        Instant now = Instant.now();
        Date issueTime = Date.from(now);
        Date expirationTime = Date.from(now.plusSeconds(VALID_DURATION));

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(email)
                .issuer(ISSUER)
                .issueTime(issueTime)
                .jwtID(UUID.randomUUID().toString())
                .claim("type", "forgot_password")
                .expirationTime(expirationTime)
                .build();

        JWSObject jwsObject = new JWSObject(header, new Payload(jwtClaimsSet.toJSONObject()));

        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes(StandardCharsets.UTF_8)));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            throw new AppException(
                    Error.ErrorCode.UNAUTHORIZED,
                    Error.ErrorCodeMessage.UNAUTHORIZED,
                    HttpStatus.UNAUTHORIZED.value()
            );
        }
    }

    private SignedJWT verifyToken(String token, boolean isRefresh) throws JOSEException, ParseException {
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());

        SignedJWT signedJWT = SignedJWT.parse(token);

        Date expiryTime = (isRefresh)
                ? new Date(signedJWT
                .getJWTClaimsSet()
                .getIssueTime()
                .toInstant()
                .plus(REFRESHABLE_DURATION, ChronoUnit.SECONDS)
                .toEpochMilli())
                : signedJWT.getJWTClaimsSet().getExpirationTime();

        var verified = signedJWT.verify(verifier);

        if (!(verified && expiryTime.after(new Date()))) throw new AppException(Error.ErrorCode.UNAUTHORIZED,
                Error.ErrorCodeMessage.UNAUTHORIZED, HttpStatus.UNAUTHORIZED.value());

//        if (invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID()))
//            throw new AppException(ErrorCode.UNAUTHENTICATED);

        return signedJWT;
    }

    private String generateAccessToken(Account account) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(account.getUsername())
                .issuer(ISSUER)
                .issueTime(new Date())
                .expirationTime(new Date(
                        Instant.now().plus(VALID_DURATION, ChronoUnit.SECONDS).toEpochMilli()))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", buildScope(account))
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            throw new AppException(
                    Error.ErrorCode.UNAUTHORIZED,
                    Error.ErrorCodeMessage.UNAUTHORIZED, HttpStatus.UNAUTHORIZED.value()
            );
        }
    }

    private String buildScope(Account account) {
        StringJoiner stringJoiner = new StringJoiner(" ");

        if (!CollectionUtils.isEmpty(account.getRoles()))
            account.getRoles().forEach(role -> {
                stringJoiner.add("ROLE_" + role.getName());
                if (!CollectionUtils.isEmpty(role.getPermissions()))
                    role.getPermissions().forEach(permission -> stringJoiner.add(permission.getName()));
            });

        return stringJoiner.toString();
    }

    private String generateRefeshToken(Account account) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(account.getUsername())
                .issuer(ISSUER)
                .issueTime(new Date())
                .jwtID(UUID.randomUUID().toString())
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());
        JWSObject jwsObject = new JWSObject(header, payload);

        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            throw new AppException(Error.ErrorCode.UNAUTHORIZED,
                    Error.ErrorCodeMessage.UNAUTHORIZED, HttpStatus.UNAUTHORIZED.value());
        }
    }

    private String generateAndStoreOtp(String email) {
        String otp = generateOTP();

        String redisKey = "otp:" + email;
        try {
            redisService.saveValue(redisKey, otp, Duration.ofMinutes(10));
        } catch (JsonProcessingException e) {
            throw new AppException(
                    Error.ErrorCodeMessage.UNCATEGORIZED_EXCEPTION,
                    Error.ErrorCodeMessage.UNCATEGORIZED_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR.value()
            );
        }
        return otp;
    }
    private String generateOTP() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            otp.append((int) (Math.random() * 10));
        }
        return otp.toString();
    }
}
