package com.dts.entry.identityservice.service.impl;

import com.dts.entry.identityservice.consts.Error;
import com.dts.entry.identityservice.exception.AppException;
import com.dts.entry.identityservice.model.Account;
import com.dts.entry.identityservice.model.Role;
import com.dts.entry.identityservice.model.enumerable.Status;
import com.dts.entry.identityservice.repository.AccountRepository;
import com.dts.entry.identityservice.repository.RoleRepository;
import com.dts.entry.identityservice.service.AuthService;
import com.dts.entry.identityservice.viewmodel.IntrospectRequest;
import com.dts.entry.identityservice.viewmodel.request.SignUpRequest;
import com.dts.entry.identityservice.viewmodel.response.IntrospectResponse;
import com.dts.entry.identityservice.viewmodel.response.SignInResponse;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;

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

    AccountRepository accountRepository;
    RoleRepository roleRepository;
    ObjectProvider<PasswordEncoder> passwordEncoder;

    @Override
    public SignInResponse signIn(String username, String password) {
        return null;
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
}
