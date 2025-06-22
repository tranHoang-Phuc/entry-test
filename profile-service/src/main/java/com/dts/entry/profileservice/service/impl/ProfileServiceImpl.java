package com.dts.entry.profileservice.service.impl;

import com.cloudinary.Cloudinary;
import com.dts.entry.event.AssignRoleEvent;
import com.dts.entry.event.BlockAccountEvent;
import com.dts.entry.event.ResetPasswordRequestEvent;
import com.dts.entry.profileservice.consts.CookieConstants;
import com.dts.entry.profileservice.consts.Error;
import com.dts.entry.profileservice.exception.AppException;
import com.dts.entry.profileservice.model.UserProfile;
import com.dts.entry.profileservice.repository.UserProfileRepository;
import com.dts.entry.profileservice.repository.client.AuthClient;
import com.dts.entry.profileservice.service.ProfileService;
import com.dts.entry.profileservice.utils.CookieUtils;
import com.dts.entry.profileservice.viewmodel.request.*;
import com.dts.entry.profileservice.viewmodel.response.UserProfileResponse;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import java.io.IOException;
import java.text.ParseException;
import java.time.LocalDate;
import java.util.Map;
import java.util.UUID;

@Service
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@RequiredArgsConstructor
public class ProfileServiceImpl implements ProfileService {
    UserProfileRepository userProfileRepository;
    Cloudinary cloudinary;
    AuthClient authClient;
    KafkaTemplate<String, Object> kafkaTemplate;

    @Value("${internal.secret}")
    @NonFinal
    String internalSecret;

    @Value("${kafka.topic.reset-password}")
    @NonFinal
    String resetPasswordTopic;

    @Value("${kafka.topic.block-user}")
    @NonFinal
    String blockUserTopic;

    @Value("${kafka.topic.assign-role}")
    @NonFinal
    String assignRoleTopic;

    @Override
    @Transactional(readOnly = true)
    public UserProfileResponse getProfile(HttpServletRequest request) throws ParseException {
        String accessToken = CookieUtils.getCookieValue(request, CookieConstants.ACCESS_TOKEN);
        String email = getEmailFromToken(accessToken);
        UserProfile userProfile = userProfileRepository.findByEmail(email);


        if(userProfile == null) {
            throw new AppException(Error.ErrorCode.USER_PROFILE_NOT_FOUND,
                    Error.ErrorCodeMessage.USER_PROFILE_NOT_FOUND, HttpStatus.NOT_FOUND.value());
        }
        // Check if the email in the token matches the email in the user profile
        if(!userProfile.getEmail().equals(email)) {
            throw new AppException(Error.ErrorCode.FORBIDDEN,
                    Error.ErrorCodeMessage.FORBIDDEN, HttpStatus.FORBIDDEN.value());
        }

        return UserProfileResponse.builder()
            .id(userProfile.getProfileId().toString())
            .dateOfBirth(userProfile.getDateOfBirth() == null ? null : userProfile.getDateOfBirth())
            .firstName(userProfile.getFirstName())
            .lastName(userProfile.getLastName())
            .email(userProfile.getEmail())
            .dateOfBirth(userProfile.getDateOfBirth() == null ? null : userProfile.getDateOfBirth())
            .imageUrl(userProfile.getImageUrl() == null ? null : userProfile.getImageUrl())
            .build();
    }

    @Override
    public UserProfileResponse updateProfile(UpdatedProfileRequest profileRequest,
                                             HttpServletRequest httpRequest) throws IOException, ParseException {
        String accessToken = CookieUtils.getCookieValue(httpRequest, CookieConstants.ACCESS_TOKEN);
        String email = getEmailFromToken(accessToken);
        UserProfile userProfile = userProfileRepository.findByEmail(email);

        if(userProfile == null) {
            throw new AppException(Error.ErrorCode.USER_PROFILE_NOT_FOUND,
                    Error.ErrorCodeMessage.USER_PROFILE_NOT_FOUND, HttpStatus.NOT_FOUND.value());
        }
        if(!userProfile.getEmail().equals(email)) {
            throw new AppException(Error.ErrorCode.FORBIDDEN,
                    Error.ErrorCodeMessage.FORBIDDEN, HttpStatus.FORBIDDEN.value());
        }

        MultipartHttpServletRequest multipartRequest = (MultipartHttpServletRequest) httpRequest;
        MultipartFile avatarImage = multipartRequest.getFile("avatar_image");
        if (avatarImage != null && !avatarImage.isEmpty()) {

            String contentType = avatarImage.getContentType();
            if (contentType == null || !contentType.startsWith("image/")) {
                throw new AppException(Error.ErrorCode.INVALID_IMAGE_TYPE,
                        Error.ErrorCodeMessage.INVALID_IMAGE_TYPE,
                        HttpStatus.BAD_REQUEST.value());
            }

            if (avatarImage.getSize() > 10 * 1024 * 1024) {
                throw new AppException(Error.ErrorCode.IMAGE_TOO_LARGE,
                        Error.ErrorCodeMessage.IMAGE_TOO_LARGE,
                        HttpStatus.BAD_REQUEST.value());
            }

            Map<?, ?> uploadResult = cloudinary.uploader().upload(avatarImage.getBytes(), Map.of());
            String imageUrl = (String) uploadResult.get("secure_url");
            userProfile.setImageUrl(imageUrl);
        }
        String firstName = httpRequest.getParameter("first_name");
        String lastName = httpRequest.getParameter("last_name");
        String dateOfBirthStr = httpRequest.getParameter("date_of_birth");
        if(firstName != null) {
            userProfile.setFirstName(firstName);
        }
        if(lastName != null) {
            userProfile.setLastName(lastName);
        }
        if(dateOfBirthStr != null) {
           userProfile.setDateOfBirth(LocalDate.parse(dateOfBirthStr));
        }

        userProfile = userProfileRepository.save(userProfile);


            return UserProfileResponse.builder()
                    .id(userProfile.getProfileId().toString())
                    .firstName(userProfile.getFirstName())
                    .lastName(userProfile.getLastName())
                    .email(userProfile.getEmail())
                    .dateOfBirth(userProfile.getDateOfBirth() == null ? null : userProfile.getDateOfBirth())
                    .imageUrl(userProfile.getImageUrl() == null ? null : userProfile.getImageUrl())
                    .build();
    }

    @Override
    @Transactional(readOnly = true)
    public Page<UserProfileResponse> getAllProfiles(int size, int page) {
        Pageable pageable = PageRequest.of(page, size);
        Page<UserProfile> userProfiles = userProfileRepository.findAll(pageable);
        if (userProfiles.isEmpty()) {
            return Page.empty();
        }
        return userProfiles.map(userProfile -> UserProfileResponse.builder()
                .id(userProfile.getProfileId().toString())
                .firstName(userProfile.getFirstName())
                .lastName(userProfile.getLastName())
                .email(userProfile.getEmail())
                .dateOfBirth(userProfile.getDateOfBirth() == null ? null : userProfile.getDateOfBirth())
                .imageUrl(userProfile.getImageUrl() == null ? null : userProfile.getImageUrl())
                .build());
    }

    @Override
    public UserProfileResponse createUser(UserProfileCreation userProfileCreation, HttpServletRequest request) throws IOException {
        UserProfile userProfile = userProfileRepository.findByEmail(userProfileCreation.getEmail());
        if (userProfile != null) {
            throw new AppException(Error.ErrorCode.USER_PROFILE_ALREADY_EXISTS,
                    Error.ErrorCodeMessage.USER_PROFILE_ALREADY_EXISTS, HttpStatus.BAD_REQUEST.value());
        }
        AccountCreation accountCreation = AccountCreation.builder()
                .email(userProfileCreation.getEmail())
                .password(userProfileCreation.getPassword())
                .firstName(userProfileCreation.getFirstName())
                .lastName(userProfileCreation.getLastName())
                .roles(userProfileCreation.getRoles())
                .build();

        String profileImageUrl = null;

        if (userProfileCreation.getProfilePicture() != null && !userProfileCreation.getProfilePicture() .isEmpty()) {

            String contentType = userProfileCreation.getProfilePicture() .getContentType();
            if (contentType == null || !contentType.startsWith("image/")) {
                throw new AppException(Error.ErrorCode.INVALID_IMAGE_TYPE,
                        Error.ErrorCodeMessage.INVALID_IMAGE_TYPE,
                        HttpStatus.BAD_REQUEST.value());
            }

            if (userProfileCreation.getProfilePicture() .getSize() > 10 * 1024 * 1024) {
                throw new AppException(Error.ErrorCode.IMAGE_TOO_LARGE,
                        Error.ErrorCodeMessage.IMAGE_TOO_LARGE,
                        HttpStatus.BAD_REQUEST.value());
            }

            Map<?, ?> uploadResult = cloudinary.uploader().upload(userProfileCreation.getProfilePicture() .getBytes(), Map.of());
            profileImageUrl = (String) uploadResult.get("secure_url");
        }
        var response = authClient.createAccount(accountCreation, internalSecret);

        UserProfile newUserProfile = UserProfile.builder()
                .email(userProfileCreation.getEmail())
                .firstName(userProfileCreation.getFirstName())
                .lastName(userProfileCreation.getLastName())
                .dateOfBirth(userProfileCreation.getBirthDate() == null ? null : userProfileCreation.getBirthDate())
                .imageUrl(profileImageUrl)
                .isDeleted(false)
                .accountId(UUID.fromString(response.data().accountId()))
                .build();
        UserProfile newProfile = userProfileRepository.save(newUserProfile);

        return UserProfileResponse.builder()
                .id(newProfile.getProfileId().toString())
                .firstName(newProfile.getFirstName())
                .lastName(newProfile.getLastName())
                .email(newProfile.getEmail())
                .dateOfBirth(newProfile.getDateOfBirth() == null ? null : newProfile.getDateOfBirth())
                .imageUrl(newProfile.getImageUrl() == null ? null : newProfile.getImageUrl())
                .build();

    }

    @Override
    public UserProfileResponse getProfileAdmin(String profileId) {
        UserProfile userProfile = userProfileRepository.findById(UUID.fromString(profileId))
                .orElseThrow(() -> new AppException(Error.ErrorCode.USER_PROFILE_NOT_FOUND,
                        Error.ErrorCodeMessage.USER_PROFILE_NOT_FOUND, HttpStatus.NOT_FOUND.value()));
        return UserProfileResponse.builder()
                .id(userProfile.getProfileId().toString())
                .firstName(userProfile.getFirstName())
                .lastName(userProfile.getLastName())
                .email(userProfile.getEmail())
                .dateOfBirth(userProfile.getDateOfBirth() == null ? null : userProfile.getDateOfBirth())
                .imageUrl(userProfile.getImageUrl() == null ? null : userProfile.getImageUrl())
                .build();
    }

    @Override
    @Transactional
    public void resetPasswordAdmin(UUID profileId, ResetPasswordRequest newPassword) {
        UserProfile userProfile = userProfileRepository.findByAccountId(profileId)
                .orElseThrow(() -> new AppException(Error.ErrorCode.USER_PROFILE_NOT_FOUND,
                        Error.ErrorCodeMessage.USER_PROFILE_NOT_FOUND, HttpStatus.NOT_FOUND.value()));
        if(!newPassword.confirmNewPassword().equals(newPassword.newPassword())) {
            throw new AppException(Error.ErrorCode.NOT_MATCHING,
                    Error.ErrorCodeMessage.NOT_MATCHING, HttpStatus.CONFLICT.value());
        }

        ResetPasswordRequestEvent resetPasswordRequest = ResetPasswordRequestEvent.builder()
                .accountId(userProfile.getAccountId())
                .newPassword(newPassword.newPassword())
                .build();
        kafkaTemplate.send(resetPasswordTopic, resetPasswordRequest);
        log.info("Reset password request sent for account ID: {}", userProfile.getAccountId());
    }

    @Override
    public void deleteUserAdmin(UUID profileId, HttpServletRequest request) throws ParseException {
        String accessToken = CookieUtils.getCookieValue(request, CookieConstants.ACCESS_TOKEN);
        String email = getEmailFromToken(accessToken);

        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(Error.ErrorCode.USER_PROFILE_NOT_FOUND,
                        Error.ErrorCodeMessage.USER_PROFILE_NOT_FOUND, HttpStatus.NOT_FOUND.value()));

        if(userProfile.getEmail().equals(email)) {
            throw new AppException(Error.ErrorCode.FORBIDDEN,
                    Error.ErrorCodeMessage.FORBIDDEN, HttpStatus.FORBIDDEN.value());
        }

        userProfile.setIsDeleted(true);
        userProfileRepository.save(userProfile);
        BlockAccountEvent blockAccountEvent = BlockAccountEvent.builder()
                .accountId(userProfile.getAccountId())
                .build();
        kafkaTemplate.send(blockUserTopic, blockAccountEvent);
        log.info("User with profile ID: {} has been soft deleted and account blocked", profileId);
    }

    @Override
    public void assignRoleAdmin(UUID profileId, AssignRoleRequest roleName, HttpServletRequest request) throws ParseException {
        String accessToken = CookieUtils.getCookieValue(request, CookieConstants.ACCESS_TOKEN);
        String email = getEmailFromToken(accessToken);

        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(Error.ErrorCode.USER_PROFILE_NOT_FOUND,
                        Error.ErrorCodeMessage.USER_PROFILE_NOT_FOUND, HttpStatus.NOT_FOUND.value()));

        if((email == userProfile.getEmail())) {
            roleName.roles().remove("ADMIN");
        }

        if(roleName.roles() == null || roleName.roles().isEmpty()) {
            throw new AppException(Error.ErrorCode.NOT_MATCHING,
                    Error.ErrorCodeMessage.NOT_MATCHING, HttpStatus.BAD_REQUEST.value());
        }

        AssignRoleEvent assignRoleEvent = AssignRoleEvent.builder()
                .accountId(userProfile.getAccountId())
                .roles(roleName.roles())
                .build();

        kafkaTemplate.send(assignRoleTopic, assignRoleEvent);
        log.info("Assign role event sent for account ID: {}", userProfile.getAccountId());

    }

    private String getEmailFromToken(String accessToken) throws ParseException {
        return SignedJWT.parse(accessToken).getJWTClaimsSet().getSubject() ;
    }


}

