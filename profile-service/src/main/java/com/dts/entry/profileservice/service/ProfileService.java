package com.dts.entry.profileservice.service;

import com.dts.entry.profileservice.viewmodel.request.ResetPasswordRequest;
import com.dts.entry.profileservice.viewmodel.request.UpdatedProfileRequest;
import com.dts.entry.profileservice.viewmodel.request.UserProfileCreation;
import com.dts.entry.profileservice.viewmodel.response.UserProfileResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Page;

import java.io.IOException;
import java.text.ParseException;
import java.util.UUID;

public interface ProfileService {

    UserProfileResponse getProfile(HttpServletRequest request) throws ParseException;

    UserProfileResponse updateProfile(UpdatedProfileRequest profileRequest, HttpServletRequest httpRequest)
            throws IOException, ParseException;

    Page<UserProfileResponse> getAllProfiles(int size, int page);

    UserProfileResponse createUser(UserProfileCreation userProfileCreation, HttpServletRequest request) throws IOException;

    UserProfileResponse getProfileAdmin(String profileId);

    void resetPasswordAdmin(UUID profileId, ResetPasswordRequest newPassword);
}
