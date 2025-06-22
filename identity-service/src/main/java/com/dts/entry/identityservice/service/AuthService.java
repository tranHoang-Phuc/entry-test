package com.dts.entry.identityservice.service;

import com.dts.entry.identityservice.viewmodel.request.AccountCreation;
import com.dts.entry.identityservice.viewmodel.request.IntrospectRequest;
import com.dts.entry.identityservice.viewmodel.request.SignUpRequest;
import com.dts.entry.identityservice.viewmodel.request.VerifiedStatus;
import com.dts.entry.identityservice.viewmodel.response.AccountCreationResponse;
import com.dts.entry.identityservice.viewmodel.response.AccountDetailResponse;
import com.dts.entry.identityservice.viewmodel.response.IntrospectResponse;
import com.dts.entry.identityservice.viewmodel.response.SignInResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Email;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.text.ParseException;
import java.util.UUID;

public interface AuthService {
    SignInResponse signIn(String username, String password);
    IntrospectResponse introspect(IntrospectRequest request) throws ParseException, JOSEException;
    ObjectProvider<PasswordEncoder> getPasswordEncoderProvider();
    void signUp(SignUpRequest request);

    void sendOtp(@Email String email) throws JsonProcessingException;

    SignInResponse verifyOtp(String email, String otp) throws JsonProcessingException;

    VerifiedStatus isEmailVerified(String email);

    void forgotPassword(String email) throws JsonProcessingException;

    void resetPassword(String email, String token, String newPassword) throws JsonProcessingException;

    void verifyResetPasswordToken(String email, String token) throws JsonProcessingException;

    void logout(HttpServletRequest request);

    SignInResponse refreshToken(HttpServletRequest request);

    boolean verifyRefreshToken(String refreshToken) throws ParseException, JOSEException;

    boolean verifyAccessToken(String accessToken) throws ParseException, JOSEException;
    void createProfile(String email, String firstName, String lastName, UUID accountId) ;

    AccountCreationResponse createAccount(AccountCreation accountCreation);

    AccountDetailResponse getAccountById(UUID id);
}
