package com.dts.entry.identityservice.controller;

import com.dts.entry.identityservice.service.AuthService;
import com.dts.entry.identityservice.utils.CookieUtils;
import com.dts.entry.identityservice.viewmodel.request.IntrospectRequest;
import com.dts.entry.identityservice.viewmodel.request.*;
import com.dts.entry.identityservice.viewmodel.response.BaseResponse;
import com.dts.entry.identityservice.viewmodel.response.IntrospectResponse;
import com.dts.entry.identityservice.viewmodel.response.SignInResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import jakarta.annotation.security.PermitAll;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;

@RestController
@RequestMapping("/auth")
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class AuthController {

    AuthService authService;

    @PostMapping("/sign-up")
    @PermitAll
    public ResponseEntity<?> signUp(@RequestBody SignUpRequest request) {
        authService.signUp(request);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @PostMapping("/sign-in")
    @PermitAll
    public ResponseEntity<BaseResponse<SignInResponse>> signIn(@RequestBody SignInRequest request,
                                                               HttpServletResponse httpServletResponse) {
        SignInResponse response = authService.signIn(request.email(), request.passsword());
        BaseResponse<SignInResponse> body = BaseResponse.<SignInResponse>builder()
                .message("Sign in successfully")
                .data(response)
                .build();
        CookieUtils.setTokenCookies(httpServletResponse, response);
        return ResponseEntity.ok(body);
    }

    @PostMapping("/send-otp")
    @PermitAll
    public ResponseEntity<?> sendOtp(@RequestBody SendOtpRequest request) throws JsonProcessingException {
        authService.sendOtp(request.email());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/verify-otp")
    @PermitAll
    public ResponseEntity<BaseResponse<SignInResponse>> verifyOtp(@RequestBody VerifyOtpRequest request,
                                                                  HttpServletResponse response)
            throws JsonProcessingException {
        SignInResponse data = authService.verifyOtp(request.email(), request.otp());
        BaseResponse<SignInResponse> body = BaseResponse.<SignInResponse>builder()
                .message("Verify OTP successfully")
                .data(data)
                .build();
        CookieUtils.setTokenCookies(response, data);
        return ResponseEntity.ok(body);
    }

    @GetMapping("/verify-email/status")
    @PermitAll
    public ResponseEntity<BaseResponse<VerifiedStatus>> isEmailVerified(@RequestParam String email) {
        VerifiedStatus isVerified = authService.isEmailVerified(email);
        BaseResponse<VerifiedStatus> body = BaseResponse.<VerifiedStatus>builder()
                .message("Check email verification status successfully")
                .data(isVerified)
                .build();
        return ResponseEntity.ok(body);
    }

    @PostMapping("/forgot-password")
    @PermitAll
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) throws JsonProcessingException {
        authService.forgotPassword(request.email());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reset-password")
    @PermitAll
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) throws JsonProcessingException {
        authService.resetPassword(request.email(), request.token(), request.newPassword());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/verify/reset-password-token")
    @PermitAll
    public ResponseEntity<BaseResponse<Void>> verifyResetPasswordToken(@RequestBody VerifyResetPasswordTokenRequest request) throws JsonProcessingException {
        authService.verifyResetPasswordToken(request.email(), request.token());
        BaseResponse<Void> body = BaseResponse.<Void>builder()
                .message("Verify reset password token successfully")
                .data(null)
                .build();
        return ResponseEntity.ok(body);
    }

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<BaseResponse<Void>> logout(HttpServletResponse response, HttpServletRequest request) {
        authService.logout(request);
        CookieUtils.revokeTokenCookies(response);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/refresh-token")
    @PermitAll
    public ResponseEntity<BaseResponse<SignInResponse>> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        SignInResponse signInResponse = authService.refreshToken(request);
        CookieUtils.setTokenCookies(response, signInResponse);
        BaseResponse<SignInResponse> body = BaseResponse.<SignInResponse>builder()
                .message("Refresh token successfully")
                .data(signInResponse)
                .build();
        return ResponseEntity.ok(body);
    }

    @PostMapping("/introspect")
    @PermitAll
    public ResponseEntity<BaseResponse<IntrospectResponse>> introspect(@RequestBody IntrospectRequest request) throws ParseException, JOSEException {
        IntrospectResponse response = authService.introspect(request);
        BaseResponse<IntrospectResponse> body = BaseResponse.<IntrospectResponse>builder()
                .message("Introspect token successfully")
                .data(response)
                .build();
        return ResponseEntity.ok(body);
    }

}
