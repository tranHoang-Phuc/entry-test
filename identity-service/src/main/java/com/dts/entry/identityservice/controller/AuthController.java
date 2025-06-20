package com.dts.entry.identityservice.controller;

import com.dts.entry.identityservice.service.AuthService;
import com.dts.entry.identityservice.viewmodel.request.SendOtpRequest;
import com.dts.entry.identityservice.viewmodel.request.SignInRequest;
import com.dts.entry.identityservice.viewmodel.request.SignUpRequest;
import com.dts.entry.identityservice.viewmodel.request.VerifyOtpRequest;
import com.dts.entry.identityservice.viewmodel.response.BaseResponse;
import com.dts.entry.identityservice.viewmodel.response.SignInResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.annotation.security.PermitAll;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
    public ResponseEntity<BaseResponse<SignInResponse>> signIn(@RequestBody SignInRequest request) {
        SignInResponse response = authService.signIn(request.email(), request.passsword());
        BaseResponse<SignInResponse> body = BaseResponse.<SignInResponse>builder()
                .message("Sign in successfully")
                .data(response)
                .build();
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
    public ResponseEntity<BaseResponse<SignInResponse>> verifyOtp(@RequestBody VerifyOtpRequest request) throws JsonProcessingException {
        SignInResponse data = authService.verifyOtp(request.email(), request.otp());
        BaseResponse<SignInResponse> body = BaseResponse.<SignInResponse>builder()
                .message("Verify OTP successfully")
                .data(data)
                .build();
        return ResponseEntity.ok(body);
    }


}
