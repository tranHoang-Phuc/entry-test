package com.dts.entry.identityservice.service;

import com.dts.entry.identityservice.viewmodel.IntrospectRequest;
import com.dts.entry.identityservice.viewmodel.request.SignUpRequest;
import com.dts.entry.identityservice.viewmodel.response.IntrospectResponse;
import com.dts.entry.identityservice.viewmodel.response.SignInResponse;
import com.nimbusds.jose.JOSEException;
import jakarta.validation.constraints.Email;

import java.text.ParseException;

public interface AuthService {
    SignInResponse signIn(String username, String password);
    IntrospectResponse introspect(IntrospectRequest request) throws ParseException, JOSEException;

    void signUp(SignUpRequest request);

    void sendOtp(@Email String email);
}
