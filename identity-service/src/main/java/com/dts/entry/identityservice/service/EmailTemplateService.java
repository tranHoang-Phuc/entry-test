package com.dts.entry.identityservice.service;

public interface EmailTemplateService {
    String buildVerificationEmail(String otp);

    String buildForgotPasswordEmail(String url);

    String buildEmailVerificationSuccess(String email, String fullName);
}

