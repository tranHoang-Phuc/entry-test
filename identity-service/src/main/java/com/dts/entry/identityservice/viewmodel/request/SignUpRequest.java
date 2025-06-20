package com.dts.entry.identityservice.viewmodel.request;

public record SignUpRequest(
        String email,
        String password,
        String firstName,
        String lastName
) {
}
