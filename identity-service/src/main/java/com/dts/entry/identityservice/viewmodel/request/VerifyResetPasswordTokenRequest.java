package com.dts.entry.identityservice.viewmodel.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public record VerifyResetPasswordTokenRequest(
        @JsonProperty(required = true)
        String token,
        @JsonProperty(required = true)
        String email
) {
}
