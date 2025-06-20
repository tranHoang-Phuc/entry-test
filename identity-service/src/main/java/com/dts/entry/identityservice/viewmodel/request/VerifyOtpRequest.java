package com.dts.entry.identityservice.viewmodel.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public record VerifyOtpRequest(
        @JsonProperty( value = "otp", required = true)
        String otp,
        @JsonProperty(value ="email", required = true)
        String email
) {
}
