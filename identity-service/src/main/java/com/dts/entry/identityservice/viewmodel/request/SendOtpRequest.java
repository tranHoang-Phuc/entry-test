package com.dts.entry.identityservice.viewmodel.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;

public record SendOtpRequest(
        @Email
        @JsonProperty(value = "email", required = true)
        String email
) {
}
