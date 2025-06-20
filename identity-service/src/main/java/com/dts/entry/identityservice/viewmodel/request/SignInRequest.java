package com.dts.entry.identityservice.viewmodel.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import org.hibernate.validator.constraints.Length;

public record SignInRequest(
        @JsonProperty(value = "email", required = true)
        @Email
        String email,
        @JsonProperty(value = "password", required = true)
        @Length(min = 8, max = 32)
        String passsword
) {
}
