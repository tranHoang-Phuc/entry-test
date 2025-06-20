package com.dts.entry.identityservice.viewmodel.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import org.hibernate.validator.constraints.Length;

public record SignUpRequest(
        @JsonProperty(value = "email", required = true)
        @Email
        String username,
        @JsonProperty(value = "password", required = true)
        @Length(min = 8, max = 32)
        String password,
        @JsonProperty(value = "first_name", required = true)
        String firstName,
        @JsonProperty(value = "last_name", required = true)
        String lastName
) {
}
