package com.dts.entry.profileservice.viewmodel.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record AccountCreation(
        @JsonProperty(value = "email")
        String email,
        @JsonProperty(value = "password")
        String password,
        @JsonProperty(value = "first_name")
        String firstName,
        @JsonProperty(value = "last_name")
        String lastName,
        @JsonProperty(value ="roles")
        String[] roles
) {
}

