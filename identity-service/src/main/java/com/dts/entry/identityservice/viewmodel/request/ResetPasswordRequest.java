package com.dts.entry.identityservice.viewmodel.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ResetPasswordRequest(
        @JsonProperty(required = true)
        String email,
        @JsonProperty(required = true, value = "new_password")
        String newPassword,
        @JsonProperty(required = true)
        String token
) {
}
