package com.dts.entry.identityservice.viewmodel.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record SignInResponse(
        @JsonProperty("access_token")
        String accessToken,
        @JsonProperty("refresh_token")
        String refreshToken,
        @JsonProperty("token_type")
        String tokenType,
        @JsonProperty("expires_in")
        Long expiresIn
) {

}
