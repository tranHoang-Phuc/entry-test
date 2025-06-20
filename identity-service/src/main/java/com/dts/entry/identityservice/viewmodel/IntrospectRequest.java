package com.dts.entry.identityservice.viewmodel;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record IntrospectRequest(
        @JsonProperty("access_token")
        String accessToken
) {
}
