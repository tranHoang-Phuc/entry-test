package com.dts.entry.profileservice.viewmodel.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record IntrospectRequest(
        @JsonProperty("access_token")
        String accessToken
) {
}
