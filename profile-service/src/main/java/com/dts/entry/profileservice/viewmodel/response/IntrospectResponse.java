package com.dts.entry.profileservice.viewmodel.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record IntrospectResponse(
        @JsonProperty("is_valid")
        boolean isValid
) {
}
