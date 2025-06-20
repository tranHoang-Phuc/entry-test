package com.dts.entry.identityservice.viewmodel.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record IntrospectResponse(
        @JsonProperty("is_valid")
        boolean isValid
) {
}
