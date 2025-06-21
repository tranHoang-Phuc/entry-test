package com.dts.entry.identityservice.viewmodel.request;

import lombok.Builder;

@Builder
public record VerifiedStatus(
        String email,
        boolean verified
) {
}
