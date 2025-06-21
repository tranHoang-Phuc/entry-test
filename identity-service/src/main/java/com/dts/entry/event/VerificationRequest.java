package com.dts.entry.event;

import lombok.Builder;

@Builder
public record VerificationRequest(
        String token
) {
}
