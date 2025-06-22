package com.dts.entry.event;

import lombok.Builder;

import java.util.UUID;

@Builder
public record ResetPasswordRequestEvent(
        UUID accountId,
        String newPassword
) {
}
