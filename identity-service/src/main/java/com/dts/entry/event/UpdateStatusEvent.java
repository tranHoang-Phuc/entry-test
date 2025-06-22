package com.dts.entry.event;

import lombok.Builder;

import java.util.UUID;

@Builder
public record UpdateStatusEvent(
        UUID accountId,
        int status
) {
}
