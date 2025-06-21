package com.dts.entry.event;

import lombok.Builder;

import java.util.UUID;

@Builder
public record UserCreation(
        UUID accountId,
        String firstName,
        String lastName
) {
}
