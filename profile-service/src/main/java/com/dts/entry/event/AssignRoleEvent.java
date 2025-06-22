package com.dts.entry.event;

import lombok.Builder;

import java.util.List;
import java.util.UUID;

@Builder
public record AssignRoleEvent(
        UUID accountId,
        List<String> roles
) {
}
