package com.dts.entry.event;

import lombok.Builder;

import java.util.List;
import java.util.UUID;

@Builder
public record UnAssignRoleEvent(
        UUID accountId,
        List<String> roles
) {
}
