package com.dts.entry.event;

import lombok.Builder;

import java.util.UUID;

@Builder
public record RecipientUser(String email, String firstName, String lastName, UUID userId) {
}
