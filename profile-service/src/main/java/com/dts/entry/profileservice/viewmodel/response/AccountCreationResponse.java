package com.dts.entry.profileservice.viewmodel.response;

import lombok.Builder;

@Builder
public record AccountCreationResponse(
        String accountId,
        String firstName,
        String lastName,
        String email
) {
}
