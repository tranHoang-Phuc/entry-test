package com.dts.entry.event;

import lombok.Builder;

@Builder
public record EmailSendingRequest<T>(
        String subject,
        String htmlContent,
        T data,
        RecipientUser recipientUser

) {
}
