package com.dts.entry.notificationservice.viewmodel.event.consume;

import lombok.Builder;

import java.util.List;

@Builder
public record EmailRequest(
        Sender sender,
        List<Recipient> to,
        String subject,
        String htmlContent
) {
}
