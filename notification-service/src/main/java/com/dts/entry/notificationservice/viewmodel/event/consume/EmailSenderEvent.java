package com.dts.entry.notificationservice.viewmodel.event.consume;

import com.dts.entry.event.RecipientUser;
import lombok.Builder;

@Builder
public record EmailSenderEvent(
        RecipientUser recipientUser,
        String token,
        String subject,
        String htmlContent

) {

}
