package com.dts.entry.notificationservice.viewmodel.event.consume;

import lombok.Builder;

@Builder
public record Sender(
        String name,
        String email
) {
}
