package com.dts.entry.notificationservice.listener;

import com.dts.entry.event.EmailSendingRequest;
import com.dts.entry.notificationservice.service.EmailService;
import com.dts.entry.notificationservice.viewmodel.event.consume.EmailSenderEvent;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
@Service
public class EmailVerificationListener {
    EmailService emailService;

    @KafkaListener(topics = "${kafka.topic.user-verification}", groupId = "${spring.kafka.consumer.group-id}")
    public void listen(EmailSendingRequest request) {
        EmailSenderEvent emailSenderEvent = EmailSenderEvent.builder()
                .recipientUser(request.recipientUser())
                .subject("Verify your email")
                .htmlContent(request.htmlContent())
                .build();
        emailService.sendEmail(emailSenderEvent);
    }
}
