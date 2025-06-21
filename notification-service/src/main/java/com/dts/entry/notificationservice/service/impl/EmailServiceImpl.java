package com.dts.entry.notificationservice.service.impl;

import com.dts.entry.notificationservice.repository.client.EmailClient;
import com.dts.entry.notificationservice.service.EmailService;
import com.dts.entry.notificationservice.viewmodel.event.EmailResponse;
import com.dts.entry.notificationservice.viewmodel.event.consume.EmailRequest;
import com.dts.entry.notificationservice.viewmodel.event.consume.EmailSenderEvent;
import com.dts.entry.notificationservice.viewmodel.event.consume.Recipient;
import com.dts.entry.notificationservice.viewmodel.event.consume.Sender;
import feign.FeignException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class EmailServiceImpl implements EmailService {

    EmailClient emailClient;

    @Value("${notification.email.brevo-apikey}")
    @NonFinal
    String apiKey;




    @Override
    public EmailResponse sendEmail(EmailSenderEvent sendEmailRequest) {
        EmailRequest emailResponse = EmailRequest.builder()
                .sender(Sender.builder()
                        .name("noreply")
                        .email("phucth115.dev@gmail.com")
                        .build()
                )
                .to(List.of(Recipient.builder()
                        .email(sendEmailRequest.recipientUser().email())
                        .name(sendEmailRequest.recipientUser().firstName().concat(" ")
                                .concat(sendEmailRequest.recipientUser().lastName()))
                        .build()))
                .subject(sendEmailRequest.subject())
                .htmlContent(sendEmailRequest.htmlContent())
                .build();
        try {
            return emailClient.sendEmail(apiKey, emailResponse);
        } catch (FeignException e) {
            throw new RuntimeException("Failed to send email: " + e.getMessage(), e);
        }
    }
}
