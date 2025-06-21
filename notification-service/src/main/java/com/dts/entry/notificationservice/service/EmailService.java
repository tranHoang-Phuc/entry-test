package com.dts.entry.notificationservice.service;

import com.dts.entry.notificationservice.viewmodel.event.EmailResponse;
import com.dts.entry.notificationservice.viewmodel.event.consume.EmailSenderEvent;

public interface EmailService {
    EmailResponse sendEmail(EmailSenderEvent sendEmailRequest);


}
