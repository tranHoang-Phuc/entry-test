package com.dts.entry.identityservice.listener;

import com.dts.entry.event.ResetPasswordRequestEvent;
import com.dts.entry.identityservice.consts.Error;
import com.dts.entry.identityservice.exception.AppException;
import com.dts.entry.identityservice.model.Account;
import com.dts.entry.identityservice.repository.AccountRepository;
import com.dts.entry.identityservice.service.AuthService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
@Service
public class ResetPasswordListener {
    AccountRepository accountRepository;
    PasswordEncoder passwordEncoder;
    @KafkaListener(topics = "${kafka.topic.reset-password}", groupId = "${spring.kafka.consumer.group-id}")
    public void listen(ResetPasswordRequestEvent resetPasswordRequestEvent) {
        Account account = accountRepository.findById(resetPasswordRequestEvent.accountId())
                .orElseThrow(() -> new AppException(Error.ErrorCodeMessage.USER_NOT_FOUND, Error.ErrorCode.USER_NOT_FOUND
                , HttpStatus.NOT_FOUND.value()));
        account.setPassword(passwordEncoder.encode(resetPasswordRequestEvent.newPassword()));
        log.info("Received reset password request for account: {}", resetPasswordRequestEvent.accountId());
        accountRepository.save(account);
    }
}
