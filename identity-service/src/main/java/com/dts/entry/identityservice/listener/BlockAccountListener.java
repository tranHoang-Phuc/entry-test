package com.dts.entry.identityservice.listener;

import com.dts.entry.event.BlockAccountEvent;
import com.dts.entry.identityservice.consts.Error;
import com.dts.entry.identityservice.exception.AppException;
import com.dts.entry.identityservice.model.Account;
import com.dts.entry.identityservice.model.enumerable.Status;
import com.dts.entry.identityservice.repository.AccountRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
@Service
public class BlockAccountListener {
    AccountRepository accountRepository;

    @KafkaListener(topics = "${kafka.topic.block-user}", groupId = "${spring.kafka.consumer.group-id}")
    public void listen(BlockAccountEvent event) {
        log.info("Received block account event for account ID: {}", event.accountId());
        Account account = accountRepository.findById(event.accountId())
                .orElseThrow(() -> new AppException(Error.ErrorCodeMessage.USER_NOT_FOUND, Error.ErrorCode.USER_NOT_FOUND
                        , HttpStatus.NOT_FOUND.value()));
        account.setStatus(Status.DELETED);
        accountRepository.save(account);
        log.info("Account with ID: {} has been blocked", event.accountId());
    }

}
