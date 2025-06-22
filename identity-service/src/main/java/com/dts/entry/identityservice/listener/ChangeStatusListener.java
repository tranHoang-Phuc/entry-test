package com.dts.entry.identityservice.listener;

import com.dts.entry.event.ResetPasswordRequestEvent;
import com.dts.entry.event.UpdateStatusEvent;
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
public class ChangeStatusListener {
    AccountRepository accountRepository;
    @KafkaListener(topics = "${kafka.topic.change-status}", groupId = "${spring.kafka.consumer.group-id}")
    public void listen(UpdateStatusEvent event) {
        Account account = accountRepository.findById(event.accountId())
                .orElseThrow(() -> new AppException(com.dts.entry.identityservice.consts.Error.ErrorCodeMessage.USER_NOT_FOUND, Error.ErrorCode.USER_NOT_FOUND
                        , HttpStatus.NOT_FOUND.value()));

        log.info("Received change status request for account: {}", event.accountId());
        Status[] statuses = Status.values();
        int statusOrdinal = event.status();

        if (statusOrdinal < 0 || statusOrdinal >= statuses.length) {
            throw new AppException(Error.ErrorCodeMessage.INVALID_STATUS, Error.ErrorCode.INVALID_STATUS,
                    HttpStatus.BAD_REQUEST.value());
        }

        account.setStatus(statuses[statusOrdinal]);
        accountRepository.save(account);
    }
}
