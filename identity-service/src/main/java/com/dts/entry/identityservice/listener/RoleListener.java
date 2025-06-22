package com.dts.entry.identityservice.listener;

import com.dts.entry.event.AssignRoleEvent;
import com.dts.entry.event.UnAssignRoleEvent;
import com.dts.entry.identityservice.consts.Error;
import com.dts.entry.identityservice.exception.AppException;
import com.dts.entry.identityservice.model.Account;
import com.dts.entry.identityservice.model.Role;
import com.dts.entry.identityservice.repository.AccountRepository;
import com.dts.entry.identityservice.repository.RoleRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
@Service
public class RoleListener {
    AccountRepository accountRepository;
    RoleRepository roleRepository;

    @KafkaListener(topics = "${kafka.topic.assign-role}", groupId = "${spring.kafka.consumer.group-id}")
    @Transactional
    public void listen(AssignRoleEvent event) {
        Account account = accountRepository.findById(event.accountId())
                .orElseThrow(() -> new AppException(
                        com.dts.entry.identityservice.consts.Error.ErrorCodeMessage.USER_NOT_FOUND,
                        Error.ErrorCode.USER_NOT_FOUND,
                        HttpStatus.NOT_FOUND.value()
                ));
        List<String> roles = new ArrayList<>(event.roles());
        List<Role> rolesOfAccount = roleRepository.findByAccounts(Set.of(account));
        rolesOfAccount.forEach(role -> roles.remove(role.getName()));
        for (String roleName : roles) {
            Role role = roleRepository.findByName(roleName)
                    .orElseThrow(() -> new AppException(
                            Error.ErrorCodeMessage.ROLE_NOT_FOUND,
                            Error.ErrorCode.ROLE_NOT_FOUND,
                            HttpStatus.NOT_FOUND.value()
                    ));

            rolesOfAccount.add(role);
            role.getAccounts().add(account);
        }

        accountRepository.save(account);
        roleRepository.saveAll(rolesOfAccount);
    }

    @KafkaListener(topics = "${kafka.topic.unassign-role}", groupId = "${spring.kafka.consumer.group-id}")
    @Transactional
    public void listen(UnAssignRoleEvent event) {
        Account account = accountRepository.findById(event.accountId())
                .orElseThrow(() -> new AppException(
                        com.dts.entry.identityservice.consts.Error.ErrorCodeMessage.USER_NOT_FOUND,
                        Error.ErrorCode.USER_NOT_FOUND,
                        HttpStatus.NOT_FOUND.value()
                ));

        List<String> rolesToRemove = new ArrayList<>(event.roles());

        List<Role> rolesOfAccount = roleRepository.findByAccounts(Set.of(account));

        for (Role role : rolesOfAccount) {
            if (rolesToRemove.contains(role.getName())) {
                role.getAccounts().remove(account);
                account.getRoles().remove(role);
            }
        }

        accountRepository.save(account);
        roleRepository.saveAll(rolesOfAccount);

        log.info("Unassigned roles {} from account {}", rolesToRemove, account.getUsername());
    }
}
