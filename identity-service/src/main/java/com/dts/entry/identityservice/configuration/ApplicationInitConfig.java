package com.dts.entry.identityservice.configuration;

import com.dts.entry.identityservice.consts.PredefinedRole;
import com.dts.entry.identityservice.model.Account;
import com.dts.entry.identityservice.model.Role;
import com.dts.entry.identityservice.model.enumerable.Status;
import com.dts.entry.identityservice.repository.AccountRepository;
import com.dts.entry.identityservice.repository.RoleRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Configuration
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class ApplicationInitConfig {

    ObjectProvider<PasswordEncoder> passwordEncoder;

    @NonFinal
    @Value("${admin.username}")
    String ADMIN_USER_NAME;

    @NonFinal
    @Value("${admin.password}")
    String ADMIN_PASSWORD;

    @Bean
    @ConditionalOnProperty(
            prefix = "spring",
            value = "datasource.driver-class-name",
            havingValue = "org.postgresql.Driver")
    ApplicationRunner applicationRunner(AccountRepository accountRepository, RoleRepository roleRepository) {
        return args -> {
            accountRepository.findByUsername(ADMIN_USER_NAME).ifPresentOrElse(
                    user -> log.info("Admin user already exists: {}", ADMIN_USER_NAME),
                    () -> {
                        log.info("Creating default admin user: {}", ADMIN_USER_NAME);
                        Role adminRole = createRoleIfNotExists(roleRepository, PredefinedRole.ADMIN_ROLE);
                        Role userRole = createRoleIfNotExists(roleRepository, PredefinedRole.USER_ROLE);

                        Account admin = Account.builder()
                                .username(ADMIN_USER_NAME)
                                .password(passwordEncoder.getIfAvailable().encode(ADMIN_PASSWORD))
                                .status(Status.VERIFIED)
                                .roles(Set.of(adminRole, userRole))
                                .build();

                        accountRepository.save(admin);
                        log.info("Admin user created: {}", ADMIN_USER_NAME);
                    }
                    );
        };
    }
    private Role createRoleIfNotExists(RoleRepository roleRepository, String roleName) {
        return roleRepository.findByName(roleName).orElseGet(() -> {
            Role role = Role.builder()
                    .name(roleName)
                    .description(roleName)
                    .build();
            return roleRepository.save(role);
        });
    }
}
