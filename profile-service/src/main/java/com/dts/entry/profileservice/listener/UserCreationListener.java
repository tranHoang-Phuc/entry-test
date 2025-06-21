package com.dts.entry.profileservice.listener;

import com.dts.entry.event.UserCreation;
import com.dts.entry.profileservice.model.UserProfile;
import com.dts.entry.profileservice.repository.UserProfileRepository;
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
public class UserCreationListener {
    UserProfileRepository userProfileRepository;
    @KafkaListener(topics = "${kafka.topic.user-creation}", groupId = "${spring.kafka.consumer.group-id}")
    public void listen(UserCreation user) {
        UserProfile userProfile = UserProfile.builder()
                .accountId(user.accountId())
                .firstName(user.firstName())
                .lastName(user.lastName())
                .build();
        log.info("Received user creation event: {}", user);
        userProfileRepository.save(userProfile);
        log.info("User profile created: {}", userProfile);
    }
}
