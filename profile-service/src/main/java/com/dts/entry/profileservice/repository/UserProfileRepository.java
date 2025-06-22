package com.dts.entry.profileservice.repository;

import com.dts.entry.profileservice.model.UserProfile;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserProfileRepository extends JpaRepository<UserProfile, UUID> {
    UserProfile findByEmail(String email);

    Optional<UserProfile> findByAccountId(UUID accountId);
}
