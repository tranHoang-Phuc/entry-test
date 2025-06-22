package com.dts.entry.identityservice.repository;

import com.dts.entry.identityservice.model.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AccountRepository extends JpaRepository<Account, UUID> {

    Optional<Account> findByUsername(String adminUserName);

    boolean existsByUsername(String username);

    @Query("""
    SELECT a FROM Account a
    LEFT JOIN FETCH a.roles
    WHERE a.accountId = :accountID
""")
    Optional<Account> findByAccountID(@Param("accountID") UUID accountID);
}
