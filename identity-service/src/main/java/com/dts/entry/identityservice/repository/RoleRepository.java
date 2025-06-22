package com.dts.entry.identityservice.repository;

import com.dts.entry.identityservice.model.Account;
import com.dts.entry.identityservice.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface RoleRepository extends JpaRepository<Role, String> {
    Optional<Role> findByName(String roleName);

    List<Role> findByAccounts(Set<Account> account);
}
