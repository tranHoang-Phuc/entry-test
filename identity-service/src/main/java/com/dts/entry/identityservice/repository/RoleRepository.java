package com.dts.entry.identityservice.repository;

import com.dts.entry.identityservice.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, String> {
    Optional<Role> findByName(String roleName);
}
