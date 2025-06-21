package com.dts.entry.identityservice.model;

import com.dts.entry.identityservice.model.enumerable.Status;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.hibernate.annotations.GenericGenerator;

import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Entity
@Table(name = "accounts")
public class Account {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    @Column(name = "account_id", updatable = false, nullable = false)
    UUID accountId;
    @Column(name = "username", nullable = false, unique = true, length = 100)
    String username;
    @Column(name = "email", nullable = false, unique = true, length = 255)
    String password;
    @Column(name = "status")
    @Enumerated(EnumType.ORDINAL)
    Status status;
    @Column(name = "first_name")
    String firstName;
    @Column(name = "last_name")
    String lastName;
    @ManyToMany
    Set<Role> roles;
}
