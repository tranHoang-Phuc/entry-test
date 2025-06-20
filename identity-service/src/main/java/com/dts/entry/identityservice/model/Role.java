package com.dts.entry.identityservice.model;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Set;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Entity
@Table(name = "roles")
public class Role {
    @Id
    @Column(name = "name",unique = true, nullable = false)
    String name;
    @Column(name = "description")
    String description;
    @ManyToMany
    Set<Permission> permissions;
}
