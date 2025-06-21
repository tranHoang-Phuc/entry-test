package com.dts.entry.identityservice.model;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Entity
@Table(name = "permissions")
public class Permission {
    @Id
    @Column(name = "name",unique = true, nullable = false)
    String name;
    @Column(name = "description")
    String description;

    @ManyToMany(mappedBy = "permissions")
    List<Role> roles;
}
