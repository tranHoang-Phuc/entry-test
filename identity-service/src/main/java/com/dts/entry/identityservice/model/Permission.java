package com.dts.entry.identityservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import lombok.experimental.FieldDefaults;

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
}
