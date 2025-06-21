package com.dts.entry.identityservice.model;

import com.dts.entry.identityservice.model.enumerable.TokenType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Date;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Entity
public class InvalidatedToken {
    @Id
    @Column(name = "id", nullable = false, unique = true)
    String id;

    @Column(name="expired_at")
    Date expiredAt;

    @Column(name = "type" , nullable = false)
    TokenType type;
}

