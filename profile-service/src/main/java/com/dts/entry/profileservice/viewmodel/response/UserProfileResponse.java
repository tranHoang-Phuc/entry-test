package com.dts.entry.profileservice.viewmodel.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.time.LocalDate;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserProfileResponse(
        @JsonProperty("id")
        String id,
        @JsonProperty("first_name")
        String firstName,
        @JsonProperty("last_name")
        String lastName,
        @JsonProperty("email")
        String email,
        @JsonProperty("date_of_birth")
        LocalDate dateOfBirth,
        @JsonProperty("image_url")
        String imageUrl,
        @JsonProperty("is_deleted")
        Boolean isDeleted,
        @JsonProperty("status")
        Integer status,
        @JsonProperty("account")
        AccountDetailResponse account
) {
}
