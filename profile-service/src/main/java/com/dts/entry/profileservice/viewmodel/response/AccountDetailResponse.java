package com.dts.entry.profileservice.viewmodel.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

import java.util.List;

@Builder
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record AccountDetailResponse(

        String accountId,
        String username,
        Integer status,
        List<RoleDetailResponse> roles
) {
    @Builder
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public record RoleDetailResponse(
            String name,
            List<PermissionDetailResponse> permissions
    ) {
        @Builder
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        public record PermissionDetailResponse(
                String name
        ) {
        }
    }
}
