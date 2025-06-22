package com.dts.entry.profileservice.viewmodel.request;

import java.util.List;

public record AssignRoleRequest(
        List<String> roles
) {
}
