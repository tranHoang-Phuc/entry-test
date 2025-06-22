package com.dts.entry.profileservice.viewmodel.request;

import lombok.Builder;

@Builder
public record ResetPasswordRequest(
        String newPassword,
        String confirmNewPassword
) {
}
