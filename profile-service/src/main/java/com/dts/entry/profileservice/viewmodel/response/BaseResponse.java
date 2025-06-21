package com.dts.entry.profileservice.viewmodel.response;

import lombok.Builder;

@Builder
public record BaseResponse<T>(
        String status,
        String message,
        T data
) {
    public BaseResponse {
        if (status == null) {
            status = "success";
        }
    }
}

