package com.dts.entry.identityservice.viewmodel.response;

import com.fasterxml.jackson.annotation.JsonInclude;
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

