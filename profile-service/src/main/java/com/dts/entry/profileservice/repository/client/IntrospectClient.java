package com.dts.entry.profileservice.repository.client;

import com.dts.entry.profileservice.viewmodel.request.IntrospectRequest;
import com.dts.entry.profileservice.viewmodel.response.BaseResponse;
import com.dts.entry.profileservice.viewmodel.response.IntrospectResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.awt.*;

@FeignClient(name = "introspect-client", url = "${introspect.service.url}")
public interface IntrospectClient {
    @PostMapping(value = "/auth/introspect", consumes = MediaType.APPLICATION_JSON_VALUE)
    BaseResponse<IntrospectResponse> introspect(@RequestBody IntrospectRequest request);
}
