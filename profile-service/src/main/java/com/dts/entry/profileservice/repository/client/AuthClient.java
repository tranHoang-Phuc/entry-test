package com.dts.entry.profileservice.repository.client;

import com.dts.entry.profileservice.viewmodel.request.AccountCreation;
import com.dts.entry.profileservice.viewmodel.request.IntrospectRequest;
import com.dts.entry.profileservice.viewmodel.response.AccountCreationResponse;
import com.dts.entry.profileservice.viewmodel.response.AccountDetailResponse;
import com.dts.entry.profileservice.viewmodel.response.BaseResponse;
import com.dts.entry.profileservice.viewmodel.response.IntrospectResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@FeignClient(name = "auth-client", url = "${introspect.service.url}")
public interface AuthClient {
    @PostMapping(value = "/auth/introspect", consumes = MediaType.APPLICATION_JSON_VALUE)
    BaseResponse<IntrospectResponse> introspect(@RequestBody IntrospectRequest request);

    @PostMapping(value ="/auth/internal/accounts", consumes = MediaType.APPLICATION_JSON_VALUE)
    BaseResponse<AccountCreationResponse> createAccount(@RequestBody AccountCreation accountCreation,
                                                         @RequestHeader("X-Internal-Secret") String internalSecretHeader);

    @GetMapping(value = "/auth/internal/accounts/{id}", consumes = MediaType.APPLICATION_JSON_VALUE)
    BaseResponse<AccountDetailResponse> getAccountById(@RequestHeader("X-Internal-Secret") String internalSecretHeader,
                                                       @PathVariable("id") UUID accountId);
}
