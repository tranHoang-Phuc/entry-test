package com.dts.entry.identityservice.controller;

import com.dts.entry.identityservice.service.AuthService;
import com.dts.entry.identityservice.viewmodel.request.AccountCreation;
import com.dts.entry.identityservice.viewmodel.response.AccountCreationResponse;
import com.dts.entry.identityservice.viewmodel.response.BaseResponse;
import io.swagger.v3.oas.annotations.headers.Header;
import jakarta.annotation.security.PermitAll;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth/internal")
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class AuthInternalController {
    AuthService authService;

    @PostMapping("/accounts")
    @PermitAll
    public ResponseEntity<BaseResponse<AccountCreationResponse>> createAccount(@RequestBody AccountCreation accountCreation) {
       AccountCreationResponse data = authService.createAccount(accountCreation);
       BaseResponse<AccountCreationResponse> response = BaseResponse.<AccountCreationResponse>builder()
                .status("success")
                .message("Account created successfully")
                .data(data)
                .build();
         return ResponseEntity.ok(response);
    }
}
