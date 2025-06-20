package com.dts.entry.identityservice.service.impl;

import com.dts.entry.identityservice.service.AuthService;
import com.dts.entry.identityservice.viewmodel.IntrospectRequest;
import com.dts.entry.identityservice.viewmodel.response.IntrospectResponse;
import com.dts.entry.identityservice.viewmodel.response.SignInResponse;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImpl implements AuthService {
    @Override
    public SignInResponse signIn(String username, String password) {
        return null;
    }

    @Override
    public IntrospectResponse introspect(IntrospectRequest request) {
        return null;
    }
}
