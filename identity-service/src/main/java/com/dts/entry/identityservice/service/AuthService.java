package com.dts.entry.identityservice.service;

import com.dts.entry.identityservice.viewmodel.IntrospectRequest;
import com.dts.entry.identityservice.viewmodel.response.IntrospectResponse;
import com.dts.entry.identityservice.viewmodel.response.SignInResponse;

public interface AuthService {
    SignInResponse signIn(String username, String password);
    IntrospectResponse introspect(IntrospectRequest request);

}
