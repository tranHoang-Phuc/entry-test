package com.dts.entry.identityservice.configuration;

import com.dts.entry.identityservice.consts.Error;
import com.dts.entry.identityservice.exception.AppException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        throw new AppException(Error.ErrorCode.UNAUTHORIZED, Error.ErrorCodeMessage.UNAUTHORIZED, HttpStatus.UNAUTHORIZED.value());
    }
}
