package com.dts.entry.identityservice.service;

import com.fasterxml.jackson.core.JsonProcessingException;

public interface VerifyEmailRateLimiter {
    boolean isBlocked(String email) throws JsonProcessingException;

    void recordAttempt(String email) throws JsonProcessingException;

}
