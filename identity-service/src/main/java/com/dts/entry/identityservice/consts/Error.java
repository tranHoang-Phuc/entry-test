package com.dts.entry.identityservice.consts;

public class Error {
    public final class ErrorCode {
        public static final String UNAUTHORIZED = "UNAUTHORIZED";
        public static final String ROLE_NOT_FOUND = "ROLE_NOT_FOUND";
        public static final String USERNAME_ALREADY_EXISTS = "USERNAME_ALREADY_EXISTS";
        public static final String UNCATEGORIZED_EXCEPTION = "UNCATEGORIZED_EXCEPTION";
        public static final String FORBIDDEN = "FORBIDDEN";
    }

    public final class ErrorCodeMessage{
        public static final String UNAUTHORIZED = "000001";
        public static final String ROLE_NOT_FOUND = "000011";
        public static final String USERNAME_ALREADY_EXISTS = "000012";
        public static final String UNCATEGORIZED_EXCEPTION = "999999";
        public static final String FORBIDDEN = "000013";
    }
}
