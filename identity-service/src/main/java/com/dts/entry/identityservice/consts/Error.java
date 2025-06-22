package com.dts.entry.identityservice.consts;

public class Error {
    public final class ErrorCode {
        public static final String UNAUTHORIZED = "UNAUTHORIZED";
        public static final String ROLE_NOT_FOUND = "ROLE_NOT_FOUND";
        public static final String USERNAME_ALREADY_EXISTS = "USERNAME_ALREADY_EXISTS";
        public static final String UNCATEGORIZED_EXCEPTION = "UNCATEGORIZED_EXCEPTION";
        public static final String FORBIDDEN = "FORBIDDEN";
        public static final String USER_NOT_FOUND = "USER_NOT_FOUND";
        public static final String USER_UNVERIFIED = "USER_UNVERIFIED";
        public static final String USER_BLOCKED = "USER_BLOCKED";
        public static final String VERIFY_EMAIL_RATE_LIMIT = "VERIFY_EMAIL_RATE_LIMIT";
        public static final String INVALID_VERIFIED_TOKEN = "INVALID_VERIFIED_TOKEN";
        public static final String FORGOT_PASSWORD_RATE_LIMIT = "FORGOT_PASSWORD_RATE_LIMIT";
        public static final String INVALID_TOKEN = "INVALID_TOKEN";
        public static final String INVALID_STATUS = "INVALID_STATUS";

    }

    public final class ErrorCodeMessage{
        public static final String UNAUTHORIZED = "000001";
        public static final String ROLE_NOT_FOUND = "000011";
        public static final String USERNAME_ALREADY_EXISTS = "000012";
        public static final String UNCATEGORIZED_EXCEPTION = "999999";
        public static final String FORBIDDEN = "000013";
        public static final String USER_NOT_FOUND = "000014";
        public static final String USER_UNVERIFIED = "000015";
        public static final String USER_BLOCKED = "000016";
        public static final String VERIFY_EMAIL_RATE_LIMIT = "000017";
        public static final String INVALID_VERIFIED_TOKEN = "000018";

        public static final String FORGOT_PASSWORD_RATE_LIMIT = "000019";
        public static final String INVALID_TOKEN = "000020";
        public static final String INVALID_STATUS = "000021";
    }
}
