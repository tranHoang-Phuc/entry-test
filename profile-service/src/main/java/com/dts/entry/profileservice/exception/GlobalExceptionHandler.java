package com.dts.entry.profileservice.exception;


import com.dts.entry.profileservice.consts.Error;
import com.dts.entry.profileservice.viewmodel.error.ErrorVm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    private final Environment environment;

    public GlobalExceptionHandler(Environment environment) {
        this.environment = environment;
    }

    @ExceptionHandler(AppException.class)
    public ResponseEntity<ErrorVm> handleAppException(AppException ex) {
        HttpStatus status = HttpStatus.valueOf(ex.getHttpStatusCode());
        String errorCode = (ex.getBusinessErrorCode() != null) ? ex.getBusinessErrorCode() : com.dts.entry.profileservice.consts.Error.ErrorCode.UNAUTHORIZED;
        String message = ex.getMessage() != null ? ex.getMessage() : com.dts.entry.profileservice.consts.Error.ErrorCodeMessage.UNCATEGORIZED_EXCEPTION;

        return buildErrorResponse(status, errorCode, message, null, ex);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorVm> handleAccessDeniedException(AccessDeniedException ex) {
        return buildErrorResponse(HttpStatus.FORBIDDEN, com.dts.entry.profileservice.consts.Error.ErrorCode.FORBIDDEN,
                com.dts.entry.profileservice.consts.Error.ErrorCodeMessage.FORBIDDEN, null, ex);
    }



    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorVm> handleGeneralException(Exception ex) {
        log.error("Unhandled exception caught: ", ex);
        return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR,
                com.dts.entry.profileservice.consts.Error.ErrorCode.UNCATEGORIZED_EXCEPTION,
                com.dts.entry.profileservice.consts.Error.ErrorCodeMessage.UNCATEGORIZED_EXCEPTION, null, ex);
    }

    private ResponseEntity<ErrorVm> buildErrorResponse(HttpStatus status, String errorCode, String message,
                                                       List<String> errors, Exception ex) {
        boolean isDev = Arrays.asList(environment.getActiveProfiles()).stream()
                .anyMatch(env -> env.equalsIgnoreCase("dev") || env.equalsIgnoreCase("local"));

        String finalMessage = message != null ? message : "Unexpected error";
        String finalCode = errorCode != null ? errorCode : Error.ErrorCode.UNCATEGORIZED_EXCEPTION;

        if (isDev) {
            String stackTrace = Arrays.stream(ex.getStackTrace())
                    .map(StackTraceElement::toString)
                    .collect(Collectors.joining("\n"));
            return ResponseEntity.status(status).body(
                    new ErrorVm("error", finalCode, finalMessage, stackTrace));
        }

        return ResponseEntity.status(status).body(
                new ErrorVm("error", finalCode, finalMessage));
    }
}
