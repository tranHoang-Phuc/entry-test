package com.dts.entry.identityservice.exception;

import com.dts.entry.identityservice.viewmodel.error.ErrorVm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    private static final String ERROR_LOG_FORMAT = "Error: URI: {}, ErrorCode: {}, Message: {}";
    private static final String INVALID_REQUEST_INFORMATION_MESSAGE = "Request information is not valid";

    private final Environment environment;

    public GlobalExceptionHandler(Environment environment) {
        this.environment = environment;
    }


    @ExceptionHandler({AppException.class})
    public ResponseEntity<ErrorVm> handleAppException(AppException ex, WebRequest request) {
        HttpStatus status = HttpStatus.valueOf(ex.getHttpStatusCode());
        String message = ex.getMessage();
        String errorCode = ex.getBusinessErrorCode();
        return buildErrorResponse(status, errorCode, message, null, ex, request, status.value());
    }


    private String getServletPath(WebRequest webRequest) {
        ServletWebRequest servletRequest = (ServletWebRequest) webRequest;
        return servletRequest.getRequest().getServletPath();
    }

    private ResponseEntity<ErrorVm> handleBadRequest(Exception ex, WebRequest request, String errorCode) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        String message = ex.getMessage();

        return buildErrorResponse(status, errorCode ,message, null, ex, request, 400);
    }

    private ResponseEntity<ErrorVm> buildErrorResponse(HttpStatus status,String errorCode ,String message,
                                                       List<String> errors,
                                                       Exception ex, WebRequest request, int statusCode) {
        boolean isDev = Arrays.asList(environment.getActiveProfiles()).contains("dev");
        boolean isLocal = Arrays.asList(environment.getActiveProfiles()).contains("local");
        if (request != null) {
            log.error(ERROR_LOG_FORMAT, this.getServletPath(request), statusCode, message);
        }
        log.error(message, ex);

        if (isDev || isLocal) {
            String stackTrace = Arrays.stream(ex.getStackTrace())
                    .map(StackTraceElement::toString)
                    .collect(Collectors.joining("\n"));
            return ResponseEntity.status(status).body(new ErrorVm(
                    "error",errorCode ,message, stackTrace
            ));
        } else {
            return ResponseEntity.status(status).body(new ErrorVm(
                    "error",errorCode, message
            ));
        }
    }
}
