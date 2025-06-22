package com.dts.entry.identityservice.component;

import com.dts.entry.identityservice.consts.Error;
import com.dts.entry.identityservice.viewmodel.error.ErrorVm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
@RequiredArgsConstructor
public class InternalSecretInterceptor implements HandlerInterceptor {

    @Value("${internal.secret}")
    private String internalSecret;
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String headerSecret = request.getHeader("X-Internal-Secret");

        if (!internalSecret.equals(headerSecret)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            ErrorVm errorVm = ErrorVm.builder()
                    .errorCode(Error.ErrorCode.FORBIDDEN)
                    .message(Error.ErrorCodeMessage.FORBIDDEN)
                    .build();
            ObjectMapper mapper = new ObjectMapper();
            String json = mapper.writeValueAsString(errorVm);
            response.getWriter().write(json);
            return false;
        }

        return true;
    }
}
