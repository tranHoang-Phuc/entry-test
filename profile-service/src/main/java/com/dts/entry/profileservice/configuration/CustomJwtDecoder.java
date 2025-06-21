package com.dts.entry.profileservice.configuration;


import com.dts.entry.profileservice.exception.AppException;
import com.dts.entry.profileservice.repository.client.IntrospectClient;
import com.dts.entry.profileservice.viewmodel.request.IntrospectRequest;
import com.dts.entry.profileservice.viewmodel.response.IntrospectResponse;
import com.nimbusds.jose.JOSEException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;
import java.util.Objects;

@Component
public class CustomJwtDecoder implements JwtDecoder {
    @Value("${jwt.signerKey}")
    private String signerKey;

    @Autowired
    private IntrospectClient introspectClient   ;

    private NimbusJwtDecoder nimbusJwtDecoder = null;

    @Override
    public Jwt decode(String token) throws JwtException {
        IntrospectResponse response = null;

        response = introspectClient.introspect(IntrospectRequest.builder()
                        .accessToken(token)
                .build()).data();

        if (!response.isValid()) throw new AppException(com.dts.entry.profileservice.consts.Error.ErrorCode.UNAUTHORIZED,
                com.dts.entry.profileservice.consts.Error.ErrorCode.UNAUTHORIZED,
                    HttpStatus.UNAUTHORIZED.value());


        if (Objects.isNull(nimbusJwtDecoder)) {
            SecretKeySpec secretKeySpec = new SecretKeySpec(signerKey.getBytes(), "HS512");
            nimbusJwtDecoder = NimbusJwtDecoder.withSecretKey(secretKeySpec)
                    .macAlgorithm(MacAlgorithm.HS512)
                    .build();
        }
        return nimbusJwtDecoder.decode(token);
    }
}
