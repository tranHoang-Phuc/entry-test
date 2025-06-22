package com.dts.entry.apigateway.config;

import lombok.experimental.NonFinal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class GatewayRoutesConfig {
    @Value("${domain.identity-service}")
    @NonFinal
    String identityServiceDomain;

    @Value("${domain.profile-service}")
    @NonFinal
    String profileServiceDomain;
    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("identity-service", r -> r
                        .path("/api/v1/identity/**")
                        .filters(f -> f.stripPrefix(2))
                        .uri(identityServiceDomain))
                .route("reading-service", r -> r
                        .path("/api/v1/user/**")
                        .filters(f -> f.stripPrefix(2))
                        .uri(profileServiceDomain))
                .build();
    }
}
