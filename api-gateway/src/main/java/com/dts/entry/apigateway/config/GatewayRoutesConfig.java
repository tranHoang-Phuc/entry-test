package com.dts.entry.apigateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class GatewayRoutesConfig {
    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("identity-service", r -> r
                        .path("/api/v1/identity/**")
                        .filters(f -> f.stripPrefix(2))
                        .uri("http://localhost:8090"))
                .route("reading-service", r -> r
                        .path("/api/v1/profile/**")
                        .filters(f -> f.stripPrefix(2))
                        .uri("http://localhost:8091"))
                .build();
    }
}
