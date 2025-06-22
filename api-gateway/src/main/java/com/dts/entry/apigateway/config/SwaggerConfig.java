package com.dts.entry.apigateway.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import lombok.experimental.NonFinal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class SwaggerConfig {
    @Value("${springdoc.swagger-ui.urls[0].url}")
    @NonFinal
    private String identityServiceUrl;

    @Value("${springdoc.swagger-ui.urls[1].url}")
    @NonFinal

    private String profileServiceUrl;
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .servers(List.of(
                        new Server().url(identityServiceUrl).description("Identity Service"),
                        new Server().url(profileServiceUrl).description("Profile Service")
                ))
                .info(new Info().title("Entry test").version("1.0.0"));
    }
}

