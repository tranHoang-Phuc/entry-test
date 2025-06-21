package com.dts.entry.apigateway.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .servers(List.of(
                        new Server().url("http://localhost:9191/api/v1/identity").description("Identity Service"),
                        new Server().url("http://localhost:9191/api/v1/profile").description("Profile Service")
                ))
                .info(new Info().title("SEP490").version("1.0.0"));
    }
}

