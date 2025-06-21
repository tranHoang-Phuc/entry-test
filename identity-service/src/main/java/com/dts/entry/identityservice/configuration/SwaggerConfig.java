package com.dts.entry.identityservice.configuration;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(title = "Identity Service API", version = "v1"),
        servers = {
                @Server(url = "/api/v1/identity", description = "Identity Service")
        }
)
public class SwaggerConfig {
}
