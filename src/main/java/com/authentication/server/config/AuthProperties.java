package com.authentication.server.config;

import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth")
@Data
public class AuthProperties {

    //Add roles u want to allow
    private List<String> allowedRoles = List.of("ADMIN", "USER");
}

