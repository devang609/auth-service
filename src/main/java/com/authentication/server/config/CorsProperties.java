package com.authentication.server.config;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.cors")
@Data
public class CorsProperties {

    /** Comma-separated list supported via Spring Binder */
    private List<String> allowedOrigins = new ArrayList<>();
}
