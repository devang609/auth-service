package com.authentication.server.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtProperties {

    private String privateKeyPath;
    private String publicKeyPath;
    private String issuer;
    private String audience;

    /** milliseconds */
    private Long accessTokenExpiry;

    /** milliseconds */
    private Long refreshTokenExpiry;
}
