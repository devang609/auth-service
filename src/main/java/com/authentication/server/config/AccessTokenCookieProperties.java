package com.authentication.server.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "access-token")
@Data
public class AccessTokenCookieProperties {

    private String cookieName;

    /** Cookie Path */
    private String cookiePath;

    /** seconds */
    private int cookieMaxAge;

    private boolean cookieSecure;

    /** e.g. None, Lax, Strict */
    private String cookieSameSite;
}

