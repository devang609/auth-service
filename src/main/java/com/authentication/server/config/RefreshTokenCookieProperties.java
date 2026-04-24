package com.authentication.server.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "refresh-token")
@Data
public class RefreshTokenCookieProperties {

    private String cookieName;

    /** Cookie Path (should include both refresh and logout endpoints) */
    private String cookiePath;

    /** seconds */
    private int cookieMaxAge;

    private boolean cookieSecure;

    /** e.g. None, Lax, Strict */
    private String cookieSameSite;
}
