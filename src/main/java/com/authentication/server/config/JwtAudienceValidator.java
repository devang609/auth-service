package com.authentication.server.config;

import java.util.List;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class JwtAudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final String audience;

    public JwtAudienceValidator(String audience) {
        this.audience = audience;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if (audience == null || audience.isBlank()) {
            return OAuth2TokenValidatorResult.success();
        }

        List<String> audiences = token.getAudience();
        if (audiences != null && audiences.contains(audience)) {
            return OAuth2TokenValidatorResult.success();
        }

        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid audience", null));
    }
}

