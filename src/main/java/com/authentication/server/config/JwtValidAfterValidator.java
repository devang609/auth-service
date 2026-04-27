package com.authentication.server.config;

import com.authentication.server.service.UserService;
import java.time.Instant;
import java.util.UUID;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class JwtValidAfterValidator implements OAuth2TokenValidator<Jwt> {

    private final UserService userService;

    public JwtValidAfterValidator(UserService userService) {
        this.userService = userService;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        UUID userId;
        try {
            userId = UUID.fromString(token.getSubject());
        } catch (Exception e) {
            return failure("Invalid subject");
        }

        Instant issuedAt = token.getIssuedAt();
        if (issuedAt == null) {
            return failure("Missing iat");
        }

        Instant tokenValidAfter = userService.findById(userId)
                .map(u -> u.getTokenValidAfter() == null ? Instant.EPOCH : u.getTokenValidAfter())
                .orElse(null);

        if (tokenValidAfter == null) {
            return failure("User not found");
        }

        if (issuedAt.isBefore(tokenValidAfter)) {
            return failure("Token has been revoked");
        }

        return OAuth2TokenValidatorResult.success();
    }

    private static OAuth2TokenValidatorResult failure(String message) {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", message, null));
    }
}
