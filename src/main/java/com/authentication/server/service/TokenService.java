package com.authentication.server.service;

import com.authentication.server.config.JwtProperties;
import com.authentication.server.entity.User;
import com.authentication.server.exception.UnauthorizedException;
import com.authentication.server.security.JwtUtil;
import io.jsonwebtoken.Claims;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtUtil jwtUtil;
    private final JwtProperties jwtProperties;

    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", user.getEmail());
        claims.put("role", user.getRole());
        return jwtUtil.generateToken(user.getId().toString(), claims, jwtProperties.getAccessTokenExpiry(), null);
    }

    public long accessTokenExpiresInSeconds() {
        return jwtProperties.getAccessTokenExpiry() / 1000;
    }

    public String generateRefreshToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("token_use", "refresh");
        String jti = UUID.randomUUID().toString();
        return jwtUtil.generateToken(user.getId().toString(), claims, jwtProperties.getRefreshTokenExpiry(), jti);
    }

    public UUID validateAndExtractUserIdFromRefreshToken(String refreshTokenJwt) {
        Claims claims;
        try {
            claims = jwtUtil.parseAndValidate(refreshTokenJwt);
        } catch (Exception e) {
            throw new UnauthorizedException("Invalid refresh token");
        }

        if (!"refresh".equals(String.valueOf(claims.get("token_use")))) {
            throw new UnauthorizedException("Invalid refresh token");
        }

        try {
            return UUID.fromString(claims.getSubject());
        } catch (Exception e) {
            throw new UnauthorizedException("Invalid refresh token");
        }
    }

    public String extractUserId(String token) {
        return jwtUtil.extractSubject(token);
    }

    public boolean validateToken(String token) {
        return jwtUtil.validateToken(token);
    }
}
