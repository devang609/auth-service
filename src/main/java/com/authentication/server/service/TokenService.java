package com.authentication.server.service;

import com.authentication.server.config.JwtProperties;
import com.authentication.server.entity.User;
import com.authentication.server.security.JwtUtil;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtUtil jwtUtil;
    private final JwtProperties jwtProperties;

    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        return jwtUtil.generateToken(user.getId().toString(), claims, jwtProperties.getAccessTokenExpiry());
    }

    public long accessTokenExpiresInSeconds() {
        return jwtProperties.getAccessTokenExpiry() / 1000;
    }

    public String extractUserId(String token) {
        return jwtUtil.extractSubject(token);
    }

    public boolean validateToken(String token) {
        return jwtUtil.validateToken(token);
    }
}
