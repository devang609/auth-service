package com.authentication.server.service;

import com.authentication.server.dto.request.LoginRequest;
import com.authentication.server.dto.response.TokenResponse;
import com.authentication.server.entity.RefreshToken;
import com.authentication.server.entity.User;
import com.authentication.server.exception.UnauthorizedException;
import java.security.SecureRandom;
import java.util.Locale;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private static final String USERNAME_SUFFIX_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

    private final UserService userService;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;

    private final SecureRandom secureRandom = new SecureRandom();

    @Transactional
    public AuthResult login(LoginRequest loginRequest) {
        String email = loginRequest.getEmail().trim().toLowerCase(Locale.ROOT);
        log.info("Login attempt for email: {}", email);

        User user = userService.findByEmail(email)
                .orElseGet(() -> createNewUser(email, loginRequest.getPassword()));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPasswordHash())) {
            throw new UnauthorizedException("Invalid credentials");
        }

        String accessToken = tokenService.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        TokenResponse response = TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(tokenService.accessTokenExpiresInSeconds())
                .build();

        return new AuthResult(response, refreshToken.getToken());
    }

    @Transactional
    public AuthResult refreshAccessToken(String refreshTokenValue) {
        log.info("Token refresh attempt");

        RefreshToken refreshToken = refreshTokenService.validateRefreshToken(refreshTokenValue);
        refreshTokenService.revokeToken(refreshToken);

        User user = refreshToken.getUser();
        String accessToken = tokenService.generateAccessToken(user);
        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

        TokenResponse response = TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(tokenService.accessTokenExpiresInSeconds())
                .build();

        return new AuthResult(response, newRefreshToken.getToken());
    }

    @Transactional
    public void logout(String refreshTokenValue) {
        log.info("Logout attempt");

        RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenValue)
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));

        refreshTokenService.revokeToken(refreshToken);
        log.info("User logged out successfully: {}", refreshToken.getUser().getId());
    }

    private User createNewUser(String email, String rawPassword) {
        log.info("Auto-registering user with email: {}", email);

        User user = new User();
        user.setEmail(email);
        user.setUsername(generateUniqueUsername(email));
        user.setPasswordHash(passwordEncoder.encode(rawPassword));

        try {
            return userService.save(user);
        } catch (DataIntegrityViolationException e) {
            // Race condition: someone else registered at same time.
            return userService.findByEmail(email).orElseThrow(() -> e);
        }
    }

    private String generateUniqueUsername(String email) {
        String base = extractUsernameFromEmail(email);
        if (!userService.existsByUsername(base)) {
            return base;
        }

        for (int i = 0; i < 10; i++) {
            String candidate = base + "_" + randomSuffix(6);
            if (!userService.existsByUsername(candidate)) {
                return candidate;
            }
        }

        return base + "_" + System.currentTimeMillis();
    }

    private String extractUsernameFromEmail(String email) {
        int atIndex = email.indexOf('@');
        String raw = (atIndex > 0) ? email.substring(0, atIndex) : email;
        raw = raw.toLowerCase(Locale.ROOT);
        raw = raw.replaceAll("[^a-z0-9._-]", "");
        return raw.isBlank() ? "user" : raw;
    }

    private String randomSuffix(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int idx = secureRandom.nextInt(USERNAME_SUFFIX_ALPHABET.length());
            sb.append(USERNAME_SUFFIX_ALPHABET.charAt(idx));
        }
        return sb.toString();
    }
}
