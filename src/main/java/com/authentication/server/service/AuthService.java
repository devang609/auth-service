package com.authentication.server.service;

import com.authentication.server.config.AuthProperties;
import com.authentication.server.dto.request.LoginRequest;
import com.authentication.server.dto.request.SignupRequest;
import com.authentication.server.dto.response.TokenResponse;
import com.authentication.server.entity.User;
import com.authentication.server.exception.BadRequestException;
import com.authentication.server.exception.UnauthorizedException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
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
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$", Pattern.CASE_INSENSITIVE);

    private final UserService userService;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final AuthProperties authProperties;

    private final SecureRandom secureRandom = new SecureRandom();

    @Transactional
    public AuthResult signup(SignupRequest signupRequest) {
        String email = normalizeAndValidateEmail(signupRequest.getEmail());
        String role = normalizeRole(signupRequest.getRole());
        log.info("Signup attempt for email: {}", email);

        validateRoleAllowed(role);

        User user = new User();
        user.setEmail(email);
        user.setUsername(generateUniqueUsername(email));
        user.setPasswordHash(passwordEncoder.encode(signupRequest.getPassword()));
        user.setRole(role);
        user.setTokenValidAfter(Instant.EPOCH);

        try {
            user = userService.save(user);
        } catch (DataIntegrityViolationException e) {
            // Race condition: someone else registered at same time.
            throw e;
        }

        String accessToken = tokenService.generateAccessToken(user);
        String refreshTokenJwt = tokenService.generateRefreshToken(user);

        TokenResponse response = TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(tokenService.accessTokenExpiresInSeconds())
                .build();

        return new AuthResult(response, refreshTokenJwt);
    }

    @Transactional(readOnly = true)
    public AuthResult login(LoginRequest loginRequest) {
        String email = normalizeAndValidateEmail(loginRequest.getEmail());
        log.info("Login attempt for email: {}", email);

        User user = userService.findByEmail(email)
                .orElseThrow(() -> new UnauthorizedException("Invalid credentials"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPasswordHash())) {
            throw new UnauthorizedException("Invalid credentials");
        }

        String accessToken = tokenService.generateAccessToken(user);
        String refreshTokenJwt = tokenService.generateRefreshToken(user);

        TokenResponse response = TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(tokenService.accessTokenExpiresInSeconds())
                .build();

        return new AuthResult(response, refreshTokenJwt);
    }

    @Transactional
    public AuthResult refreshAccessToken(String refreshTokenValue) {
        log.info("Token refresh attempt");

        var userId = tokenService.validateAndExtractUserIdFromRefreshToken(refreshTokenValue);
        User user = userService.findById(userId)
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));

        String accessToken = tokenService.generateAccessToken(user);
        String newRefreshTokenJwt = tokenService.generateRefreshToken(user);

        TokenResponse response = TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(tokenService.accessTokenExpiresInSeconds())
                .build();

        return new AuthResult(response, newRefreshTokenJwt);
    }

    @Transactional
    public void logout(String refreshTokenValue) {
        if (refreshTokenValue == null || refreshTokenValue.isBlank()) {
            return;
        }

        try {
            var userId = tokenService.validateAndExtractUserIdFromRefreshToken(refreshTokenValue);
            User user = userService.findById(userId).orElse(null);
            if (user == null) {
                return;
            }

            user.setTokenValidAfter(revocationInstant());
            userService.save(user);
        } catch (UnauthorizedException ignored) {
            // Logout is idempotent.
        }
    }

    private static Instant revocationInstant() {
        return Instant.now().truncatedTo(ChronoUnit.SECONDS).plusSeconds(1);
    }

    private void validateRoleAllowed(String role) {
        Set<String> allowed = authProperties.getAllowedRoles().stream()
                .map(this::normalizeRole)
                .collect(java.util.stream.Collectors.toSet());

        if (!allowed.contains(role)) {
            throw new BadRequestException("Invalid role");
        }
    }

    private String normalizeRole(String role) {
        return role == null ? "" : role.trim().toUpperCase(Locale.ROOT);
    }

    private String normalizeAndValidateEmail(String rawEmail) {
        String email = rawEmail == null ? "" : rawEmail.trim().toLowerCase(Locale.ROOT);
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            throw new BadRequestException("Email must be valid");
        }
        return email;
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
