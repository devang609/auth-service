package com.authentication.server.controller;

import com.authentication.server.dto.request.LoginRequest;
import com.authentication.server.dto.request.SignupRequest;
import com.authentication.server.dto.response.TokenResponse;
import com.authentication.server.exception.UnauthorizedException;
import com.authentication.server.service.AuthResult;
import com.authentication.server.service.AuthService;
import com.authentication.server.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final CookieUtil cookieUtil;

    @PostMapping("/signup")
    public ResponseEntity<TokenResponse> signup(
            @Valid @RequestBody SignupRequest signupRequest,
            HttpServletResponse response
    ) {
        AuthResult result = authService.signup(signupRequest);
        cookieUtil.setAccessTokenCookie(response, result.tokenResponse().getAccessToken());
        cookieUtil.setRefreshTokenCookie(response, result.refreshTokenValue());
        return ResponseEntity.ok(result.tokenResponse());
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletResponse response
    ) {
        AuthResult result = authService.login(loginRequest);
        cookieUtil.setAccessTokenCookie(response, result.tokenResponse().getAccessToken());
        cookieUtil.setRefreshTokenCookie(response, result.refreshTokenValue());
        return ResponseEntity.ok(result.tokenResponse());
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = cookieUtil.extractRefreshTokenFromCookie(request);
        AuthResult result = authService.refreshAccessToken(refreshToken);
        cookieUtil.setAccessTokenCookie(response, result.tokenResponse().getAccessToken());
        cookieUtil.setRefreshTokenCookie(response, result.refreshTokenValue());
        return ResponseEntity.ok(result.tokenResponse());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = null;
        try {
            refreshToken = cookieUtil.extractRefreshTokenFromCookie(request);
        } catch (UnauthorizedException ignored) {
            // Logout is idempotent: if cookie is missing/invalid, still clear browser cookies.
        }
        authService.logout(refreshToken);
        cookieUtil.clearAccessTokenCookie(response);
        cookieUtil.clearRefreshTokenCookie(response);
        return ResponseEntity.noContent().build();
    }
}
