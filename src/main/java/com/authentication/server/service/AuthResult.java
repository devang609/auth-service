package com.authentication.server.service;

import com.authentication.server.dto.response.TokenResponse;

public record AuthResult(TokenResponse tokenResponse, String refreshTokenValue) {
}
