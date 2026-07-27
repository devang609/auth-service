package com.authentication.server.util;

import com.authentication.server.config.RefreshTokenCookieProperties;
import com.authentication.server.exception.UnauthorizedException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CookieUtil {

    private final RefreshTokenCookieProperties cookieProperties;

    public void setRefreshTokenCookie(HttpServletResponse response, String refreshTokenValue) {
        ResponseCookie cookie = ResponseCookie.from(cookieProperties.getCookieName(), refreshTokenValue)
                .httpOnly(true)
                .secure(cookieProperties.isCookieSecure())
                .path(cookieProperties.getCookiePath())
                .maxAge(Duration.ofSeconds(cookieProperties.getCookieMaxAge()))
                .sameSite(cookieProperties.getCookieSameSite())
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public String extractRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            throw new UnauthorizedException("No refresh token found");
        }

        for (Cookie cookie : cookies) {
            if (cookieProperties.getCookieName().equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        throw new UnauthorizedException("No refresh token found");
    }

    public void clearRefreshTokenCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(cookieProperties.getCookieName(), "")
                .httpOnly(true)
                .secure(cookieProperties.isCookieSecure())
                .path(cookieProperties.getCookiePath())
                .maxAge(Duration.ZERO)
                .sameSite(cookieProperties.getCookieSameSite())
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
