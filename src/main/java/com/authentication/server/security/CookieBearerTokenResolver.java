package com.authentication.server.security;

import com.authentication.server.config.AccessTokenCookieProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CookieBearerTokenResolver implements BearerTokenResolver {

    private final AccessTokenCookieProperties accessTokenCookieProperties;
    private final DefaultBearerTokenResolver fallback = createFallback();

    @Override
    public String resolve(HttpServletRequest request) {
        String fromCookie = resolveFromCookie(request);
        if (fromCookie != null && !fromCookie.isBlank()) {
            return fromCookie;
        }

        return fallback.resolve(request);
    }

    private String resolveFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        String cookieName = accessTokenCookieProperties.getCookieName();
        if (cookieName == null || cookieName.isBlank()) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private static DefaultBearerTokenResolver createFallback() {
        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        resolver.setAllowFormEncodedBodyParameter(false);
        resolver.setAllowUriQueryParameter(false);
        return resolver;
    }
}
