package com.authentication.server.security;

import com.authentication.server.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import java.util.Date;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtUtil {

    private final JwtProperties jwtProperties;
    private final JwtKeyManager jwtKeyManager;

    public String generateToken(String subject, Map<String, Object> claims, Long expiryMs, String jti) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + expiryMs);

        var builder = Jwts.builder()
                .header().add("kid", jwtKeyManager.getKid()).and()
                .claims(claims)
                .subject(subject)
                .issuer(jwtProperties.getIssuer())
                .audience().add(jwtProperties.getAudience()).and()
                .issuedAt(now)
                .expiration(exp)
                .signWith(jwtKeyManager.getPrivateKey(), Jwts.SIG.RS256);

        if (jti != null && !jti.isBlank()) {
            builder.id(jti);
        }

        return builder.compact();
    }

    public String extractSubject(String token) {
        return extractAllClaims(token).getSubject();
    }

    public Claims parseAndValidate(String token) {
        return extractAllClaims(token);
    }

    public boolean validateToken(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Invalid JWT: {}", e.getMessage());
            return false;
        }
    }

    private Claims extractAllClaims(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(jwtKeyManager.getPublicKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        if (jwtProperties.getIssuer() != null && !jwtProperties.getIssuer().isBlank()) {
            if (!jwtProperties.getIssuer().equals(claims.getIssuer())) {
                throw new JwtException("Invalid issuer");
            }
        }

        if (jwtProperties.getAudience() != null && !jwtProperties.getAudience().isBlank()) {
            if (!audienceContains(claims, jwtProperties.getAudience())) {
                throw new JwtException("Invalid audience");
            }
        }

        return claims;
    }

    private static boolean audienceContains(Claims claims, String expected) {
        Object aud = claims.get("aud");
        if (aud instanceof String audString) {
            return expected.equals(audString);
        }
        if (aud instanceof Iterable<?> audIterable) {
            for (Object item : audIterable) {
                if (expected.equals(String.valueOf(item))) {
                    return true;
                }
            }
            return false;
        }
        var getter = claims.getAudience();
        return getter != null && getter.contains(expected);
    }
}
