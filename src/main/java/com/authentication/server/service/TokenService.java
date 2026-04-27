package com.authentication.server.service;

import com.authentication.server.config.JwtProperties;
import com.authentication.server.entity.User;
import com.authentication.server.exception.UnauthorizedException;
import com.authentication.server.security.JwtKeyManager;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final JwtKeyManager jwtKeyManager;
    private final JwtProperties jwtProperties;

    public String generateAccessToken(User user) {
        String issuer = requireIssuer();
        String audience = requireAudience();

        Instant issuedAt = computeIssuedAt(user);
        Instant exp = issuedAt.plusMillis(jwtProperties.getAccessTokenExpiry());

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .audience(List.of(audience))
                .issuedAt(issuedAt)
                .expiresAt(exp)
                .subject(user.getId().toString())
                .claim("email", user.getEmail())
                .claim("role", user.getRole())
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(jwtKeyManager.getKid())
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    public long accessTokenExpiresInSeconds() {
        return jwtProperties.getAccessTokenExpiry() / 1000;
    }

    public String generateRefreshToken(User user) {
        String jti = UUID.randomUUID().toString();
        String issuer = requireIssuer();
        String audience = requireAudience();

        Instant issuedAt = computeIssuedAt(user);
        Instant exp = issuedAt.plusMillis(jwtProperties.getRefreshTokenExpiry());

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .audience(List.of(audience))
                .issuedAt(issuedAt)
                .expiresAt(exp)
                .subject(user.getId().toString())
                .id(jti)
                .claim("token_use", "refresh")
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(jwtKeyManager.getKid())
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    public UUID validateAndExtractUserIdFromRefreshToken(String refreshTokenJwt) {
        Jwt jwt;
        try {
            jwt = jwtDecoder.decode(refreshTokenJwt);
        } catch (Exception e) {
            throw new UnauthorizedException("Invalid refresh token");
        }

        if (!"refresh".equals(jwt.getClaimAsString("token_use"))) {
            throw new UnauthorizedException("Invalid refresh token");
        }

        try {
            return UUID.fromString(jwt.getSubject());
        } catch (Exception e) {
            throw new UnauthorizedException("Invalid refresh token");
        }
    }

    public String extractUserId(String token) {
        try {
            return jwtDecoder.decode(token).getSubject();
        } catch (Exception e) {
            throw new UnauthorizedException("Invalid token");
        }
    }

    public boolean validateToken(String token) {
        try {
            jwtDecoder.decode(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String requireIssuer() {
        String issuer = jwtProperties.getIssuer();
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalStateException("JWT issuer is not configured (jwt.issuer)");
        }
        return issuer;
    }

    private String requireAudience() {
        String audience = jwtProperties.getAudience();
        if (audience == null || audience.isBlank()) {
            throw new IllegalStateException("JWT audience is not configured (jwt.audience)");
        }
        return audience;
    }

    private static Instant computeIssuedAt(User user) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant validAfter = user.getTokenValidAfter() == null
                ? Instant.EPOCH
                : user.getTokenValidAfter().truncatedTo(ChronoUnit.SECONDS);

        return now.isBefore(validAfter) ? validAfter : now;
    }
}
