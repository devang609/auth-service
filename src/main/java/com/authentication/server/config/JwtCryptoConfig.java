package com.authentication.server.config;

import com.authentication.server.security.JwtKeyManager;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.security.interfaces.RSAPrivateKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
public class JwtCryptoConfig {

    @Bean
    public JwtEncoder jwtEncoder(JwtKeyManager jwtKeyManager) {
        RSAKey rsaKey = new RSAKey.Builder(jwtKeyManager.getPublicKey())
                .privateKey((RSAPrivateKey) jwtKeyManager.getPrivateKey())
                .keyID(jwtKeyManager.getKid())
                .build();

        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(rsaKey)));
    }

    @Bean
    public JwtDecoder jwtDecoder(JwtKeyManager jwtKeyManager, JwtProperties jwtProperties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(jwtKeyManager.getPublicKey()).build();

        OAuth2TokenValidator<Jwt> issuerAndTimestamps = JwtValidators.createDefaultWithIssuer(jwtProperties.getIssuer());
        OAuth2TokenValidator<Jwt> audience = new JwtAudienceValidator(jwtProperties.getAudience());
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(issuerAndTimestamps, audience));

        return decoder;
    }
}

