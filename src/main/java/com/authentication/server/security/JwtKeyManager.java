package com.authentication.server.security;

import com.authentication.server.config.JwtProperties;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtKeyManager {

    private final JwtProperties jwtProperties;

    @Getter
    private PrivateKey privateKey;

    @Getter
    private RSAPublicKey publicKey;

    @Getter
    private String kid;

    @Getter
    private Map<String, Object> jwk;

    @jakarta.annotation.PostConstruct
    void init() {
        if (jwtProperties.getPrivateKeyPath() == null || jwtProperties.getPrivateKeyPath().isBlank()) {
            throw new IllegalStateException("JWT private key path is not configured (jwt.private-key-path)");
        }
        if (jwtProperties.getPublicKeyPath() == null || jwtProperties.getPublicKeyPath().isBlank()) {
            throw new IllegalStateException("JWT public key path is not configured (jwt.public-key-path)");
        }

        try {
            Path publicPath = Path.of(jwtProperties.getPublicKeyPath()).toAbsolutePath().normalize();
            Path privatePath = Path.of(jwtProperties.getPrivateKeyPath()).toAbsolutePath().normalize();

            if (!Files.exists(publicPath)) {
                throw new IllegalStateException("JWT public key not found at: " + publicPath);
            }
            if (!Files.exists(privatePath)) {
                throw new IllegalStateException("JWT private key not found at: " + privatePath);
            }

            byte[] publicDer = readPemDerBytes(publicPath, "PUBLIC KEY");
            this.publicKey = (RSAPublicKey) readPublicKey(publicDer);

            byte[] privateDer = readPemDerBytes(privatePath, "PRIVATE KEY");
            this.privateKey = readPrivateKey(privateDer);

            this.kid = computeKid(publicDer);
            this.jwk = buildJwk(this.publicKey, this.kid);
        } catch (Exception e) {
            if (e instanceof IllegalStateException ise) {
                throw ise;
            }
            throw new IllegalStateException("Failed to load JWT RSA keys", e);
        }
    }

    private static byte[] readPemDerBytes(Path path, String pemLabel) throws IOException {
        String pem = Files.readString(path, StandardCharsets.US_ASCII);
        String begin = "-----BEGIN " + pemLabel + "-----";
        String end = "-----END " + pemLabel + "-----";

        int beginIdx = pem.indexOf(begin);
        int endIdx = pem.indexOf(end);
        if (beginIdx < 0 || endIdx < 0 || endIdx <= beginIdx) {
            throw new IllegalArgumentException("Invalid PEM format for " + path);
        }

        String base64 = pem.substring(beginIdx + begin.length(), endIdx)
                .replaceAll("\\s", "");

        return Base64.getDecoder().decode(base64);
    }

    private static PublicKey readPublicKey(byte[] publicDer) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(publicDer));
    }

    private static PrivateKey readPrivateKey(byte[] privateDer) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateDer));
    }

    private static String computeKid(byte[] publicKeyDer) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] digest = sha256.digest(publicKeyDer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static Map<String, Object> buildJwk(RSAPublicKey publicKey, String kid) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("use", "sig");
        jwk.put("alg", "RS256");
        jwk.put("kid", kid);
        jwk.put("n", base64UrlEncodeUnsigned(publicKey.getModulus()));
        jwk.put("e", base64UrlEncodeUnsigned(publicKey.getPublicExponent()));
        return jwk;
    }

    private static String base64UrlEncodeUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
