package com.authentication.server.security;

import com.authentication.server.config.JwtProperties;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

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
            throw new IllegalStateException("JWT private key URL is not configured (jwt.private-key-path)");
        }
        if (jwtProperties.getPublicKeyPath() == null || jwtProperties.getPublicKeyPath().isBlank()) {
            throw new IllegalStateException("JWT public key URL is not configured (jwt.public-key-path)");
        }

        try {
            String publicKeyUrl = jwtProperties.getPublicKeyPath().trim();
            String privateKeyUrl = jwtProperties.getPrivateKeyPath().trim();

            byte[] publicDer = readPemDerBytesFromUrl(publicKeyUrl, "PUBLIC KEY");
            this.publicKey = (RSAPublicKey) readPublicKey(publicDer);

            byte[] privateDer = readPemDerBytesFromUrl(privateKeyUrl, "PRIVATE KEY");
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

    private static byte[] readPemDerBytesFromUrl(String location, String pemLabel) throws IOException, InterruptedException {
        URI uri;
        try {
            uri = URI.create(location);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid JWT key URL: " + location, ex);
        }

        String scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http"))) {
            throw new IllegalStateException("JWT key URL must use HTTP or HTTPS: " + location);
        }

        HttpRequest request = HttpRequest.newBuilder(uri)
                .GET()
                .header("Accept", "application/x-pem-file,text/plain,*/*")
                .build();
        HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.US_ASCII));

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("Failed to fetch JWT key from URL: " + location + " (status " + response.statusCode() + ")");
        }

        String pem = response.body();
        String begin = "-----BEGIN " + pemLabel + "-----";
        String end = "-----END " + pemLabel + "-----";

        int beginIdx = pem.indexOf(begin);
        int endIdx = pem.indexOf(end);
        if (beginIdx < 0 || endIdx < 0 || endIdx <= beginIdx) {
            throw new IllegalArgumentException("Invalid PEM format from " + location);
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
