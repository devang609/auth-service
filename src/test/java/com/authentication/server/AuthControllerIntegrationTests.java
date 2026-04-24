package com.authentication.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.authentication.server.security.JwtKeyManager;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void signup_setsRefreshCookie_andReturnsAccessTokenWithEmailAndRoleClaims() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/signup")
                        .contentType(APPLICATION_JSON)
                        .content("{\"email\":\" Test@Example.com \",\"password\":\"password123\",\"role\":\"user\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").isNumber())
                .andReturn();

        List<String> setCookies = result.getResponse().getHeaders("Set-Cookie");
        String refreshToken = extractCookieValue(setCookies, "refresh_token");
        assertThat(refreshToken).isNotBlank();

        String accessToken = new ObjectMapper()
                .readTree(result.getResponse().getContentAsString())
                .get("access_token")
                .asText();
        var parsed = Jwts.parser()
                .verifyWith(jwtKeyManager.getPublicKey())
                .build()
                .parseSignedClaims(accessToken);

        assertThat(parsed.getHeader().get("kid")).isEqualTo(jwtKeyManager.getKid());
        assertThat(parsed.getPayload().get("email")).isEqualTo("test@example.com");
        assertThat(parsed.getPayload().get("role")).isEqualTo("USER");
    }

    @Test
    void login_failsForNonExistentUser_thenSucceedsAfterSignup() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(APPLICATION_JSON)
                        .content("{\"email\":\"missing@example.com\",\"password\":\"password123\"}"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(APPLICATION_JSON)
                        .content("{\"email\":\"missing@example.com\",\"password\":\"password123\",\"role\":\"USER\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(APPLICATION_JSON)
                        .content("{\"email\":\"missing@example.com\",\"password\":\"password123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @Test
    void refresh_requiresCsrf_andRotatesCookie() throws Exception {
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(APPLICATION_JSON)
                        .content("{\"email\":\"rotate@example.com\",\"password\":\"password123\",\"role\":\"USER\"}"))
                .andExpect(status().isOk());

        // Login to get refresh token cookie.
        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(APPLICATION_JSON)
                        .content("{\"email\":\"rotate@example.com\",\"password\":\"password123\"}"))
                .andExpect(status().isOk())
                .andReturn();

        List<String> loginSetCookies = login.getResponse().getHeaders("Set-Cookie");
        String xsrfToken = extractCookieValue(loginSetCookies, "XSRF-TOKEN");
        assertThat(xsrfToken).isNotBlank();
        String refreshToken = extractCookieValue(loginSetCookies, "refresh_token");
        assertThat(refreshToken).isNotBlank();

        // Missing CSRF should be rejected.
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", refreshToken)))
                .andExpect(status().isForbidden());

        // With CSRF should work and rotate refresh cookie.
        MvcResult refreshed = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", refreshToken), new Cookie("XSRF-TOKEN", xsrfToken))
                        .header("X-XSRF-TOKEN", xsrfToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andReturn();

        List<String> rotatedSetCookies = refreshed.getResponse().getHeaders("Set-Cookie");
        String rotatedRefreshToken = extractCookieValue(rotatedSetCookies, "refresh_token");
        assertThat(rotatedRefreshToken).isNotBlank();
        assertThat(rotatedRefreshToken).isNotEqualTo(refreshToken);
    }

    @Test
    void logout_requiresCsrf_andClearsRefreshCookie() throws Exception {
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(APPLICATION_JSON)
                        .content("{\"email\":\"logout@example.com\",\"password\":\"password123\",\"role\":\"USER\"}"))
                .andExpect(status().isOk());

        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(APPLICATION_JSON)
                        .content("{\"email\":\"logout@example.com\",\"password\":\"password123\"}"))
                .andExpect(status().isOk())
                .andReturn();

        List<String> loginSetCookies = login.getResponse().getHeaders("Set-Cookie");
        String xsrfToken = extractCookieValue(loginSetCookies, "XSRF-TOKEN");
        assertThat(xsrfToken).isNotBlank();

        mockMvc.perform(post("/api/auth/logout"))
                .andExpect(status().isForbidden());

        MvcResult logout = mockMvc.perform(post("/api/auth/logout")
                        .cookie(new Cookie("XSRF-TOKEN", xsrfToken))
                        .header("X-XSRF-TOKEN", xsrfToken))
                .andExpect(status().isNoContent())
                .andReturn();

        List<String> logoutSetCookies = logout.getResponse().getHeaders("Set-Cookie");
        String refreshCookieHeader = logoutSetCookies.stream()
                .filter(h -> h.startsWith("refresh_token="))
                .findFirst()
                .orElse("");
        assertThat(refreshCookieHeader).contains("Max-Age=0");
    }

    @Test
    void jwks_returnsKeyWithCorrectKid() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value(jwtKeyManager.getKid()))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].e").isNotEmpty());
    }

    @Autowired
    private JwtKeyManager jwtKeyManager;

    private static String extractCookieValue(List<String> setCookieHeaders, String cookieName) {
        if (setCookieHeaders == null) {
            return "";
        }

        for (String header : setCookieHeaders) {
            String value = extractCookieValueFromSingleHeader(header, cookieName);
            if (!value.isBlank()) {
                return value;
            }
        }

        return "";
    }

    private static String extractCookieValueFromSingleHeader(String setCookieHeader, String cookieName) {
        if (setCookieHeader == null) {
            return "";
        }
        String prefix = cookieName + "=";
        int start = setCookieHeader.indexOf(prefix);
        if (start < 0) {
            return "";
        }
        start += prefix.length();
        int end = setCookieHeader.indexOf(';', start);
        if (end < 0) {
            end = setCookieHeader.length();
        }
        return setCookieHeader.substring(start, end);
    }
}
