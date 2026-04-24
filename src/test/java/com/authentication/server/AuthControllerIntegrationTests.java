package com.authentication.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
    void login_setsRefreshCookie_andReturnsAccessToken() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(APPLICATION_JSON)
                        .content("{\"email\":\"test@example.com\",\"password\":\"password123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").isNumber())
                .andReturn();

            List<String> setCookies = result.getResponse().getHeaders("Set-Cookie");
            String refreshToken = extractCookieValue(setCookies, "refresh_token");
            assertThat(refreshToken).isNotBlank();
    }

    @Test
    void refresh_requiresCsrf_andRotatesCookie() throws Exception {
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
