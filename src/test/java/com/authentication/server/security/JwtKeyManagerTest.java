package com.authentication.server.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;

class JwtKeyManagerTest {

    @Test
    void devAllowsRawPemValues() throws Exception {
        byte[] der = readPemDerBytes("""
                -----BEGIN PUBLIC KEY-----
                AQID
                -----END PUBLIC KEY-----
                """, "PUBLIC KEY", true);

        assertThat(der).containsExactly(1, 2, 3);
    }

    @Test
    void prodRejectsLocalKeyLocations() {
        assertThatThrownBy(() -> readPemDerBytes("jwt-public.pem", "PUBLIC KEY", false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must use HTTP or HTTPS outside dev");
    }

    private static byte[] readPemDerBytes(String location, String pemLabel, boolean allowLocalDevKeys) throws Exception {
        Method method = JwtKeyManager.class.getDeclaredMethod("readPemDerBytes", String.class, String.class, boolean.class);
        method.setAccessible(true);
        try {
            return (byte[]) method.invoke(null, location, pemLabel, allowLocalDevKeys);
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception exception) {
                throw exception;
            }
            throw e;
        }
    }
}
