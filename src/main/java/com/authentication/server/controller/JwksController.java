package com.authentication.server.controller;

import com.authentication.server.security.JwtKeyManager;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JwksController {

    private final JwtKeyManager jwtKeyManager;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return Map.of("keys", List.of(jwtKeyManager.getJwk()));
    }
}

