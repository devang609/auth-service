# Auth Service

Simple Spring Boot authentication service with JWT access tokens, refresh-token cookies, and a JWKS endpoint.

## Features

- Email/password signup and login
- JWT access token issuance
- HttpOnly refresh-token cookie flow
- Token refresh and logout endpoints
- Public JWKS endpoint for downstream services
- OpenAPI + Swagger UI (available in dev when `springdoc` dependency is enabled; disabled by default in prod)

## Tech Stack

- Java 17
- Spring Boot 3
- Spring Security
- Spring Data JPA
- PostgreSQL
- Maven
- Docker (multi-stage build, distroless runtime)

## Project Structure

- API controllers: [src/main/java/com/authentication/server/controller](src/main/java/com/authentication/server/controller)
- Security configuration: [src/main/java/com/authentication/server/config/SecurityConfig.java](src/main/java/com/authentication/server/config/SecurityConfig.java)
- JWT key loading: [src/main/java/com/authentication/server/security/JwtKeyManager.java](src/main/java/com/authentication/server/security/JwtKeyManager.java)
- Config files: [src/main/resources](src/main/resources)
- Environment template: [.env.example](.env.example)

## Prerequisites

- JDK 17+
- Maven (or use Maven Wrapper)
- PostgreSQL (Supabase or self-hosted)

## Environment Setup

1. Copy [.env.example](.env.example) to `.env`.
2. Fill all values.
3. Ensure JWT key values are external raw PEM URLs:
	 - `JWT_PRIVATE_KEY_PATH`
	 - `JWT_PUBLIC_KEY_PATH`

Important:
- The service currently fetches keys over HTTP(S) from those URLs.
- Do not commit `.env`.
- Local `spring-boot:run` does **not** automatically load `.env` (the `spring.config.import` line is commented out in [src/main/resources/application.properties](src/main/resources/application.properties)).
	- For `prod`, it is imported automatically or import it by custom Docker run command. For `dev`, uncomment `spring.config.import=optional:file:./.env[.properties]`.

## Dev-only Dependencies

Some dependencies are intentionally grouped under a single `DEV-ONLY` comment block in [pom.xml](pom.xml) so they can be toggled for production by commenting/uncommenting that whole block:

- OpenAPI/Swagger UI (`springdoc-openapi-starter-webmvc-ui`)
- Test stack (`spring-boot-starter-test`, `h2`)

## Run Locally

Using Maven Wrapper:

```bash
./mvnw spring-boot:run
```

Windows PowerShell:

```powershell
.\mvnw spring-boot:run
```

By default, profile is controlled by `SPRING_PROFILES_ACTIVE`.

## Run with Docker

Build:

```bash
docker build -t auth-service:latest .
```

Run:

```bash
docker run --rm -p 8080:8080 --env-file .env auth-service:latest
```

For GHCR image:

```bash
docker run --rm -p 8080:8080 --env-file .env ghcr.io/<github-username>/auth-service:latest
```

## API Documentation

When enabled (dev profile *and* the `springdoc` dependency is enabled), OpenAPI docs are available at:

- OpenAPI JSON: `/v3/api-docs`
- Swagger UI: `/swagger-ui/index.html`

Production profile disables Swagger/OpenAPI by default in [src/main/resources/application-prod.properties](src/main/resources/application-prod.properties).

## How To Use (API Guide)

Base URL (local):

```text
http://localhost:8080
```

### 1. Health Check

- `GET /api/health`

Example:

```bash
curl http://localhost:8080/api/health
```

### 2. Sign Up

- `POST /api/auth/signup`

Request body:

```json
{
	"email": "user@example.com",
	"password": "password123",
	"role": "CUSTOMER"
}
```

Example:

```bash
curl -X POST http://localhost:8080/api/auth/signup \
	-H "Content-Type: application/json" \
	-d '{"email":"user@example.com","password":"password123","role":"CUSTOMER"}'
```

Returns a JSON token response and sets refresh token in an HttpOnly cookie.

### 3. Login

- `POST /api/auth/login`

Request body:

```json
{
	"email": "user@example.com",
	"password": "password123"
}
```

Example:

```bash
curl -i -X POST http://localhost:8080/api/auth/login \
	-H "Content-Type: application/json" \
	-d '{"email":"user@example.com","password":"password123"}'
```

### 4. Refresh Access Token

- `POST /api/auth/refresh`

Requirements:
- `refresh_token` cookie
- CSRF header `X-XSRF-TOKEN` with value from `XSRF-TOKEN` cookie

Example (conceptual):

```bash
curl -X POST http://localhost:8080/api/auth/refresh \
	-H "X-XSRF-TOKEN: <xsrf-token-from-cookie>" \
	-b "refresh_token=<refresh-token>; XSRF-TOKEN=<xsrf-token-from-cookie>"
```

### 5. Logout

- `POST /api/auth/logout`

Requirements:
- CSRF header `X-XSRF-TOKEN`

Example (conceptual):

```bash
curl -X POST http://localhost:8080/api/auth/logout \
	-H "X-XSRF-TOKEN: <xsrf-token-from-cookie>" \
	-b "refresh_token=<refresh-token>; XSRF-TOKEN=<xsrf-token-from-cookie>"
```

### 6. JWKS Endpoint

- `GET /.well-known/jwks.json`

Example:

```bash
curl http://localhost:8080/.well-known/jwks.json
```

Use this endpoint from resource servers to validate tokens issued by this service.

## Token Response Format

Successful auth endpoints return:

```json
{
	"access_token": "<jwt>",
	"token_type": "Bearer",
	"expires_in": 900
}
```

## Common Errors

- `400` validation or bad request
- `401` invalid credentials / invalid token / missing token
- `409` conflict (for example duplicate signup)
- `500` unexpected server error

## Security Notes

- Keep private key sources protected and access-controlled.
- Use HTTPS in all environments.
- In production, keep `REFRESH_TOKEN_COOKIE_SECURE=true` and a strict CORS origin list.

## Security Configuration (Current Behavior)

- **Token transport:** access token is accepted from the `access_token` cookie first, then falls back to `Authorization: Bearer ...` (see `CookieBearerTokenResolver`).
- **Cookies:** both refresh and access cookies are `HttpOnly=true`; `Secure`, `SameSite`, `Path`, and `Max-Age` are driven by configuration.
- **CSRF:** enabled via `CookieCsrfTokenRepository` (SPA reads `XSRF-TOKEN` cookie and sends `X-XSRF-TOKEN` header). CSRF is bypassed only for `POST /api/auth/login` and `POST /api/auth/signup`; refresh/logout still require CSRF.
- **CORS:** credentials allowed; `Set-Cookie` exposed; allowed methods are `GET, POST, OPTIONS`; allowed headers include `Content-Type`, `Authorization`, and `X-XSRF-TOKEN`.
- **Public endpoints:** `/api/health`, `/.well-known/jwks.json`, Swagger/OpenAPI paths, and auth endpoints are public; all other endpoints require authentication.
- **JWT validation:** issuer (`jwt.issuer`) and audience (`jwt.audience`) are validated, and tokens are rejected if revoked via `token_valid_after`.

## Configuration Reference (Key Security/Runtime Settings)

These are configured via Spring properties mapped from environment variables in [src/main/resources/application.properties](src/main/resources/application.properties) and exemplified in [.env.example](.env.example):

- JWT keys: `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH` (HTTP(S) raw PEM URLs)
- JWT claims/expiry: `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_ACCESS_TOKEN_EXPIRY_MS`, `JWT_REFRESH_TOKEN_EXPIRY_MS`
- Allowed signup roles: `AUTH_ALLOWED_ROLES`
- CORS: `CORS_ALLOWED_ORIGINS` (supports `*`)
- Cookie controls:
	- Refresh: `REFRESH_TOKEN_COOKIE_NAME`, `REFRESH_TOKEN_COOKIE_PATH`, `REFRESH_TOKEN_COOKIE_MAX_AGE`, `REFRESH_TOKEN_COOKIE_SECURE`, `REFRESH_TOKEN_COOKIE_SAME_SITE`
	- Access: `ACCESS_TOKEN_COOKIE_NAME`, `ACCESS_TOKEN_COOKIE_PATH`, `ACCESS_TOKEN_COOKIE_MAX_AGE`, `ACCESS_TOKEN_COOKIE_SECURE`, `ACCESS_TOKEN_COOKIE_SAME_SITE`

Not everything security-related is `.env` controlled (for example: the CSRF bypass rules, which endpoints are `permitAll`, and the fixed CORS method/header allowlist are defined in code in `SecurityConfig`).

## Contributing

1. Fork and clone the repository.
2. Create a feature branch.
3. Run and test locally.
4. Open a PR with a clear description of changes.
