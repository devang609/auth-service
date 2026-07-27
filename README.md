# Auth Service

Ready-to-use Spring Boot authentication service with JWT-RSA access-refresh token pairs and a JWKS endpoint.

## Features

- Email/password signup and login
- JWT access token issuance
- HttpOnly refresh-token cookie flow
- Token refresh and logout endpoints
- Public JWKS endpoint for downstream services
- OpenAPI + Swagger UI (available in dev when `springdoc` dependency is enabled; disabled by default in prod)

## Application Flow and Design Rationale

This service keeps the auth server stateless for token handling: it issues signed JWT access and refresh tokens, but does not store token values, refresh sessions, or token revocation state in the database.

Flow:

1. The client signs up or logs in with email/password.
2. The service validates the user and returns a short-lived access token in the response body.
3. The service also sets the refresh token as an `HttpOnly` cookie.
4. The client sends the access token as `Authorization: Bearer <token>` to protected APIs.
5. When the access token expires, the client calls `POST /api/auth/refresh`; the browser sends the refresh cookie, and the service returns a new access token.
6. On logout, the service clears the refresh cookie. Already-issued access tokens naturally expire.

This differs from session-store or refresh-token-table designs because token validity is proven cryptographically instead of by database lookup. Downstream services can validate access tokens with the public JWKS endpoint without calling this auth service for every request.

The main design constraint is no token-related persistence. That keeps the service simpler and more robust operationally: no token table hot path, no server-side session cleanup job, no database dependency for every token validation, and fewer failure modes during traffic spikes. A valid signed token remains usable until its expiry, so short access-token lifetimes are important.

Trade-offs:

- Logout is cookie cleanup, not immediate global revocation of every already-issued access token.
- Refresh tokens are not rotated server-side because there is no stored refresh-token family to track.
- Account-wide forced logout or per-device session management would require adding token/session persistence.
- Security relies on short access-token expiry, protected refresh cookies, HTTPS, strict CORS, CSRF protection, and key management.

Client responsibilities:

- Store the access token only in memory or another short-lived client location.
- Send access tokens using the `Authorization` header.
- Include credentials when calling refresh/logout endpoints so the refresh cookie is sent.
- Send the `X-XSRF-TOKEN` header for refresh/logout.
- Handle `401` by refreshing once, retrying the original request, then sending the user back to login if refresh fails.
- Treat logout as local session end plus refresh-cookie clearing; do not assume old access tokens are revoked before expiry.

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

## Database Setup

Apply the SQL migration before running with the `prod` profile:

```bash
psql "$DATABASE_URL" -f migrations/001_create_users.sql
```

The `dev` profile can still use Hibernate `ddl-auto=update`, but [migrations/001_create_users.sql](migrations/001_create_users.sql) is the portable schema source for fresh clones.

## Environment Setup

1. Copy [.env.example](.env.example) to `.env`.
2. Fill all values.
3. Apply [migrations/001_create_users.sql](migrations/001_create_users.sql) to your database.
4. Ensure JWT key values are configured:
	 - `JWT_PRIVATE_KEY_PATH`
	 - `JWT_PUBLIC_KEY_PATH`

Important:
- In `prod`, JWT keys must be external raw PEM HTTP(S) URLs.
- In `dev`, JWT keys may be HTTP(S) URLs, local paths, `file:` URLs, or raw PEM values.
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
	"expires_in": 600
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

- **Token transport:** access tokens are returned in the response body and accepted via `Authorization: Bearer ...`; they are not set as cookies.
- **Cookies:** refresh tokens are set as `HttpOnly=true`, `Secure=true`, `SameSite=Strict`, with path and max-age driven by configuration.
- **Refresh behavior:** `POST /api/auth/refresh` only reads the refresh token from the cookie, returns a new access token, and does not rotate the refresh token.
- **CSRF:** enabled via `CookieCsrfTokenRepository` (SPA reads `XSRF-TOKEN` cookie and sends `X-XSRF-TOKEN` header). CSRF is bypassed only for `POST /api/auth/login` and `POST /api/auth/signup`; refresh/logout still require CSRF.
- **CORS:** credentials allowed; `Set-Cookie` exposed; allowed methods are `GET, POST, OPTIONS`; allowed headers include `Content-Type`, `Authorization`, and `X-XSRF-TOKEN`.
- **Public endpoints:** `/api/health`, `/.well-known/jwks.json`, Swagger/OpenAPI paths, and auth endpoints are public; all other endpoints require authentication.
- **JWT validation:** issuer (`jwt.issuer`), audience (`jwt.audience`), and expiry are validated. Token values and token revocation state are not persisted.

## Configuration Reference (Key Security/Runtime Settings)

These are configured via Spring properties mapped from environment variables in [src/main/resources/application.properties](src/main/resources/application.properties) and exemplified in [.env.example](.env.example):

- JWT keys: `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH` (`prod`: HTTP(S) raw PEM URLs; `dev`: HTTP(S), local path, `file:` URL, or raw PEM)
- JWT claims/expiry: `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_ACCESS_TOKEN_EXPIRY_MS`, `JWT_REFRESH_TOKEN_EXPIRY_MS`
- Allowed signup roles: `AUTH_ALLOWED_ROLES`
- CORS: `CORS_ALLOWED_ORIGINS` (supports `*`)
- Cookie controls:
	- Refresh: `REFRESH_TOKEN_COOKIE_NAME`, `REFRESH_TOKEN_COOKIE_PATH`, `REFRESH_TOKEN_COOKIE_MAX_AGE`, `REFRESH_TOKEN_COOKIE_SECURE`, `REFRESH_TOKEN_COOKIE_SAME_SITE`

Not everything security-related is `.env` controlled (for example: the CSRF bypass rules, which endpoints are `permitAll`, and the fixed CORS method/header allowlist are defined in code in `SecurityConfig`).

## Contributing

1. Fork and clone the repository.
2. Create a feature branch.
3. Run and test locally.
4. Open a PR with a clear description of changes.
