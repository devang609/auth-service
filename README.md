# Auth Service

Simple Spring Boot authentication service with JWT access tokens, refresh-token cookies, and a JWKS endpoint.

## Features

- Email/password signup and login
- JWT access token issuance
- HttpOnly refresh-token cookie flow
- Token refresh and logout endpoints
- Public JWKS endpoint for downstream services
- OpenAPI + Swagger UI (enabled in dev, disabled by default in prod)

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
docker run --rm -p 8080:8080 --env-file .env ghcr.io/devang609/auth-service:latest
```

## API Documentation

When enabled (dev profile), OpenAPI docs are available at:

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

## Contributing

1. Fork and clone the repository.
2. Create a feature branch.
3. Run and test locally.
4. Open a PR with a clear description of changes.
