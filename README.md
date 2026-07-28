<div align="center">

<pre>
    _   _                               _
  __ _ _   _| |_| |__        ___  ___ _ ____   _(_) ___ ___
 / _` | | | | __| '_ \_____ / __|/ _ \ '__\ \ / / |/ __/ _ \
| (_| | |_| | |_| | | |_____\__ \  __/ |   \ V /| | (_|  __/
 \__,_|\__,_|\__|_| |_|     |___/\___|_|    \_/ |_|\___\___|
</pre>

</div>


Ready-to-use Spring Boot authentication service with RSA-signed JWT access/refresh token pairs and a public JWKS endpoint.

## Features

- Email/password signup and login
- JWT access token issuance
- HttpOnly refresh-token cookie flow
- Token refresh and logout endpoints
- Authenticated `/api/auth/me`
- Public `/.well-known/jwks.json` for downstream services
- PostgreSQL-backed user storage
- Docker multi-stage build with distroless runtime

## Tech Stack

- Java 17
- Spring Boot 3
- Spring Security
- Spring Data JPA
- PostgreSQL
- Maven
- Docker

## Quick Start

Apply the database migration:

```bash
psql "$DATABASE_URL" -f migrations/001_create_users.sql
```

Run locally:

```bash
./mvnw spring-boot:run
```

Windows PowerShell:

```powershell
.\mvnw spring-boot:run
```

Health check:

```bash
curl http://localhost:8080/api/health
```

## Docker

```bash
docker build -t auth-service:latest .
docker run --rm -p 8080:8080 --env-file .env auth-service:latest
```

## Documentation

- [Project Status and Roadmap](../../wiki/Project-Status-and-Roadmap)
- [Architecture](../../wiki/Architecture)
- [Minimal Token Persistence](../../wiki/Minimal-Token-Persistence)
- [Local Setup](../../wiki/Local-Setup)
- [API Guide](../../wiki/API-Guide)
- [Security Model](../../wiki/Security-Model)
- [Configuration](../../wiki/Configuration)
- [Operations](../../wiki/Operations)

## Project Structure

- API controllers: [src/main/java/com/authentication/server/controller](src/main/java/com/authentication/server/controller)
- Security configuration: [src/main/java/com/authentication/server/config/SecurityConfig.java](src/main/java/com/authentication/server/config/SecurityConfig.java)
- JWT key loading: [src/main/java/com/authentication/server/security/JwtKeyManager.java](src/main/java/com/authentication/server/security/JwtKeyManager.java)
- Config files: [src/main/resources](src/main/resources)
- Database migration: [migrations/001_create_users.sql](migrations/001_create_users.sql)

## Contributing

1. Fork and clone the repository.
2. Create a feature branch.
3. Run and test locally.
4. Open a PR with a clear description of changes.
