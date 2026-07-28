# Local Setup

## Requirements

- JDK 17+
- Maven or the Maven Wrapper
- PostgreSQL

## Database

Apply the schema:

```bash
psql "$DATABASE_URL" -f migrations/001_create_users.sql
```

The dev profile uses Hibernate `ddl-auto=update`. Production uses `ddl-auto=validate`, so the schema must already exist.

## Environment

Create a `.env` file with the required values. The important settings are:

- `SPRING_PROFILES_ACTIVE`
- `SUPABASE_DB_URL`
- `SUPABASE_DB_USERNAME`
- `SUPABASE_DB_PASSWORD`
- `SERVER_PORT`
- `JWT_PRIVATE_KEY_PATH`
- `JWT_PUBLIC_KEY_PATH`
- `JWT_AUDIENCE`
- `AUTH_ALLOWED_ROLES`
- `CORS_ALLOWED_ORIGINS`
- refresh-token cookie settings

## Run

Windows PowerShell:

```powershell
.\mvnw spring-boot:run
```

Unix shell:

```bash
./mvnw spring-boot:run
```

Health check:

```bash
curl http://localhost:8080/api/health
```

## Docker

Build:

```bash
docker build -t auth-service:latest .
```

Run:

```bash
docker run --rm -p 8080:8080 --env-file .env auth-service:latest
```

