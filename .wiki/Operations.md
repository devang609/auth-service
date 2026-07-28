# Operations

## Build

```bash
./mvnw clean package
```

## Test

```bash
./mvnw test
```

## Run Jar

```bash
java -jar target/server-*.jar --spring.profiles.active=prod
```

## Run Container

```bash
docker run --rm -p 8080:8080 --env-file .env auth-service:latest
```

## Production Checklist

- Apply `migrations/001_create_users.sql`
- Set `SPRING_PROFILES_ACTIVE=prod`
- Use HTTPS
- Use protected RSA key sources
- Set strict `CORS_ALLOWED_ORIGINS`
- Keep refresh cookie `Secure=true`
- Keep access-token expiry short
- Disable Swagger/OpenAPI unless explicitly needed

## Common Failures

- Missing or invalid JWT keys: app fails during token/JWKS setup
- Missing `JWT_AUDIENCE`: token generation fails
- Schema missing in prod: Hibernate validation fails
- Missing CSRF header on refresh/logout: request is rejected
- Wrong CORS origin: browser blocks cookie-based refresh/logout

