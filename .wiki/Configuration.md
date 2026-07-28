Configuration is mapped from Spring properties and environment variables.

## Profiles

- `dev`: Hibernate `ddl-auto=update`
- `prod`: Hibernate `ddl-auto=validate`, OpenAPI/Swagger disabled by default

## Database

- `SUPABASE_DB_URL`
- `SUPABASE_DB_USERNAME`
- `SUPABASE_DB_PASSWORD`
- `DB_POOL_MAX`
- `DB_POOL_MIN`
- `DB_POOL_CONN_TIMEOUT_MS`
- `DB_POOL_IDLE_TIMEOUT_MS`
- `DB_POOL_MAX_LIFETIME_MS`

## JWT

- `JWT_PRIVATE_KEY_PATH`
- `JWT_PUBLIC_KEY_PATH`
- `JWT_ISSUER`
- `JWT_AUDIENCE`
- `JWT_ACCESS_TOKEN_EXPIRY_MS`
- `JWT_REFRESH_TOKEN_EXPIRY_MS`

Production expects externally hosted raw PEM key URLs. Development may use HTTP(S), local paths, `file:` URLs, or raw PEM values.

## Auth

- `AUTH_ALLOWED_ROLES`

Signup roles are normalized to uppercase and checked against this allowlist.

## CORS

- `CORS_ALLOWED_ORIGINS`

Allowed methods are `GET`, `POST`, and `OPTIONS`. Allowed headers are `Content-Type`, `Authorization`, and `X-XSRF-TOKEN`.

## Cookies

- `REFRESH_TOKEN_COOKIE_NAME`
- `REFRESH_TOKEN_COOKIE_PATH`
- `REFRESH_TOKEN_COOKIE_MAX_AGE`
- `REFRESH_TOKEN_COOKIE_SECURE`
- `REFRESH_TOKEN_COOKIE_SAME_SITE`

Production should keep `REFRESH_TOKEN_COOKIE_SECURE=true`.

