Base URL locally:

```text
http://localhost:8080
```

## Health

`GET /api/health`

```bash
curl http://localhost:8080/api/health
```

## Signup

`POST /api/auth/signup`

```json
{
  "email": "user@example.com",
  "password": "password123",
  "role": "CUSTOMER"
}
```

Returns an access-token response and sets a refresh cookie.

## Login

`POST /api/auth/login`

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

Returns:

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 600
}
```

## Current User

`GET /api/auth/me`

Requires:

```text
Authorization: Bearer <access-token>
```

Returns the authenticated user's `id`, `email`, `username`, and `role`.

## Refresh

`POST /api/auth/refresh`

Requires:

- `refresh_token` cookie
- `X-XSRF-TOKEN` header matching the `XSRF-TOKEN` cookie

Returns a new access token. The refresh token is not rotated.

## Logout

`POST /api/auth/logout`

Requires the CSRF header. Clears the refresh cookie.

## JWKS

`GET /.well-known/jwks.json`

Resource servers use this endpoint to validate tokens issued by this service.

