# Security Model

For the design rationale behind this stateless approach, see [Minimal Token Persistence](Minimal-Token-Persistence).

## Token Transport

- Access tokens are returned in the JSON response.
- Clients send access tokens with `Authorization: Bearer <token>`.
- Refresh tokens are stored in an HttpOnly cookie.

## CSRF

CSRF is enabled through Spring's `CookieCsrfTokenRepository`.

- Login and signup do not require CSRF.
- Refresh and logout require `X-XSRF-TOKEN`.
- The frontend reads the `XSRF-TOKEN` cookie and echoes it in the header.

## JWT Validation

Tokens are RSA-signed and validated for:

- signature
- issuer
- audience
- expiry
- refresh token `token_use=refresh` claim when refreshing

## Stateless Trade-offs

This service does not persist tokens or sessions.

That means:

- logout clears the refresh cookie but does not revoke already-issued access tokens
- refresh tokens are not rotated
- account-wide forced logout is not available
- per-device session management is not available

Keep access-token lifetimes short and use HTTPS, strict CORS, protected key storage, and secure cookie settings in production.
