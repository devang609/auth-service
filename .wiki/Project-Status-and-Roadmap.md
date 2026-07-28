## Current Status

The service is functional as a stateless JWT auth server.

Implemented:

- Signup and login with BCrypt password hashing
- Minimal token-related persistence by design
- Role allowlist validation
- JWT access and refresh tokens signed with RSA
- Refresh token stored in an HttpOnly cookie
- CSRF protection for refresh and logout
- Public JWKS endpoint for resource servers
- `/api/auth/me` for the current authenticated user
- PostgreSQL schema migration for `users`
- Dev and prod Spring profiles
- Docker multi-stage build with distroless runtime
- Unit coverage for JWT key loading

## Roadmap

Near-term:

- Add controller/service tests for signup, login, refresh, logout, and `/me`
- Add CI for `mvn test` and Docker build
- Add release packaging instructions for the jar and container image
- Document frontend integration examples

Later, only if needed:

- Refresh-token rotation
- Server-side session table
- Account-wide forced logout
- Per-device session list
- Email verification and password reset
- Rate limiting for auth endpoints

Skipped: token/session persistence. Add it when immediate revocation, device management, or refresh replay detection becomes a real requirement.
