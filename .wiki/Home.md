Auth Service is a Spring Boot authentication server for email/password login with RSA-signed JWT access tokens, refresh tokens in an HttpOnly cookie, and a public JWKS endpoint.

## Quick Links

- [Project Status and Roadmap](Project-Status-and-Roadmap)
- [Architecture](Architecture)
- [Minimal Token Persistence](Minimal-Token-Persistence)
- [Local Setup](Local-Setup)
- [API Guide](API-Guide)
- [Security Model](Security-Model)
- [Configuration](Configuration)
- [Operations](Operations)

## Current Scope

- User signup and login
- Access-token issuance in JSON responses
- Refresh-token cookie flow
- Token refresh and logout
- Authenticated `/api/auth/me`
- Public `/.well-known/jwks.json`
- PostgreSQL-backed user storage
- Docker image build

The service intentionally does not store refresh sessions, token values, device sessions, or token revocation state.
