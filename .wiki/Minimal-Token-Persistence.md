Can authentication stay secure with minimal token-related persistence? This service answers yes, with a few explicit trade-offs.

## Access Token in the Response, Refresh Token in an HttpOnly Cookie

Access tokens are returned in the response body and used with the standard `Authorization: Bearer <token>` flow for downstream APIs. Refresh tokens are stored in an HttpOnly cookie.

If browser-side JavaScript is compromised, an attacker may steal the short-lived access token and call APIs until it expires, but they cannot read the long-lived refresh token from the HttpOnly cookie. This limits the compromise window while keeping API authorization explicit.

## CSRF Protection Without Stored CSRF Tokens

Spring issues an `XSRF-TOKEN` cookie, and the frontend sends the same value back in the `X-XSRF-TOKEN` header.

An attacker on another site can cause the browser to send cookies, but they cannot read the `XSRF-TOKEN` cookie value and mirror it into the required header because same-origin rules block that read. The server checks the cookie/header pair without sessions, database storage, or a separate persistence layer for CSRF tokens.

## Multi-Device Login Without Device Tracking

Each browser keeps its own refresh cookie, so users can stay logged in on multiple devices.

If one device is compromised, an attacker may use that device's refresh cookie through the browser, but they cannot enumerate or steal refresh cookies from the user's other devices through this service. The server does not maintain a session table or device list, so authentication remains stateless from a token-management perspective.

## No Refresh-Token Rotation

Refresh-token rotation needs token-family storage, replay detection, and extra server-side state.

This service skips rotation because the refresh token is protected by an HttpOnly, `SameSite=Strict` cookie: injected JavaScript cannot read it, and cross-site requests cannot normally send it. If the cookie itself is stolen outside the browser boundary, rotation would help detect replay; that is the point where token persistence becomes worth adding.

## Logout Clears Only the Refresh Cookie

Logout removes the refresh token from the browser, but it does not revoke already-issued access tokens.

After logout, an attacker with only the old browser session cannot refresh again because the refresh cookie is gone. If they already stole an access token, they can use it only until it expires. This avoids token blacklists and per-request revocation checks.

## When to Add Persistence

Add token/session persistence only when the product needs immediate access-token revocation, refresh-token replay detection, account-wide forced logout, or per-device session management.
