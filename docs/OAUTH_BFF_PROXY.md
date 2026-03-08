# OAuth BFF Proxy Pattern

## Implementation Overview

This document describes the OAuth Backend-for-Frontend (BFF) proxy pattern used for GitHub OAuth, which requires a client secret for token exchange.

**Current OAuth2 Dependency**: `oauth2 = "5.0"` (latest stable)

## Security Compliance

GitHub OAuth requires a **client secret** for the token exchange, which violates the security constraint:

> "Do not embed/commit CLIENT_SECRET into the desktop binary; use PKCE (and use BFF if a provider requires a secret)."

## ⚠️ CRITICAL: Production Requirement

**GitHub OAuth in production REQUIRES the BFF proxy.** The desktop binary must never contain or use `GITHUB_CLIENT_SECRET` in production builds.

| Environment     | Configuration                        | Status                       |
| --------------- | ------------------------------------ | ---------------------------- |
| **Development** | `GITHUB_CLIENT_SECRET` + default URL | ✅ Allowed (not distributed) |
| **Production**  | `GITHUB_TOKEN_URL` → BFF proxy       | ✅ **REQUIRED**              |
| **Production**  | `GITHUB_CLIENT_SECRET` embedded      | ❌ **FORBIDDEN**             |

### Why This Matters

GitHub's OAuth implementation does NOT support PKCE-only token exchange. Unlike Google (which allows PKCE-only flows), GitHub requires a `client_secret` for the authorization code exchange. This creates a security dilemma for desktop applications:

1. **Embedding the secret** in the binary exposes it to extraction
2. **Not using GitHub OAuth** limits provider options
3. **Using a BFF proxy** adds infrastructure complexity but maintains security

## Environment Variables

### Desktop App Configuration

```bash
# Required for GitHub OAuth
GITHUB_CLIENT_ID=your_github_client_id

# Production: Proxy URL for token exchange
GITHUB_TOKEN_URL=https://auth.yourapp.com/oauth/github/token

# Alternative: Derive from base proxy URL
AUTH_PROXY_URL=https://auth.yourapp.com

# Development only (FORBIDDEN in production)
GITHUB_CLIENT_SECRET=your_github_client_secret
```

### Proxy Service Configuration

```bash
# Proxy server configuration
SERVER_BIND_ADDRESS=0.0.0.0:3000
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GITHUB_REDIRECT_URI=aroeira://auth/callback
GITHUB_ALLOWED_HOSTS=github.com,api.github.com

# Rate limiting (per-IP)
RATE_LIMIT_REQUESTS=5
RATE_LIMIT_WINDOW_SECS=60

# CORS allowed origins
ALLOWED_ORIGINS=http://localhost:1420,https://*.aroeira.app
```

## GitHub Scopes

GitHub does not support OIDC (`OpenID` Connect), so we request scopes that provide equivalent functionality:

| Scope        | Purpose                                    | OIDC Equivalent |
| ------------ | ------------------------------------------ | --------------- |
| `read:user`  | Read access to user profile (name, avatar) | `profile`       |
| `user:email` | Read access to user email addresses        | `email`         |

These scopes are minimal and necessary for user identification. See [GitHub OAuth Scopes Documentation](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps).

## Protocol Details

### Token Exchange Request Format

When using proxy mode (non-default `GITHUB_TOKEN_URL`), the desktop app sends a **JSON** request:

```json
POST /oauth/github/token
Content-Type: application/json
X-Client-Id: your_github_client_id

{
  "code": "authorization_code",
  "state": "session_state",
  "redirect_uri": "aroeira://auth/callback",
  "code_verifier": "pkce_verifier_43_to_128_chars"
}
```

### Direct Mode (Development Only)

When using default GitHub URL with `GITHUB_CLIENT_SECRET`, standard OAuth2 form-encoded requests are used.

## Security Features

### Per-IP Rate Limiting

The proxy implements **per-IP rate limiting** using `tower_governor`:

- Prevents DoS attacks from single malicious IPs
- Each IP has independent quota
- Configurable via `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW_SECS`

### Redirect URI Validation

The proxy validates:

- Scheme is allowlisted (`aroeira`, `com.aroeira.app`)
- No userinfo, query, or fragment components
- Matches configured `GITHUB_REDIRECT_URI`

### State Parameter

- SHA256-hashed for session storage
- 64-character lowercase hex format
- Validated on callback to prevent CSRF

## Architecture

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Desktop   │ ──────► │ BFF Proxy   │ ──────► │   GitHub    │
│    App      │  JSON   │  (server)   │  +secret│    OAuth    │
└─────────────┘         └─────────────┘         └─────────────┘
       ▲                       │
       │                       ▼
       │                ┌─────────────┐
       │                │   GitHub    │
       └─────────────── │   Tokens    │
                        └─────────────┘
```

## Proxy Implementation

The proxy is located at `apps/proxy/` and provides:

- `POST /oauth/github/token` - Token exchange endpoint
- `GET /health` - Health check endpoint

Key security features:

- Per-IP rate limiting
- CORS validation
- Request body size limits (16KB max)
- Input validation via `validator` crate

## References

- [OAuth2 for Native Apps (RFC 8252)](https://tools.ietf.org/html/rfc8252)
- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps)
- [GitHub OAuth Scopes](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps)
- [Backend for Frontend Pattern](https://samnewman.io/patterns/architectural/bff/)
