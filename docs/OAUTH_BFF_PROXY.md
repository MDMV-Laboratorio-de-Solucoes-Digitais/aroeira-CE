# OAuth BFF Proxy Pattern

## Security Compliance Issue

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

### Current Implementation

GitHub token exchange **must be performed via the BFF proxy** so the desktop binary never embeds or uses `client_secret`.

- Desktop app uses `GITHUB_BFF_PROXY_URL` to call the proxy for code→token exchange
- If `GITHUB_BFF_PROXY_URL` is not configured, **GitHub OAuth is disabled**

**The desktop app must not read/use `GITHUB_CLIENT_SECRET` in production or development.**

### The BFF Proxy Solution

A proper solution uses a **Backend for Frontend (BFF) proxy** pattern:

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Desktop   │ ──────► │ BFF Proxy   │ ──────► │   GitHub    │
│    App      │  code   │  (server)   │  +secret│    OAuth    │
└─────────────┘         └─────────────┘         └─────────────┘
       ▲                       │
       │                       ▼
       │                ┌─────────────┐
       │                │   GitHub    │
       └─────────────── │   Tokens    │
                        └─────────────┘
```

#### Implementation Steps

1. **Create a lightweight proxy service** (e.g., in `apps/proxy/`):

```rust
// apps/proxy/src/main.rs
use axum::{
    extract::Json,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct TokenExchangeRequest {
    code: String,
    state: String,
    redirect_uri: String,
    // PKCE verifier
    code_verifier: String,
}

#[derive(Serialize)]
struct TokenExchangeResponse {
    access_token: String,
    refresh_token: Option<String>,
    // ... other fields
}

async fn exchange_github_token(
    Json(req): Json<TokenExchangeRequest>,
) -> Result<Json<TokenExchangeResponse>, StatusCode> {
    // Validate state, CSRF, etc.
    // Use embedded client_secret here (safe on server)
    // Exchange with GitHub
    // Return tokens
}
```

2. **Update desktop app to use proxy**:

```rust
// In libs/infra/src/services/oauth/mod.rs

async fn exchange_code_github(
    &self,
    code: String,
    session: &OAuthPkceSession,
) -> Result<OAuthUser, OAuthError> {
    // Instead of direct GitHub exchange, call BFF proxy
    let proxy_url = self.config.github_bff_proxy_url
        .as_ref()
        .ok_or_else(|| OAuthError::ProviderNotConfigured(
            "GitHub BFF proxy URL not configured".to_string()
        ))?;

    let response = self.http_client
        .post(proxy_url)
        .json(&json!({
            "code": code,
            "state": session.state,
            "redirect_uri": self.config.redirect_uri,
            "code_verifier": session.pkce_verifier.secret(),
        }))
        .send()
        .await
        .map_err(|e| OAuthError::TokenRequestFailed(e.to_string()))?;

    // Parse response...
}
```

3. **Configuration changes**:

```rust
// In OAuthConfig
pub struct OAuthConfig {
    // ... existing fields
    /// BFF proxy URL for GitHub OAuth (required to avoid embedding client secret)
    pub github_bff_proxy_url: Option<String>,
}
```

4. **Environment variables**:

```bash
# .env
# Instead of GITHUB_CLIENT_SECRET, use proxy URL
GITHUB_BFF_PROXY_URL=https://auth.yourapp.com/github/exchange
```

### Security Considerations for the Proxy

The BFF proxy itself must be secured:

1. **Rate limiting** - Prevent abuse of the token exchange endpoint
2. **State validation** - Verify the state parameter matches the session
3. **CORS configuration** - Only allow requests from your desktop app
4. **Audit logging** - Log all token exchanges for security review
5. **Short-lived sessions** - Implement expiration for pending exchanges

### Alternative: Remove GitHub OAuth

If the BFF proxy adds too much complexity, consider:

- **Remove GitHub OAuth** and use only Google (PKCE-only)
- **Document the limitation** in your app's authentication docs
- **Guide users** to create accounts via email/password or Google

### Migration Path

To migrate from embedded secret to BFF proxy:

1. Set up the BFF proxy service
2. Deploy it to a secure environment
3. Update desktop app to use `GITHUB_BFF_PROXY_URL` instead of `GITHUB_CLIENT_SECRET`
4. Rotate the client secret in GitHub settings
5. Remove `GITHUB_CLIENT_SECRET` from build environment
6. Update documentation

## References

- [OAuth2 for Native Apps (RFC 8252)](https://tools.ietf.org/html/rfc8252)
- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps)
- [Backend for Frontend Pattern](https://samnewman.io/patterns/architectural/bff/)
