# 🔐 OAuth2 Setup Guide

**Note:** This feature is currently in the **roadmap** phase. This guide serves as the implementation plan for the `libs/infra` and `libs/domain` layers.

## Architecture

OAuth2 will be implemented as part of the **Infrastructure Layer** (`libs/infra`), exposing a clean interface to the **Domain Layer** (`libs/domain`).

### 1. Domain Layer (`libs/domain`)

We define the interface (Port) that the application uses, agnostic of the specific provider libraries.

```rust
// libs/domain/src/modules/auth/ports.rs

#[async_trait]
pub trait OAuthService: Send + Sync {
    async fn get_authorization_url(&self, provider: OAuthProvider) -> String;
    async fn exchange_code(&self, provider: OAuthProvider, code: String) -> Result<AuthUser, AuthError>;
}

pub enum OAuthProvider {
    Google,
    GitHub,
}
```

### 2. Infrastructure Layer (`libs/infra`)

We implement the `OAuthService` using standard Rust crates like `oauth2`.

**Dependencies (to be added):**

```toml
# libs/infra/Cargo.toml
[dependencies]
oauth2 = "4.4"
reqwest = { version = "0.11", features = ["json"] }
```

**Implementation Strategy:**

- **Google**: OIDC flow.
- **GitHub**: Authorization Code flow.
- **Storage**: Tokens should be stored securely (system keychain via Tauri plugin or encrypted in DB).

### 3. Tauri Integration (`apps/desktop`)

Since this is a Multiplatform App, the OAuth flow requires handling redirects.

**Strategy: Deep Linking**

1.  App opens system browser for Auth URL.
2.  Provider redirects to `aroeira://auth/callback`.
3.  Tauri app catches the deep link protocol.
4.  Frontend sends the `code` to the Rust Backend.
5.  Rust Backend exchanges code for Session/Token.

## Configuration

Environment variables (for development):

```bash
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
```

_In production, these secrets must be embedded securely or handled via a proxy server to avoid leaking client secrets in the desktop binary._
