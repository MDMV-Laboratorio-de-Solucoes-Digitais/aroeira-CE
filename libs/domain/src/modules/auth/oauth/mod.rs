//! OAuth2 Domain Types - TDD RED PHASE
//!
//! This module will contain OAuth2 authentication types for PKCE flow.
//! Currently empty - tests are written first per TDD methodology.
//!
//! Expected types (to be implemented in GREEN phase):
//! - `AuthProvider` - Enum for Google/GitHub
//! - `OAuthError` - Error types for OAuth flow
//! - `OAuthPkceSession` - PKCE session state
//! - `OAuthUser` - User info from OAuth provider
//! - `OAuthService` - Port trait for OAuth operations

// Tests are defined but will fail to compile until types are implemented
#[cfg(test)]
mod tests;
