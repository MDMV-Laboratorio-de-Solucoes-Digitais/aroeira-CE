//! `OAuth2` Domain Types
//!
//! This module contains `OAuth2` authentication types for PKCE flow.
//! Implements the types required by the test suite defined in `tests.rs`.
//!
//! # Security Notes
//!
//! - Desktop apps are "public clients" - no client secrets embedded
//! - PKCE (RFC 7636) is mandatory for all OAuth flows
//! - State parameter provides CSRF protection
//! - Sessions expire after 10 minutes to limit attack window

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// ===========================================
// AuthProvider
// ===========================================

/// Supported `OAuth2` providers.
///
/// Each provider has different OAuth endpoints and user info schemas.
/// Serializes to lowercase for consistent JSON representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthProvider {
    /// Google `OAuth2` (`OpenID` Connect)
    Google,
    /// GitHub `OAuth2`
    GitHub,
}

impl fmt::Display for AuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Google => write!(f, "Google"),
            Self::GitHub => write!(f, "GitHub"),
        }
    }
}

// ===========================================
// OAuthError
// ===========================================

/// Error types for `OAuth2` authentication flow.
///
/// These errors are designed to be informative for debugging while
/// avoiding leaking sensitive information in production error messages.
#[derive(Error, Debug)]
pub enum OAuthError {
    /// Session not found in storage or has expired
    #[error("Session not found or expired")]
    SessionNotFound,

    /// State parameter mismatch - potential CSRF attack
    #[error("State mismatch: potential CSRF attack")]
    StateMismatch,

    /// Authorization code exchange failed
    #[error("Code exchange failed: {0}")]
    CodeExchangeFailed(String),

    /// Provider not configured (missing client ID)
    #[error("Provider configuration missing: {0}")]
    ProviderNotConfigured(String),

    /// Token request to provider failed
    #[error("Token request failed: {0}")]
    TokenRequestFailed(String),

    /// User info request to provider failed
    #[error("User info request failed: {0}")]
    UserInfoFailed(String),

    /// Provider user ID validation failed (invalid length or format)
    #[error("Provider user ID validation failed: {0}")]
    InvalidProviderUserId(String),
}

// ===========================================
// OAuthPkceSession
// ===========================================

/// PKCE session stored during OAuth authorization flow.
///
/// This struct holds the state needed between:
/// 1. Generating the authorization URL
/// 2. Receiving the callback with authorization code
///
/// # Security Properties
///
/// - `state`: Random value for CSRF protection (must match callback)
/// - `pkce_verifier`: Secret used to prove we initiated the request (RFC 7636)
/// - `created_at`: Used to enforce session TTL (10 minutes max)
///
/// # PKCE Requirements (RFC 7636)
///
/// - `code_verifier` must be 43-128 characters
/// - Must use only unreserved URI characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthPkceSession {
    /// Random state value for CSRF protection
    pub state: String,
    /// PKCE code verifier (43-128 chars, RFC 7636)
    pub pkce_verifier: String,
    /// The OAuth provider for this session
    pub provider: AuthProvider,
    /// When this session was created (for TTL enforcement)
    pub created_at: DateTime<Utc>,
}

impl OAuthPkceSession {
    /// Session TTL in minutes
    const SESSION_TTL_MINUTES: i64 = 10;
    /// Minimum PKCE verifier length (RFC 7636)
    const PKCE_VERIFIER_MIN_LEN: usize = 43;
    /// Maximum PKCE verifier length (RFC 7636)
    const PKCE_VERIFIER_MAX_LEN: usize = 128;

    /// Creates a new PKCE session with current timestamp.
    ///
    /// # Arguments
    ///
    /// * `state` - Random CSRF protection token
    /// * `pkce_verifier` - PKCE code verifier (should be 43-128 chars)
    /// * `provider` - The OAuth provider for this flow
    #[must_use]
    pub fn new(state: String, pkce_verifier: String, provider: AuthProvider) -> Self {
        Self {
            state,
            pkce_verifier,
            provider,
            created_at: Utc::now(),
        }
    }

    /// Validates session according to PKCE requirements.
    ///
    /// A session is valid if:
    /// - State is not empty (CSRF protection)
    /// - PKCE verifier is 43-128 characters (RFC 7636)
    /// - PKCE verifier uses only unreserved URI characters (RFC 7636)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        // Expired sessions must never be considered valid
        if self.is_expired() {
            return false;
        }

        // State must not be empty (CSRF protection)
        if self.state.is_empty() {
            return false;
        }

        // PKCE code_verifier must be 43-128 characters (RFC 7636)
        let verifier_len = self.pkce_verifier.len();
        if !(Self::PKCE_VERIFIER_MIN_LEN..=Self::PKCE_VERIFIER_MAX_LEN).contains(&verifier_len) {
            return false;
        }

        // PKCE code_verifier must use only unreserved URI characters (RFC 7636 Section 4.1)
        // Allowed: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        if !self.pkce_verifier.chars().all(Self::is_pkce_valid_char) {
            return false;
        }

        true
    }

    /// Checks if a character is valid for PKCE `code_verifier` (RFC 7636 Section 4.1).
    ///
    /// Unreserved URI characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
    #[inline]
    fn is_pkce_valid_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')
    }

    /// Checks if session has expired.
    ///
    /// Sessions expire after 10 minutes to limit the attack window
    /// if a state token is somehow leaked.
    ///
    /// Also rejects sessions with future timestamps to prevent
    /// artificial lifetime extension attacks.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = Utc::now();

        // Defensive: future timestamps should never extend session lifetime.
        if self.created_at > now {
            return true;
        }

        let age = now.signed_duration_since(self.created_at);
        age > Duration::minutes(Self::SESSION_TTL_MINUTES)
    }
}

// ===========================================
// OAuthUser
// ===========================================

/// User information retrieved from OAuth provider.
///
/// This struct normalizes user data across different providers
/// (Google and GitHub have different response schemas).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthUser {
    /// The OAuth provider this user authenticated with
    pub provider: AuthProvider,
    /// Provider-specific user ID (e.g., Google sub, GitHub id)
    pub provider_user_id: String,
    /// User's email address
    pub email: String,
    /// User's display name (optional, some providers may not provide)
    pub name: Option<String>,
    /// URL to user's avatar/profile picture (optional)
    pub avatar_url: Option<String>,
    /// Whether the email has been verified by the provider
    pub email_verified: bool,
}

// ===========================================
// OAuthService (Port/Interface)
// ===========================================

/// Port for `OAuth2` authentication service.
///
/// This trait defines the interface for OAuth operations.
/// Infrastructure layer will provide the concrete implementation.
///
/// # Design Notes
///
/// - Uses PKCE flow (no client secret required)
/// - Session management is caller's responsibility
/// - Returns normalized `OAuthUser` regardless of provider
#[allow(async_fn_in_trait)]
pub trait OAuthService: Send + Sync {
    /// Generates authorization URL and PKCE session.
    ///
    /// The caller must store the returned session and use it
    /// when handling the callback to verify the state and
    /// exchange the code.
    ///
    /// # Arguments
    ///
    /// * `provider` - Which OAuth provider to authenticate with
    ///
    /// # Returns
    ///
    /// * `Ok((url, session))` - Authorization URL to open in browser, and session to store
    /// * `Err(OAuthError)` - If provider is not configured
    async fn generate_authorization_url(
        &self,
        provider: AuthProvider,
    ) -> Result<(String, OAuthPkceSession), OAuthError>;

    /// Exchanges authorization code for user info.
    ///
    /// # Arguments
    ///
    /// * `session` - The PKCE session from `generate_authorization_url`
    /// * `code` - The authorization code from the callback
    ///
    /// # Returns
    ///
    /// * `Ok(OAuthUser)` - Authenticated user information
    /// * `Err(OAuthError)` - If exchange fails or session invalid
    async fn exchange_code(
        &self,
        session: &OAuthPkceSession,
        code: String,
    ) -> Result<OAuthUser, OAuthError>;
}

#[cfg(test)]
mod tests;
