//! OAuth2 Tauri Commands - TDD GREEN PHASE
//!
//! This module provides Tauri commands for OAuth2 authentication
//! with PKCE flow for Google and GitHub providers.
//!
//! # Security Notes
//!
//! - Uses PKCE (RFC 7636) for all flows - no client secrets
//! - State parameter provides CSRF protection
//! - Sessions expire after 10 minutes
//! - Tokens stored in OS secure storage (not in this module)

use domain::modules::auth::oauth::{AuthProvider, OAuthPkceSession, OAuthService, OAuthUser};
use infra::services::oauth::{OAuthConfig, OAuthServiceImpl};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::State;
use url::Url;

/// OAuth state managed by Tauri.
///
/// This struct is registered as Tauri managed state to persist
/// OAuth sessions across command invocations.
pub struct OAuthState {
    /// Session store for pending OAuth flows
    pub session_store: OAuthSessionStore,
    /// OAuth service implementation
    pub oauth_service: Arc<OAuthServiceImpl>,
}

impl OAuthState {
    /// Creates new OAuth state with given configuration.
    #[must_use]
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            session_store: OAuthSessionStore::new(),
            oauth_service: Arc::new(OAuthServiceImpl::new(config)),
        }
    }
}

/// Response from `start_oauth_flow` command.
#[derive(Debug, Serialize, Deserialize)]
pub struct StartOAuthResponse {
    /// Authorization URL to open in browser
    pub auth_url: String,
    /// State parameter for CSRF verification
    pub state: String,
}

/// Response from `handle_oauth_callback` command.
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthCallbackResponse {
    /// Provider that authenticated the user
    pub provider: String,
    /// User's email from the provider
    pub email: String,
    /// User's display name (optional)
    pub name: Option<String>,
    /// User's avatar URL (optional)
    pub avatar_url: Option<String>,
}

impl From<OAuthUser> for OAuthCallbackResponse {
    fn from(user: OAuthUser) -> Self {
        Self {
            provider: user.provider.to_string().to_lowercase(),
            email: user.email,
            name: user.name,
            avatar_url: user.avatar_url,
        }
    }
}

/// Starts an OAuth authentication flow for the given provider.
///
/// This command:
/// 1. Generates a PKCE challenge and authorization URL
/// 2. Stores the PKCE session for later verification
/// 3. Returns the URL to open in the system browser
///
/// # Arguments
///
/// * `provider` - Either "google" or "github"
///
/// # Returns
///
/// * `Ok(StartOAuthResponse)` - Authorization URL and state parameter
/// * `Err(String)` - If provider is invalid or not configured
#[tauri::command]
pub async fn start_oauth_flow(
    provider: String,
    oauth_state: State<'_, OAuthState>,
) -> Result<StartOAuthResponse, String> {
    // Parse provider
    let auth_provider = match provider.to_lowercase().as_str() {
        "google" => AuthProvider::Google,
        "github" => AuthProvider::GitHub,
        _ => {
            return Err("Invalid provider. Use 'google' or 'github'.".to_string());
        }
    };

    // Generate authorization URL
    let (auth_url, session) = oauth_state
        .oauth_service
        .generate_authorization_url(auth_provider)
        .await
        .map_err(|e| {
            tracing::error!("OAuth URL generation failed: {e}");
            "Failed to start authentication. Please try again.".to_string()
        })?;

    let state = session.state.clone();

    // Store session for callback verification
    if !oauth_state.session_store.store(session) {
        tracing::error!("Failed to store OAuth session");
        return Err("Failed to start authentication. Please try again.".to_string());
    }

    Ok(StartOAuthResponse { auth_url, state })
}

/// Handles an OAuth callback URL from deep linking.
///
/// This command:
/// 1. Parses the callback URL to extract code and state
/// 2. Verifies the state matches a pending session (CSRF protection)
/// 3. Exchanges the code for tokens and user info
/// 4. Returns the authenticated user information
///
/// # Arguments
///
/// * `callback_url` - The full callback URL (e.g., "aroeira://auth/callback?code=...&state=...")
///
/// # Returns
///
/// * `Ok(OAuthCallbackResponse)` - Authenticated user information
/// * `Err(String)` - If callback parsing fails, state mismatch, or exchange fails
#[tauri::command]
pub async fn handle_oauth_callback(
    callback_url: String,
    oauth_state: State<'_, OAuthState>,
) -> Result<OAuthCallbackResponse, String> {
    // Parse callback URL
    let (code, state) = parse_oauth_callback_url(&callback_url)?;

    // Retrieve and consume session (CSRF protection)
    let session = oauth_state
        .session_store
        .take(&state)
        .ok_or("Invalid or expired OAuth session. Please try again.")?;

    // Exchange code for user info
    let user = oauth_state
        .oauth_service
        .exchange_code(&session, code)
        .await
        .map_err(|e| {
            tracing::error!("OAuth code exchange failed: {e}");
            "Authentication failed. Please try again.".to_string()
        })?;

    // Log successful OAuth login (audit trail)
    tracing::info!(
        provider = %session.provider,
        "OAuth authentication successful"
    );

    Ok(OAuthCallbackResponse::from(user))
}

/// Thread-safe storage for OAuth PKCE sessions.
///
/// Sessions are stored temporarily between:
/// 1. Generating the authorization URL
/// 2. Receiving the callback with authorization code
///
/// Sessions are automatically cleaned up when expired.
pub struct OAuthSessionStore {
    sessions: Mutex<HashMap<String, OAuthPkceSession>>,
}

impl OAuthSessionStore {
    /// Creates a new empty session store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Stores a session, keyed by its state value.
    ///
    /// Automatically cleans up expired sessions during this operation.
    /// Returns `true` if stored successfully, `false` if the lock was poisoned.
    pub fn store(&self, session: OAuthPkceSession) -> bool {
        let Ok(mut sessions) = self.sessions.lock() else {
            // Lock poisoned - log and return false instead of panicking
            tracing::error!("OAuth session store lock poisoned during store operation");
            return false;
        };

        // Clean up expired sessions
        sessions.retain(|_, s| !s.is_expired());

        // Store new session
        sessions.insert(session.state.clone(), session);
        true
    }

    /// Takes a session by its state value, removing it from storage.
    ///
    /// Returns `None` if:
    /// - Session doesn't exist
    /// - Session has expired
    /// - Lock is poisoned
    #[must_use]
    pub fn take(&self, state: &str) -> Option<OAuthPkceSession> {
        let Ok(mut sessions) = self.sessions.lock() else {
            // Lock poisoned - log and return None instead of panicking
            tracing::error!("OAuth session store lock poisoned during take operation");
            return None;
        };

        // Remove and return, checking expiration
        sessions.remove(state).filter(|s| !s.is_expired())
    }
}

impl Default for OAuthSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses an OAuth callback URL to extract code and state.
///
/// # Arguments
///
/// * `callback_url` - The full callback URL (e.g., "aroeira://auth/callback?code=...&state=...")
///
/// # Returns
///
/// * `Ok((code, state))` - The authorization code and state parameter
/// * `Err(String)` - Description of what went wrong
///
/// # Errors
///
/// Returns error if:
/// - URL cannot be parsed
/// - URL scheme is not "aroeira"
/// - URL host is not "auth" or path is not "/callback"
/// - Code or state parameters are missing
/// - Error parameter is present (OAuth error response)
pub fn parse_oauth_callback_url(callback_url: &str) -> Result<(String, String), String> {
    let url = Url::parse(callback_url).map_err(|_| "Invalid callback URL format")?;

    // Enforce expected deep-link callback origin
    if url.scheme() != "aroeira" {
        return Err("Invalid callback URL scheme".to_string());
    }
    if url.host_str() != Some("auth") || url.path() != "/callback" {
        return Err("Invalid callback URL target".to_string());
    }

    // Check for error response (use generic message for user)
    if url.query_pairs().any(|(k, _)| k == "error") {
        return Err("Authentication was denied or failed. Please try again.".to_string());
    }

    // Extract code and state
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .ok_or("Missing authorization code in callback")?;

    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .ok_or("Missing state parameter in callback")?;

    Ok((code, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::modules::auth::oauth::{AuthProvider, OAuthPkceSession};

    // ===========================================
    // OAuthSessionStore Tests
    // ===========================================

    #[test]
    fn session_store_returns_none_for_unknown_state() {
        let store = OAuthSessionStore::new();
        assert!(store.take("unknown-state").is_none());
    }

    #[test]
    fn session_store_returns_session_once_then_removes() {
        let store = OAuthSessionStore::new();
        let session = OAuthPkceSession::new(
            "test-state".to_string(),
            "a".repeat(43),
            AuthProvider::Google,
        );

        store.store(session);

        // First take succeeds
        let retrieved = store.take("test-state");
        assert!(retrieved.is_some());

        // Second take fails (session consumed)
        assert!(store.take("test-state").is_none());
    }

    #[test]
    fn session_store_handles_multiple_sessions() {
        let store = OAuthSessionStore::new();

        let session1 =
            OAuthPkceSession::new("state-1".to_string(), "a".repeat(43), AuthProvider::Google);
        let session2 =
            OAuthPkceSession::new("state-2".to_string(), "b".repeat(43), AuthProvider::GitHub);

        store.store(session1);
        store.store(session2);

        // Can retrieve both independently
        let s1 = store.take("state-1");
        assert!(s1.is_some());
        assert_eq!(s1.unwrap().provider, AuthProvider::Google);

        let s2 = store.take("state-2");
        assert!(s2.is_some());
        assert_eq!(s2.unwrap().provider, AuthProvider::GitHub);

        // Both consumed
        assert!(store.take("state-1").is_none());
        assert!(store.take("state-2").is_none());
    }

    #[test]
    fn session_store_cleans_expired_sessions_on_store() {
        use chrono::{Duration as ChronoDuration, Utc};

        let store = OAuthSessionStore::new();

        // Store an expired session
        let mut old_session = OAuthPkceSession::new(
            "old-state".to_string(),
            "a".repeat(43),
            AuthProvider::Google,
        );
        old_session.created_at = Utc::now() - ChronoDuration::minutes(15);
        store.store(old_session);

        // Store a new session (triggers cleanup)
        let new_session = OAuthPkceSession::new(
            "new-state".to_string(),
            "a".repeat(43),
            AuthProvider::GitHub,
        );
        store.store(new_session);

        // Old session should be gone (expired)
        assert!(store.take("old-state").is_none());
        // New session should exist
        assert!(store.take("new-state").is_some());
    }

    #[test]
    fn session_store_preserves_unexpired_sessions() {
        use chrono::{Duration as ChronoDuration, Utc};

        let store = OAuthSessionStore::new();

        // Store a session that's 5 minutes old (not expired - TTL is 10 min)
        let mut recent_session = OAuthPkceSession::new(
            "recent-state".to_string(),
            "a".repeat(43),
            AuthProvider::Google,
        );
        recent_session.created_at = Utc::now() - ChronoDuration::minutes(5);
        store.store(recent_session);

        // Store another session (triggers cleanup, but shouldn't remove the 5-min-old one)
        let new_session = OAuthPkceSession::new(
            "new-state".to_string(),
            "b".repeat(43),
            AuthProvider::GitHub,
        );
        store.store(new_session);

        // Both sessions should still exist
        assert!(store.take("recent-state").is_some());
        assert!(store.take("new-state").is_some());
    }

    // ===========================================
    // URL Parsing Tests
    // ===========================================

    #[test]
    fn parse_callback_url_extracts_code_and_state() {
        let url = "aroeira://auth/callback?code=abc123&state=xyz789";
        let (code, state) = parse_oauth_callback_url(url).expect("Should parse valid URL");

        assert_eq!(code, "abc123");
        assert_eq!(state, "xyz789");
    }

    #[test]
    fn parse_callback_url_fails_without_code() {
        let url = "aroeira://auth/callback?state=xyz789";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
    }

    #[test]
    fn parse_callback_url_fails_without_state() {
        let url = "aroeira://auth/callback?code=abc123";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
    }

    #[test]
    fn parse_callback_url_fails_on_invalid_url() {
        let url = "not a valid url";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
    }

    #[test]
    fn parse_callback_url_handles_url_encoded_values() {
        let url = "aroeira://auth/callback?code=abc%2B123&state=xyz%3D789";
        let (code, state) = parse_oauth_callback_url(url).expect("Should parse URL-encoded values");

        assert_eq!(code, "abc+123");
        assert_eq!(state, "xyz=789");
    }

    #[test]
    fn parse_callback_url_handles_error_response() {
        let url = "aroeira://auth/callback?error=access_denied&error_description=User%20denied";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
        let err = result.unwrap_err();
        // Error should be generic, not expose provider details
        assert!(err.contains("denied") || err.contains("failed"));
    }

    #[test]
    fn parse_callback_url_rejects_wrong_scheme() {
        let url = "https://auth/callback?code=abc123&state=xyz789";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("scheme"));
    }

    #[test]
    fn parse_callback_url_rejects_wrong_host() {
        let url = "aroeira://malicious/callback?code=abc123&state=xyz789";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("target"));
    }

    #[test]
    fn parse_callback_url_rejects_wrong_path() {
        let url = "aroeira://auth/malicious?code=abc123&state=xyz789";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("target"));
    }
}
