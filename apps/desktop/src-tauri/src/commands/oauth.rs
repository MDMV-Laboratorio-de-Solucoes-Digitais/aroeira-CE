//! OAuth2 Tauri Commands - TDD RED PHASE
//!
//! This module provides Tauri commands for OAuth2 authentication.
//! Currently contains only test definitions - implementation follows in GREEN phase.

use domain::modules::auth::oauth::OAuthPkceSession;
use std::collections::HashMap;
use std::sync::Mutex;
use url::Url;

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
    pub fn store(&self, session: OAuthPkceSession) {
        let mut sessions = self.sessions.lock().expect("Session store lock poisoned");

        // Clean up expired sessions
        sessions.retain(|_, s| !s.is_expired());

        // Store new session
        sessions.insert(session.state.clone(), session);
    }

    /// Takes a session by its state value, removing it from storage.
    ///
    /// Returns `None` if:
    /// - Session doesn't exist
    /// - Session has expired
    #[must_use]
    pub fn take(&self, state: &str) -> Option<OAuthPkceSession> {
        let mut sessions = self.sessions.lock().expect("Session store lock poisoned");

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
/// - Code or state parameters are missing
/// - Error parameter is present (OAuth error response)
pub fn parse_oauth_callback_url(callback_url: &str) -> Result<(String, String), String> {
    let url = Url::parse(callback_url).map_err(|e| format!("Invalid callback URL: {e}"))?;

    // Check for error response
    if let Some(error) = url.query_pairs().find(|(k, _)| k == "error") {
        let error_desc = url
            .query_pairs()
            .find(|(k, _)| k == "error_description")
            .map(|(_, v)| v.to_string())
            .unwrap_or_else(|| "Unknown error".to_string());

        return Err(format!("OAuth error: {} - {}", error.1, error_desc));
    }

    // Extract code and state
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .ok_or("Missing 'code' parameter in callback URL")?;

    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .ok_or("Missing 'state' parameter in callback URL")?;

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
        assert!(err.contains("access_denied") || err.contains("denied"));
    }
}
