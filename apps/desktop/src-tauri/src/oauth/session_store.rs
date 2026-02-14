use domain::modules::auth::oauth::OAuthPkceSession;
use infra::services::oauth::{KeyringPkceStorage, PkceSessionStorage};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// Thread-safe storage for OAuth PKCE sessions.
///
/// Sessions are stored temporarily between:
/// 1. Generating the authorization URL
/// 2. Receiving the callback with authorization code
///
/// Sessions are automatically cleaned up when expired.
/// Uses `parking_lot::Mutex` for better async performance.
///
/// # Security Note
///
/// When evicting sessions due to capacity limits, also deletes from
/// the persistent keyring storage to prevent stale data accumulation.
#[derive(Clone)]
pub struct OAuthSessionStore {
    sessions: Arc<Mutex<HashMap<String, OAuthPkceSession>>>,
    pkce_storage: Arc<dyn PkceSessionStorage>,
}

impl OAuthSessionStore {
    /// Creates a new empty session store with keyring storage.
    #[must_use]
    pub fn new(pkce_storage: Arc<dyn PkceSessionStorage>) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            pkce_storage,
        }
    }

    /// Takes a session by its state value, validating it before removal.
    ///
    /// Returns `None` if:
    /// - Session doesn't exist
    /// - Session state doesn't match
    /// - Session is invalid or has expired
    #[must_use]
    pub fn take_valid(&self, state: &str, request_id: &str) -> Option<OAuthPkceSession> {
        let (expired_hashes, removed_state_hash_if_invalid, session_to_return) = {
            let mut sessions = self.sessions.lock();

            // Collect expired hashes so we can also delete persisted sessions from keyring.
            let expired_hashes: Vec<String> = sessions
                .iter()
                .filter(|&(_k, s)| s.is_expired())
                .map(|(k, _s)| hex::encode(Sha256::digest(k.as_bytes())))
                .collect();

            sessions.retain(|_, s| !s.is_expired());

            let existing = sessions.get(state);

            let is_valid =
                existing.is_some_and(|s| s.state == state && s.is_valid() && !s.is_expired());

            if is_valid {
                (expired_hashes, None, sessions.remove(state))
            } else if existing.is_some() {
                // Session exists but is invalid/expired: log warning and remove it.
                tracing::warn!(
                    target: "audit",
                    request_id = %request_id,
                    outcome = "failure",
                    reason = "session_invalid_or_expired",
                    "OAuth authentication failed: invalid or expired session"
                );

                sessions.remove(state);
                let removed_state_hash_if_invalid =
                    Some(hex::encode(Sha256::digest(state.as_bytes())));

                (expired_hashes, removed_state_hash_if_invalid, None)
            } else {
                // Missing session: do not emit "invalid" audit warning (prevents noise/log-flooding).
                (expired_hashes, None, None)
            }
        };

        // Cleanup *after* releasing the lock to prevent blocking all OAuth flows.
        Self::perform_keyring_cleanup(
            expired_hashes,
            removed_state_hash_if_invalid,
            &self.pkce_storage,
        );

        session_to_return
    }

    /// Stores a session, keyed by its state value.
    ///
    /// Automatically cleans up expired sessions during this operation.
    /// When evicting due to capacity limits, also deletes from keyring.
    pub fn store(&self, session: OAuthPkceSession) {
        const MAX_SESSIONS: usize = 512;

        let (expired_hashes, evicted_hash, pkce_storage) = {
            let mut sessions = self.sessions.lock();

            let expired_hashes = Self::collect_and_remove_expired(&mut sessions);
            let evicted_hash = Self::evict_if_full(&mut sessions, MAX_SESSIONS);

            // Store new session while still holding the lock to preserve the cap invariant.
            sessions.insert(session.state.clone(), session);

            (expired_hashes, evicted_hash, self.pkce_storage.clone())
        };

        Self::perform_keyring_cleanup(expired_hashes, evicted_hash, &pkce_storage);
    }

    fn collect_and_remove_expired(sessions: &mut HashMap<String, OAuthPkceSession>) -> Vec<String> {
        let expired_hashes: Vec<String> = sessions
            .iter()
            .filter(|&(_k, s)| s.is_expired())
            .map(|(k, _)| hex::encode(Sha256::digest(k.as_bytes())))
            .collect();

        // Clean up expired sessions
        sessions.retain(|_, s| !s.is_expired());
        expired_hashes
    }

    fn evict_if_full(
        sessions: &mut HashMap<String, OAuthPkceSession>,
        max_sessions: usize,
    ) -> Option<String> {
        if sessions.len() < max_sessions {
            return None;
        }

        // Enforce a hard cap to prevent memory growth (DoS prevention)
        // Find oldest first, then remove in separate step to avoid borrow checker issues
        let oldest_key = sessions
            .iter()
            .min_by_key(|(_, s)| s.created_at)
            .map(|(k, _)| k.clone());

        oldest_key.map(|key| {
            let state_hash = hex::encode(Sha256::digest(key.as_bytes()));
            tracing::warn!(
                target: "security",
                reason = "session_store_full",
                evicted_state_hash = %state_hash,
                "OAuth session store reached max capacity ({max_sessions}). Evicting oldest session."
            );
            sessions.remove(&key);
            state_hash
        })
    }

    fn perform_keyring_cleanup(
        expired_hashes: Vec<String>,
        evicted_hash: Option<String>,
        pkce_storage: &Arc<dyn PkceSessionStorage>,
    ) {
        if expired_hashes.is_empty() && evicted_hash.is_none() {
            return;
        }

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let pkce_storage = pkce_storage.clone();

            handle.spawn(async move {
                let mut to_delete = expired_hashes;
                if let Some(h) = evicted_hash {
                    to_delete.push(h);
                }

                let _ = tokio::task::spawn_blocking(move || {
                    for state_hash in to_delete {
                        if let Err(e) = pkce_storage.delete_session(&state_hash) {
                            tracing::warn!(
                                target: "security",
                                state_hash = %state_hash,
                                "Failed to delete session from keyring during cleanup: {e}"
                            );
                        }
                    }
                })
                .await
                .map_err(|e| {
                    tracing::warn!(
                        target: "security",
                        "Keyring cleanup task join error: {e}"
                    );
                });
            });
        } else {
            // Sync fallback for non-async contexts (e.g. tests)
            for state_hash in expired_hashes {
                if let Err(e) = pkce_storage.delete_session(&state_hash) {
                    tracing::warn!(
                        target: "security",
                        state_hash = %state_hash,
                        "Failed to delete expired session from keyring (sync fallback): {e}"
                    );
                }
            }
            if let Some(state_hash) = evicted_hash {
                match pkce_storage.delete_session(&state_hash) {
                    Ok(()) => tracing::debug!(
                        target: "security",
                        state_hash = %state_hash,
                        "Evicted session deleted from keyring (sync fallback)"
                    ),
                    Err(e) => tracing::warn!(
                        target: "security",
                        state_hash = %state_hash,
                        "Failed to delete evicted session from keyring (sync fallback): {e}"
                    ),
                }
            }
        }
    }

    /// Performs a background cleanup of stale sessions from the keyring.
    ///
    /// This should be called on application startup to ensure that any
    /// sessions left over from crashes or forceful terminations are removed.
    pub fn cleanup_stale_sessions(&self) {
        // This is a placeholder for future implementation.
        // Currently, the keyring API doesn't support listing entries, so we can't
        // easily sweep for stale sessions without maintaining a separate index.
        // For now, we rely on the "consume-once" and "evict-on-full" policies
        // to keep the keyring usage bounded.
        tracing::debug!("OAuth session cleanup initiated (placeholder)");
    }
}

impl Default for OAuthSessionStore {
    fn default() -> Self {
        let pkce_storage: Arc<dyn PkceSessionStorage> = Arc::new(KeyringPkceStorage);
        Self::new(pkce_storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::modules::auth::oauth::{AuthProvider, OAuthPkceSession};

    /// Mock PKCE storage for testing that does nothing (no-op).
    struct MockPkceStorage;
    impl PkceSessionStorage for MockPkceStorage {
        fn save_session(&self, _state_hash: &str, _session: &str) -> Result<(), String> {
            Ok(())
        }
        fn get_session(&self, _state_hash: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn delete_session(&self, _state_hash: &str) -> Result<(), String> {
            Ok(())
        }
    }

    fn create_mock_store() -> OAuthSessionStore {
        OAuthSessionStore::new(Arc::new(MockPkceStorage))
    }

    #[test]
    fn session_store_returns_none_for_unknown_state() {
        let store = create_mock_store();
        assert!(store.take_valid("unknown-state", "test-req").is_none());
    }

    #[test]
    fn session_store_returns_session_once_then_removes() {
        let store = create_mock_store();
        let session = OAuthPkceSession::new(
            "test-state".to_string(),
            "a".repeat(43),
            AuthProvider::Google,
        );

        store.store(session);

        // First take succeeds
        let retrieved = store.take_valid("test-state", "test-req");
        assert!(retrieved.is_some());

        // Second take fails (session consumed)
        assert!(store.take_valid("test-state", "test-req").is_none());
    }

    #[test]
    fn session_store_handles_multiple_sessions() {
        let store = create_mock_store();

        let session1 =
            OAuthPkceSession::new("state-1".to_string(), "a".repeat(43), AuthProvider::Google);
        let session2 =
            OAuthPkceSession::new("state-2".to_string(), "b".repeat(43), AuthProvider::GitHub);

        store.store(session1);
        store.store(session2);

        // Can retrieve both independently
        let s1 = store.take_valid("state-1", "test-req");
        assert!(s1.is_some());
        assert_eq!(s1.unwrap().provider, AuthProvider::Google);

        let s2 = store.take_valid("state-2", "test-req");
        assert!(s2.is_some());
        assert_eq!(s2.unwrap().provider, AuthProvider::GitHub);

        // Both consumed
        assert!(store.take_valid("state-1", "test-req").is_none());
        assert!(store.take_valid("state-2", "test-req").is_none());
    }

    #[test]
    fn session_store_cleans_expired_sessions_on_store() {
        use chrono::{Duration as ChronoDuration, Utc};

        let store = create_mock_store();

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
        assert!(store.take_valid("old-state", "test-req").is_none());
        // New session should exist
        assert!(store.take_valid("new-state", "test-req").is_some());
    }

    #[test]
    fn session_store_preserves_unexpired_sessions() {
        use chrono::{Duration as ChronoDuration, Utc};

        let store = create_mock_store();

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
        assert!(store.take_valid("recent-state", "test-req").is_some());
        assert!(store.take_valid("new-state", "test-req").is_some());
    }
}
