use super::PKCE_SESSION_KEYRING_SERVICE;
use keyring::Entry;

/// Trait for securely storing OAuth tokens.
pub trait TokenStorage: Send + Sync {
    /// Stores a token secret securely.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails (e.g. keyring unavailable).
    fn store(&self, service: &str, user_key: &str, secret: &str) -> Result<(), String>;
}

/// Trait for securely storing PKCE OAuth sessions.
///
/// PKCE sessions contain sensitive data (PKCE verifier, state) that must be
/// stored in OS secure storage (keyring) rather than plaintext files.
pub trait PkceSessionStorage: Send + Sync {
    /// Saves a PKCE session securely.
    ///
    /// # Arguments
    ///
    /// * `state_hash` - The hashed state parameter (used as key)
    /// * `session_json` - The serialized session data
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails (e.g. keyring unavailable).
    fn save_session(&self, state_hash: &str, session_json: &str) -> Result<(), String>;

    /// Retrieves a PKCE session from secure storage.
    ///
    /// # Arguments
    ///
    /// * `state_hash` - The hashed state parameter (used as key)
    ///
    /// # Returns
    ///
    /// * `Ok(Some(session_json))` - The session data if found
    /// * `Ok(None)` - If session not found
    /// * `Err(...)` - If retrieval fails
    ///
    /// # Errors
    ///
    /// Returns an error if the keyring is unavailable or access fails.
    fn get_session(&self, state_hash: &str) -> Result<Option<String>, String>;

    /// Deletes a PKCE session from secure storage.
    ///
    /// # Arguments
    ///
    /// * `state_hash` - The hashed state parameter (used as key)
    ///
    /// # Errors
    ///
    /// Returns an error if deletion fails.
    fn delete_session(&self, state_hash: &str) -> Result<(), String>;
}

/// Default implementation using OS keyring.
#[derive(Clone)]
pub struct KeyringTokenStorage;

impl TokenStorage for KeyringTokenStorage {
    fn store(&self, service: &str, user_key: &str, secret: &str) -> Result<(), String> {
        const MAX_SECRET_LEN: usize = 16 * 1024;

        if secret.len() > MAX_SECRET_LEN {
            return Err("Secret too large".to_string());
        }

        #[cfg(not(test))]
        {
            let entry = Entry::new(service, user_key).map_err(|e| e.to_string())?;
            entry.set_password(secret).map_err(|e| e.to_string())?;
            Ok(())
        }
        #[cfg(test)]
        {
            let _ = (service, user_key, secret);
            Ok(())
        }
    }
}

/// Default implementation of `PkceSessionStorage` using OS keyring.
#[derive(Clone)]
pub struct KeyringPkceStorage;

impl PkceSessionStorage for KeyringPkceStorage {
    fn save_session(&self, state_hash: &str, session_json: &str) -> Result<(), String> {
        const MAX_SESSION_JSON_LEN: usize = 16 * 1024;

        if session_json.len() > MAX_SESSION_JSON_LEN {
            return Err("Session too large".to_string());
        }

        #[cfg(not(test))]
        {
            let entry =
                Entry::new(PKCE_SESSION_KEYRING_SERVICE, state_hash).map_err(|e| e.to_string())?;
            entry
                .set_password(session_json)
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        #[cfg(test)]
        {
            let _ = (state_hash, session_json);
            Ok(())
        }
    }

    fn get_session(&self, state_hash: &str) -> Result<Option<String>, String> {
        #[cfg(not(test))]
        {
            let entry =
                Entry::new(PKCE_SESSION_KEYRING_SERVICE, state_hash).map_err(|e| e.to_string())?;
            match entry.get_password() {
                Ok(password) => Ok(Some(password)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        }
        #[cfg(test)]
        {
            let _ = state_hash;
            Ok(None)
        }
    }

    fn delete_session(&self, state_hash: &str) -> Result<(), String> {
        #[cfg(not(test))]
        {
            let entry =
                Entry::new(PKCE_SESSION_KEYRING_SERVICE, state_hash).map_err(|e| e.to_string())?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        #[cfg(test)]
        {
            let _ = state_hash;
            Ok(())
        }
    }
}

// ===========================================
// Enum Dispatch Wrappers
// ===========================================

/// Enum wrapper for `TokenStorage` implementations.
#[derive(Clone)]
pub enum TokenStorageEnum {
    /// Production keyring storage.
    Keyring(KeyringTokenStorage),
    /// Mock storage for testing.
    Mock(std::sync::Arc<MockTokenStorage>),
}

impl TokenStorageEnum {
    /// Creates a new keyring-based token storage.
    #[must_use]
    pub fn new_keyring() -> Self {
        Self::Keyring(KeyringTokenStorage)
    }

    /// Creates a new mock token storage for testing.
    #[must_use]
    pub fn new_mock() -> Self {
        Self::Mock(std::sync::Arc::new(MockTokenStorage::new()))
    }
}

impl TokenStorage for TokenStorageEnum {
    fn store(&self, service: &str, user_key: &str, secret: &str) -> Result<(), String> {
        match self {
            Self::Keyring(storage) => storage.store(service, user_key, secret),
            Self::Mock(mock) => mock.store(service, user_key, secret),
        }
    }
}

/// Enum wrapper for `PkceSessionStorage` implementations.
#[derive(Clone)]
pub enum PkceSessionStorageEnum {
    /// Production keyring storage.
    Keyring(KeyringPkceStorage),
    /// Mock storage for testing.
    Mock(std::sync::Arc<MockPkceStorage>),
}

impl PkceSessionStorageEnum {
    /// Creates a new keyring-based PKCE storage.
    #[must_use]
    pub fn new_keyring() -> Self {
        Self::Keyring(KeyringPkceStorage)
    }

    /// Creates a new mock PKCE storage for testing.
    #[must_use]
    pub fn new_mock() -> Self {
        Self::Mock(std::sync::Arc::new(MockPkceStorage::new()))
    }
}

impl PkceSessionStorage for PkceSessionStorageEnum {
    fn save_session(&self, state_hash: &str, session_json: &str) -> Result<(), String> {
        match self {
            Self::Keyring(storage) => storage.save_session(state_hash, session_json),
            Self::Mock(mock) => mock.save_session(state_hash, session_json),
        }
    }

    fn get_session(&self, state_hash: &str) -> Result<Option<String>, String> {
        match self {
            Self::Keyring(storage) => storage.get_session(state_hash),
            Self::Mock(mock) => mock.get_session(state_hash),
        }
    }

    fn delete_session(&self, state_hash: &str) -> Result<(), String> {
        match self {
            Self::Keyring(storage) => storage.delete_session(state_hash),
            Self::Mock(mock) => mock.delete_session(state_hash),
        }
    }
}

// ===========================================
// Mock Implementations
// ===========================================

/// Mock token storage for testing.
pub struct MockTokenStorage {
    storage: std::sync::RwLock<std::collections::HashMap<String, String>>,
}

impl MockTokenStorage {
    /// Creates a new empty mock storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            storage: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for MockTokenStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStorage for MockTokenStorage {
    fn store(&self, service: &str, user_key: &str, secret: &str) -> Result<(), String> {
        let key = format!("{service}:{user_key}");
        self.storage
            .write()
            .unwrap()
            .insert(key, secret.to_string());
        Ok(())
    }
}

/// Mock PKCE storage for testing.
pub struct MockPkceStorage {
    sessions: std::sync::RwLock<std::collections::HashMap<String, String>>,
}

impl MockPkceStorage {
    /// Creates a new empty mock storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for MockPkceStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl PkceSessionStorage for MockPkceStorage {
    fn save_session(&self, state_hash: &str, session_json: &str) -> Result<(), String> {
        self.sessions
            .write()
            .unwrap()
            .insert(state_hash.to_string(), session_json.to_string());
        Ok(())
    }

    fn get_session(&self, state_hash: &str) -> Result<Option<String>, String> {
        Ok(self.sessions.read().unwrap().get(state_hash).cloned())
    }

    fn delete_session(&self, state_hash: &str) -> Result<(), String> {
        self.sessions.write().unwrap().remove(state_hash);
        Ok(())
    }
}
