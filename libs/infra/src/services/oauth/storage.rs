#![allow(unused_imports)]
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
pub struct KeyringTokenStorage;

impl TokenStorage for KeyringTokenStorage {
    fn store(&self, service: &str, user_key: &str, secret: &str) -> Result<(), String> {
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
pub struct KeyringPkceStorage;

impl PkceSessionStorage for KeyringPkceStorage {
    fn save_session(&self, state_hash: &str, session_json: &str) -> Result<(), String> {
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
