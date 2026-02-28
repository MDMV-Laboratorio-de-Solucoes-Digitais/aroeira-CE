use infra::security::{FileCreationConfig, PathValidator, SecureFileCreator};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::RwLock;
use tracing::{error, warn};

pub const AUTH_TOKEN_KEY: &str = "auth_token";
const MAX_TOKEN_LENGTH: usize = 4096;

pub trait SecureStorage: Send + Sync {
    async fn save(&self, key: &str, value: &str) -> Result<(), String>;
    async fn get(&self, key: &str) -> Result<Option<String>, String>;
    async fn delete(&self, key: &str) -> Result<(), String>;
}

/// Enum wrapper for `SecureStorage` implementations.
///
/// Provides static dispatch over `TauriSecureStorage` (production) and
/// `MockSecureStorage` (testing).
pub enum SecureStorageEnum {
    /// Production implementation using Tauri's secure storage.
    Tauri(TauriSecureStorage<tauri::Wry>),
    /// Mock implementation for testing.
    Mock(MockSecureStorage),
}

impl SecureStorage for SecureStorageEnum {
    async fn save(&self, key: &str, value: &str) -> Result<(), String> {
        match self {
            Self::Tauri(s) => s.save(key, value).await,
            Self::Mock(s) => s.save(key, value).await,
        }
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        match self {
            Self::Tauri(s) => s.get(key).await,
            Self::Mock(s) => s.get(key).await,
        }
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        match self {
            Self::Tauri(s) => s.delete(key).await,
            Self::Mock(s) => s.delete(key).await,
        }
    }
}

/// Mock implementation of `SecureStorage` for testing.
pub struct MockSecureStorage {
    storage: Arc<RwLock<HashMap<String, String>>>,
    should_fail: bool,
}

impl MockSecureStorage {
    /// Creates a new mock storage that succeeds on all operations.
    #[must_use]
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            should_fail: false,
        }
    }

    /// Creates a mock storage that fails on all operations.
    #[must_use]
    pub fn new_failing() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            should_fail: true,
        }
    }
}

impl Default for MockSecureStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureStorage for MockSecureStorage {
    async fn save(&self, key: &str, value: &str) -> Result<(), String> {
        if self.should_fail {
            return Err("Mock storage failure".to_string());
        }
        let mut store = self.storage.write().await;
        store.insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        if self.should_fail {
            return Err("Mock storage failure".to_string());
        }
        let store = self.storage.read().await;
        Ok(store.get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        if self.should_fail {
            return Err("Mock storage failure".to_string());
        }
        let mut store = self.storage.write().await;
        store.remove(key);
        Ok(())
    }
}

pub struct TauriSecureStorage<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> TauriSecureStorage<R> {
    pub fn new(app: AppHandle<R>) -> Self {
        Self { app }
    }

    fn get_storage_path(&self, key: &str) -> Result<PathBuf, String> {
        Self::validate_key(key)?;
        Ok(self.get_base_dir()?.join("secure_store").join(key))
    }

    fn get_old_storage_path(&self, key: &str) -> Result<PathBuf, String> {
        Self::validate_key(key)?;
        Ok(self.get_base_dir()?.join("auth").join(key))
    }

    fn validate_key(key: &str) -> Result<(), String> {
        if key.is_empty()
            || key.contains('/')
            || key.contains('\\')
            || key.contains("..")
            || key == "."
        {
            return Err(format!("Invalid storage key: {key}"));
        }
        Ok(())
    }

    fn get_base_dir(&self) -> Result<PathBuf, String> {
        self.app.path().app_config_dir().map_or_else(|_| {
            self.app.path().app_local_data_dir().map_or_else(
                |_| Err("No suitable directory available for secure storage".to_string()),
                |data_dir| {
                    warn!(
                        "app_config_dir unavailable; falling back to app_local_data_dir for secure storage"
                    );
                    Ok(data_dir)
                },
            )
        }, Ok)
    }

    fn ensure_storage_dir_exists(path: &Path) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| "Invalid storage path".to_string())?;

        let validator = PathValidator::new();
        if parent.exists() {
            validator
                .validate(parent)
                .map_err(|_| "Path validation failed".to_string())?;
        }

        std::fs::create_dir_all(parent).map_err(|e| {
            error!(error = %e, "Failed to create storage directory");
            format!("Failed to create storage directory: {e}")
        })?;

        validator.validate(parent).map_err(|e| {
            error!(error = %e, "Post-creation path validation failed");
            format!("Post-creation path validation failed: {e}")
        })?;

        Ok(())
    }
}

impl<R: Runtime> SecureStorage for TauriSecureStorage<R> {
    async fn save(&self, key: &str, value: &str) -> Result<(), String> {
        let value = value.trim().to_string();
        if value.is_empty() {
            return Err("Value cannot be empty".to_string());
        }
        if value.len() > MAX_TOKEN_LENGTH {
            return Err("Value exceeds maximum allowed length".to_string());
        }

        let path = self.get_storage_path(key)?;

        tokio::task::spawn_blocking(move || {
            Self::ensure_storage_dir_exists(&path)?;

            let config = FileCreationConfig {
                fail_if_exists: false,
                ..Default::default()
            };
            let creator = SecureFileCreator::with_config(config);

            creator.write_string(&path, &value).map_err(|e| {
                error!("Failed to write secure file: {}", e);
                format!("Failed to secure storage write: {e}")
            })?;

            Ok(())
        })
        .await
        .map_err(|e| format!("Task join error: {e}"))?
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let path = self.get_storage_path(key)?;
        let old_path = self.get_old_storage_path(key).ok();
        let key_owned = key.to_string();

        tokio::task::spawn_blocking(move || {
            let key = key_owned;
            if !path.exists() {
                // Backward compatibility: Migrate from old "auth" directory if it exists
                if let Some(old) = old_path.filter(|o| o.exists() && o.is_file()) {
                    if let Some(parent) = path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    if std::fs::rename(&old, &path).is_ok() {
                        warn!(key = %key, "Migrated secure storage");
                    }
                }

                if !path.exists() {
                    return Ok(None);
                }
            }

            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                return Ok(None);
            };

            // Refuse symlinks / non-regular files, but try to self-heal.
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                warn!(key = %key, "Invalid secure storage path type detected; self-healing...");
                if let Err(e) = std::fs::remove_file(&path) {
                    error!(key = %key, error = %e, "Failed to remove invalid secure storage file");
                }
                return Ok(None);
            }

            // Prevent memory DoS before reading.
            if metadata.len() > MAX_TOKEN_LENGTH as u64 {
                warn!(key = %key, size = metadata.len(), "Secure storage file too large; self-healing...");
                if let Err(e) = std::fs::remove_file(&path) {
                    error!(key = %key, error = %e, "Failed to remove oversized secure storage file");
                }
                return Ok(None);
            }

            let Ok(content) = std::fs::read(&path) else {
                return Ok(None);
            };

            let Ok(s) = String::from_utf8(content) else {
                warn!(key = %key, "Secure storage content is not valid UTF-8; self-healing...");
                if let Err(e) = std::fs::remove_file(&path) {
                    error!(key = %key, error = %e, "Failed to remove corrupted secure storage file");
                }
                return Ok(None);
            };

            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed.len() > MAX_TOKEN_LENGTH {
                warn!(key = %key, "Secure storage content invalid after trimming; self-healing...");
                if let Err(e) = std::fs::remove_file(&path) {
                    error!(key = %key, error = %e, "Failed to remove invalid-content secure storage file");
                }
                return Ok(None);
            }

            Ok(Some(trimmed.to_string()))
        })
        .await
        .map_err(|e| format!("Task join error: {e}"))?
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        let path = self.get_storage_path(key)?;
        let key_owned = key.to_string();

        tokio::task::spawn_blocking(move || {
            let key = key_owned;
            if path.exists() {
                // Symlink check before delete to avoid escaping jail
                if std::fs::symlink_metadata(&path)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    if let Err(e) = std::fs::remove_file(&path) {
                        error!(key = %key, error = %e, "Failed to self-heal symlink in delete");
                    }
                    return Ok(());
                }

                std::fs::remove_file(&path).map_err(|e| {
                    error!(key = %key, error = %e, "Failed to delete secure storage file");
                    e.to_string()
                })?;
            }
            Ok(())
        })
        .await
        .map_err(|e| format!("Task join error: {e}"))?
    }
}
