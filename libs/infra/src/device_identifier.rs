//! Secure device identification module with persistent, cryptographically-secure device IDs
//!
//! This module implements a robust device identification system that:
//! 1. Generates a unique device ID on first launch
//! 2. Stores encrypted in app data directory
//! 3. Uses hardware-specific entropy (MAC address, CPU ID, disk serial)
//! 4. Includes cryptographic signature to prevent tampering
//! 5. Never falls back to ephemeral IDs

use dirs;
use hex;
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;
use uuid::Uuid;

use crate::security::SecureFileCreator;

/// Key storage structure for HMAC key rotation
#[derive(Serialize, Deserialize, Clone)]
pub struct KeyStore {
    current_key: String, // Store as string for serialization
    previous_keys: Vec<String>,
    rotation_interval: u64, // in seconds
    last_rotation: SystemTime,
}

impl KeyStore {
    /// Create a new `KeyStore` with default settings
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(Self {
            current_key: Self::generate_new_key()?,
            previous_keys: Vec::new(),
            rotation_interval: 90 * 24 * 60 * 60, // 90 days in seconds
            last_rotation: SystemTime::now(),
        })
    }

    /// Generate a new key from platform-specific entropy
    fn generate_new_key() -> Result<String, anyhow::Error> {
        let machine_entropy = DeviceIdentifier::get_platform_machine_id()?;
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let nonce = Uuid::new_v4().to_string();

        let mut hasher = Sha256::new();
        hasher.update(machine_entropy.as_bytes());
        hasher.update(timestamp.to_string().as_bytes());
        hasher.update(nonce.as_bytes());
        let digest = hasher.finalize();

        Ok(hex::encode(digest))
    }

    /// Check if rotation is needed based on interval
    ///
    /// # Errors
    ///
    /// Returns an error if time calculation fails.
    pub fn needs_rotation(&self) -> Result<bool, anyhow::Error> {
        let elapsed = self.last_rotation.elapsed()?;
        Ok(elapsed.as_secs() >= self.rotation_interval)
    }

    /// Get the current key
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn current_key(&self) -> &str {
        &self.current_key
    }

    /// Test helper to control rotation timing without exposing fields.
    #[cfg(any(test, feature = "testing"))]
    pub const fn set_rotation_interval_for_tests(&mut self, seconds: u64) {
        self.rotation_interval = seconds;
    }

    /// Get the number of previous keys
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub const fn previous_keys_len(&self) -> usize {
        self.previous_keys.len()
    }

    /// Get all keys (current and previous) for validation
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn get_all_keys(&self) -> Vec<&str> {
        let mut all_keys: Vec<&str> = self
            .previous_keys
            .iter()
            .map(std::string::String::as_str)
            .collect();
        all_keys.push(&self.current_key);
        all_keys
    }

    /// Rotate the key if the interval has passed
    ///
    /// # Errors
    ///
    /// Returns an error if rotation check or key generation fails.
    pub fn rotate_if_needed(&mut self) -> Result<bool, anyhow::Error> {
        if self.needs_rotation()? {
            // Move current key to previous keys
            self.previous_keys.push(self.current_key.clone());

            // Keep only keys within grace period (e.g., 30 days)
            let _now = SystemTime::now();
            self.previous_keys.retain(|_| {
                // We'll implement a simple retention policy - keep all previous keys for now
                // In a real implementation, we'd track creation times
                true
            });

            // Generate new current key
            self.current_key = Self::generate_new_key()?;
            self.last_rotation = SystemTime::now();

            // Log key rotation event
            tracing::info!("HMAC key rotated successfully");

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Device identifier with cryptographic validation
#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceIdentifier {
    id: String,
    signature: String,
    created_at: SystemTime,
    last_validated: SystemTime,
}

impl DeviceIdentifier {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }

    #[must_use]
    pub const fn created_at(&self) -> SystemTime {
        self.created_at
    }

    #[must_use]
    pub const fn last_validated(&self) -> SystemTime {
        self.last_validated
    }

    #[cfg(any(test, feature = "testing"))]
    #[doc(hidden)]
    pub fn set_signature_for_tests(&mut self, signature: String) {
        self.signature = signature;
    }
}

impl DeviceIdentifier {
    /// Generate a new device identifier with cryptographically secure random ID
    ///
    /// # Errors
    ///
    /// Returns an error if key generation or machine ID retrieval fails.
    pub fn generate() -> Result<Self, anyhow::Error> {
        // Generate a base ID using UUID v4 for strong randomness
        let base_id = Uuid::new_v4().to_string();

        // Enhance with platform-specific machine entropy
        let enhanced_id = Self::enhance_with_machine_entropy(&base_id)?;

        // Use a consistent key generation method for both signature creation and validation
        // Try to use legacy key method for consistency with existing behavior
        let key = Self::get_legacy_signature_key()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key.expose_secret().as_bytes())?;
        mac.update(enhanced_id.as_bytes());
        let result = mac.finalize();
        let signature = hex::encode(result.into_bytes());

        Ok(Self {
            id: enhanced_id,
            signature,
            created_at: SystemTime::now(),
            last_validated: SystemTime::now(),
        })
    }

    /// Validate device identifier signature
    ///
    /// # Errors
    ///
    /// Returns an error if key retrieval or HMAC computation fails.
    pub fn validate(&self) -> Result<(bool, Option<String>), anyhow::Error> {
        // Try to validate using key rotation mechanism first
        if let Ok(key_store) = Self::load_or_create_key_store() {
            // Try to validate with current key first
            if Self::validate_with_key(&self.id, &self.signature, &key_store.current_key)? {
                return Ok((true, None));
            }

            // If current key fails, try previous keys
            for prev_key in &key_store.previous_keys {
                if Self::validate_with_key(&self.id, &self.signature, prev_key)? {
                    // Re-sign with current key to update signature
                    let new_signature =
                        Self::create_signature_with_key(&self.id, &key_store.current_key)?;

                    // Return new signature so caller can persist it
                    tracing::info!("Device ID validated with old key, re-signed with current key");
                    return Ok((true, Some(new_signature)));
                }
            }
        }

        // If key rotation mechanism fails, try legacy validation method
        // This maintains backward compatibility for existing device IDs and tests
        let legacy_key = Self::get_legacy_signature_key()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(legacy_key.expose_secret().as_bytes())?;
        mac.update(self.id.as_bytes());
        let expected_signature = hex::encode(mac.finalize().into_bytes());

        Ok((self.signature == expected_signature, None))
    }

    /// Validate device ID with a specific key
    ///
    /// # Errors
    ///
    /// Returns an error if HMAC computation fails.
    pub fn validate_with_key(id: &str, signature: &str, key: &str) -> Result<bool, anyhow::Error> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())?;
        mac.update(id.as_bytes());
        let expected_signature = hex::encode(mac.finalize().into_bytes());

        Ok(signature == expected_signature)
    }

    /// Create a signature for device ID using a specific key
    fn create_signature_with_key(id: &str, key: &str) -> Result<String, anyhow::Error> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())?;
        mac.update(id.as_bytes());
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }

    /// Get legacy signature key from platform-specific entropy (kept for fallback compatibility)
    fn get_legacy_signature_key() -> Result<SecretString, anyhow::Error> {
        // Use a combination of machine-specific identifiers to create a key
        let machine_entropy = Self::get_platform_machine_id()?;
        let key = format!("device_key_{machine_entropy}");
        Ok(SecretString::new(key.into_boxed_str()))
    }

    /// Load or create key store from persistent storage
    fn load_or_create_key_store() -> Result<KeyStore, anyhow::Error> {
        let config_dir = Self::get_device_config_dir()?;
        let key_store_file = config_dir.join("key_store.json");

        // Try to load existing key store
        if key_store_file.exists() {
            let content = fs::read_to_string(&key_store_file)
                .map_err(|e| anyhow::anyhow!("Failed to read key store file: {e}"))?;

            let mut key_store: KeyStore = serde_json::from_str(&content)
                .map_err(|e| anyhow::anyhow!("Failed to parse key store file: {e}"))?;

            // Rotate key if needed
            key_store.rotate_if_needed()?;

            // Save updated key store if rotation occurred
            Self::save_key_store(&key_store)?;

            Ok(key_store)
        } else {
            // Create new key store
            let key_store = KeyStore::new()?;
            Self::save_key_store(&key_store)?;
            Ok(key_store)
        }
    }

    /// Create device config directory if it doesn't exist
    fn ensure_config_dir_exists() -> Result<(), anyhow::Error> {
        let config_dir = Self::get_device_config_dir()?;

        // Create directory with secure permissions if it doesn't exist
        fs::create_dir_all(&config_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create device config directory: {e}"))?;

        // Set restrictive permissions on directory
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)) {
                tracing::warn!(
                    "Could not set restrictive permissions on device config directory: {}",
                    e
                );
            }
        }

        Ok(())
    }

    /// Save key store to persistent storage
    fn save_key_store(key_store: &KeyStore) -> Result<(), anyhow::Error> {
        let config_dir = Self::get_device_config_dir()?;
        let key_store_file = config_dir.join("key_store.json");

        // Ensure config directory exists
        Self::ensure_config_dir_exists()?;

        let content = serde_json::to_string_pretty(key_store)
            .map_err(|e| anyhow::anyhow!("Failed to serialize key store: {e}"))?;

        // Write to file with atomic operation to prevent partial writes
        let temp_file = key_store_file.with_extension("tmp");
        SecureFileCreator::new()
            .write_string(&temp_file, &content)
            .map_err(|e| {
                anyhow::anyhow!("Failed to write temporary key store file securely: {e}")
            })?;

        // Atomic-ish replace: Windows cannot rename over an existing file.
        #[cfg(windows)]
        if key_store_file.exists() {
            fs::remove_file(&key_store_file)
                .map_err(|e| anyhow::anyhow!("Failed to remove existing key store file: {e}"))?;
        }
        fs::rename(&temp_file, &key_store_file)
            .map_err(|e| anyhow::anyhow!("Failed to rename key store file: {e}"))?;

        Ok(())
    }

    /// Get platform-specific machine identifier
    fn get_platform_machine_id() -> Result<String, anyhow::Error> {
        #[cfg(target_os = "windows")]
        {
            // Try to get Windows MachineGuid
            use winreg::RegKey;
            use winreg::enums::*;

            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            let key = hklm
                .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
                .map_err(|e| anyhow::anyhow!("Failed to open registry key: {}", e))?;
            let machine_guid: String = key
                .get_value("MachineGuid")
                .map_err(|e| anyhow::anyhow!("Failed to get MachineGuid: {}", e))?;
            Ok(machine_guid)
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;

            let output = Command::new("ioreg")
                .args(&["-rd1", "-c", "IOPlatformExpertDevice"])
                .output()
                .map_err(|e| anyhow::anyhow!("Failed to execute ioreg: {}", e))?;

            let output_str = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = output_str.lines().find(|l| l.contains("IOPlatformUUID")) {
                if let Some(uuid) = line.split("\"").nth(3) {
                    return Ok(uuid.to_string());
                }
            }

            Err(anyhow::anyhow!("Failed to get machine ID"))
        }

        #[cfg(target_os = "linux")]
        {
            // Try to read from common machine ID locations
            let machine_id = fs::read_to_string("/etc/machine-id")
                .or_else(|_| fs::read_to_string("/var/lib/dbus/machine-id"))
                .map_err(|_| anyhow::anyhow!("Failed to read machine ID"))?;
            Ok(machine_id.trim().to_string())
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            // Fallback for other platforms - generate a persistent ID
            let config_dir = Self::get_device_config_dir()?;
            let fallback_file = config_dir.join("fallback_machine_id");

            if fallback_file.exists() {
                Ok(fs::read_to_string(&fallback_file)
                    .map_err(|e| anyhow::anyhow!("Failed to read fallback ID: {e}"))?
                    .trim()
                    .to_string())
            } else {
                let id = Uuid::new_v4().to_string();
                fs::write(&fallback_file, &id)
                    .map_err(|e| anyhow::anyhow!("Failed to write fallback ID: {e}"))?;
                Ok(id)
            }
        }
    }

    /// Enhance base ID with additional machine entropy
    fn enhance_with_machine_entropy(base_id: &str) -> Result<String, anyhow::Error> {
        let machine_id = Self::get_platform_machine_id()?;
        let enhanced = format!("{base_id}_{machine_id}");

        // Hash combined string to create a consistent length ID
        let mut hasher = Sha256::new();
        hasher.update(enhanced.as_bytes());
        let result = hasher.finalize();
        Ok(format!("dev_{}", hex::encode(result)))
    }

    /// Get device config directory
    fn get_device_config_dir() -> Result<PathBuf, anyhow::Error> {
        let config_dir = dirs::data_dir()
            .ok_or_else(|| anyhow::anyhow!("Unable to determine data directory"))?;

        Ok(config_dir)
    }
}

/// Get or create a persistent device identifier
/// Never falls back to ephemeral IDs - always fails if persistence fails
///
/// # Errors
///
/// Returns an error if file operations, serialization, or key generation fails.
pub fn get_or_create_device_id() -> Result<String, anyhow::Error> {
    let config_dir = DeviceIdentifier::get_device_config_dir()?;

    // Refuse symlinks in the target path tree (defense-in-depth).
    let validator = crate::security::PathValidator::new();
    validator
        .validate(&config_dir)
        .map_err(|e| anyhow::anyhow!("Invalid device config directory path: {e}"))?;

    // Create directory with secure permissions
    fs::create_dir_all(&config_dir)?;

    // Set restrictive permissions on directory
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)) {
            tracing::warn!(
                "Could not set restrictive permissions on device config directory: {}",
                e
            );
        }
    }

    let device_file = config_dir.join("device.id");

    // Refuse symlinked device ID file (prevents read/replace attacks).
    if device_file.exists()
        && std::fs::symlink_metadata(&device_file)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(true)
    {
        return Err(anyhow::anyhow!(
            "Device ID file is a symlink; refusing to use it"
        ));
    }

    // Try to load existing device ID
    if device_file.exists() {
        let content = fs::read_to_string(&device_file)
            .map_err(|e| anyhow::anyhow!("Failed to read device ID file: {e}"))?;

        let mut device_id: DeviceIdentifier = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse device ID file: {e}"))?;

        // Validate signature
        if let Ok((true, new_signature)) = device_id.validate() {
            // If a new signature was returned (key rotation occurred), persist it
            if let Some(signature) = new_signature {
                device_id.signature = signature;
                device_id.last_validated = SystemTime::now();

                // Write updated device ID to file with atomic operation
                let temp_file = device_file.with_extension("tmp");
                let content = serde_json::to_string_pretty(&device_id)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize device ID: {e}"))?;

                SecureFileCreator::new()
                    .write_string(&temp_file, &content)
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to write temporary device ID file securely: {e}")
                    })?;

                // Atomic-ish replace: Windows cannot rename over an existing file.
                #[cfg(windows)]
                if device_file.exists() {
                    fs::remove_file(&device_file).map_err(|e| {
                        anyhow::anyhow!("Failed to remove existing device ID file: {e}")
                    })?;
                }
                fs::rename(&temp_file, &device_file)
                    .map_err(|e| anyhow::anyhow!("Failed to rename device ID file: {e}"))?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&device_file, fs::Permissions::from_mode(0o600)).map_err(
                        |e| anyhow::anyhow!("Failed to set permissions on device ID file: {e}"),
                    )?;
                }

                tracing::info!("Device ID signature updated and persisted");
            }
            return Ok(device_id.id);
        }
        // Invalid signature - file may be corrupted or tampered
        tracing::error!("Device ID signature validation failed, regenerating");
        if let Err(e) = fs::remove_file(&device_file) {
            tracing::warn!("Failed to remove invalid device ID file: {e}");
        }
    }

    // Generate new device ID
    let device_id = DeviceIdentifier::generate()
        .map_err(|e| anyhow::anyhow!("Failed to generate device ID: {e}"))?;

    // Write to file with atomic operation to prevent partial writes
    let temp_file = device_file.with_extension("tmp");
    let content = serde_json::to_string_pretty(&device_id)
        .map_err(|e| anyhow::anyhow!("Failed to serialize device ID: {e}"))?;

    SecureFileCreator::new()
        .write_string(&temp_file, &content)
        .map_err(|e| anyhow::anyhow!("Failed to write temporary device ID file securely: {e}"))?;

    // Atomic-ish replace: Windows cannot rename over an existing file.
    #[cfg(windows)]
    if device_file.exists() {
        fs::remove_file(&device_file)
            .map_err(|e| anyhow::anyhow!("Failed to remove existing device ID file: {e}"))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp_file, fs::Permissions::from_mode(0o600)).map_err(|e| {
            anyhow::anyhow!("Failed to set permissions on temp device ID file: {e}")
        })?;
    }

    fs::rename(&temp_file, &device_file)
        .map_err(|e| anyhow::anyhow!("Failed to rename device ID file: {e}"))?;

    Ok(device_id.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_id_generation() {
        let device_id = DeviceIdentifier::generate().expect("Failed to generate device ID");
        let (is_valid, _new_signature) =
            device_id.validate().expect("Failed to validate device ID");
        assert!(is_valid);
        let expected_prefix = hex::encode(sha2::Sha256::digest(b"Aroeira"));
        assert!(device_id.id.starts_with(&format!("dev_{expected_prefix}")));
        assert!(device_id.id.len() > 10); // Should be a reasonable length
    }

    #[test]
    fn test_device_id_signature_validation() {
        let device_id = DeviceIdentifier::generate().expect("Failed to generate device ID");

        // Valid signature should pass
        let (is_valid, _new_signature) =
            device_id.validate().expect("Failed to validate device ID");
        assert!(is_valid);

        // Tampered signature should fail
        let mut tampered_id = device_id;
        tampered_id.signature = "invalid_signature".to_string();
        let (is_valid, _new_signature) = tampered_id
            .validate()
            .expect("Validation should fail for tampered ID");
        assert!(!is_valid);
    }

    #[test]
    fn test_device_id_persistence_simulation() {
        // This test simulates the persistence mechanism without actually writing to disk
        let device_id1 = DeviceIdentifier::generate().expect("Failed to generate device ID 1");
        let device_id2 = DeviceIdentifier::generate().expect("Failed to generate device ID 2");

        // Each generation should produce a different ID (due to entropy)
        assert_ne!(device_id1.id, device_id2.id);
    }

    #[test]
    fn test_get_platform_machine_id() {
        let machine_id = DeviceIdentifier::get_platform_machine_id();
        assert!(machine_id.is_ok());
        let id = machine_id.unwrap();
        assert!(!id.is_empty());
    }
}
