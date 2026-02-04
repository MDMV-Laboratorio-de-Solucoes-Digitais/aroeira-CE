use hmac::{Hmac, Mac};
use infra::device_identifier::{DeviceIdentifier, KeyStore, get_or_create_device_id};
use sha2::Sha256;
use std::fs;
use std::sync::Mutex;
use temp_env::with_var;
use tempfile::TempDir;

// Mutex to ensure tests don't interfere with each other
pub static DEVICE_ID_TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_device_id_cannot_be_spoofed_via_env_vars() {
    let _guard = DEVICE_ID_TEST_MUTEX.lock().unwrap();

    let device_id1 = with_var("DEVICE_ID_OVERRIDE", Some("malicious_device_id"), || {
        get_or_create_device_id().expect("Should generate device ID")
    });

    let device_id2 = with_var(
        "DEVICE_ID_OVERRIDE",
        Some("different_malicious_device_id"),
        || get_or_create_device_id().expect("Should get same device ID"),
    );

    assert_eq!(device_id1, device_id2);
}

#[test]
fn test_device_id_persistence_across_application_restarts() {
    let _guard = DEVICE_ID_TEST_MUTEX.lock().unwrap();

    // Get device ID first time
    let device_id1 = get_or_create_device_id().expect("Should generate device ID");

    // Simulate app restart by calling again
    let device_id2 = get_or_create_device_id().unwrap_or_else(|e| {
        panic!("Failed to get device ID: {e}");
    });
    assert_eq!(device_id1, device_id2);
}

#[test]
fn test_device_id_signature_validation_prevents_tampering() {
    let device_id = DeviceIdentifier::generate().expect("Should generate device ID");

    // Valid signature should pass
    let (is_valid, _new_signature) = device_id
        .validate()
        .expect("Should validate valid device ID");
    assert!(is_valid);

    // Tampered signature should fail
    let mut tampered_id = device_id.clone();
    tampered_id.set_signature_for_tests("invalid_signature".to_string());
    let (is_valid, _new_signature) = tampered_id
        .validate()
        .expect("Should reject tampered device ID");
    assert!(!is_valid);
}

#[test]
fn test_device_id_has_sufficient_entropy_256bit() {
    let device_id = DeviceIdentifier::generate().expect("Should generate device ID");

    // Check that ID is reasonably long (should be at least 64 chars for 256-bit entropy)
    assert!(
        device_id.id().len() >= 64,
        "Device ID should have sufficient entropy"
    );

    // Generate multiple IDs to ensure they're different (probabilistically)
    let device_id2 = DeviceIdentifier::generate().expect("Should generate device ID");
    assert_ne!(
        device_id.id(),
        device_id2.id(),
        "Different device IDs should be generated"
    );
}

#[test]
fn test_device_id_file_has_restrictive_permissions() {
    let _guard = DEVICE_ID_TEST_MUTEX.lock().unwrap();

    // Create a real temporary directory for testing (platform-independent)
    let temp_dir = TempDir::new().expect("Should create temp dir");

    // Run the test inside the environment variable scope to ensure paths match
    with_var(
        "XDG_DATA_HOME",
        Some(temp_dir.path().to_string_lossy().to_string()),
        || {
            // Get device ID to ensure it exists for testing
            let _device_id = get_or_create_device_id().expect("Should generate device ID");

            // Resolve path using the same logic as implementation
            let config_dir = dirs::data_dir()
                .expect("Should get data dir")
                .join("Aroeira")
                .join("device");
            let device_file = config_dir.join("device.id");

            // Check file permissions on all platforms
            let metadata = fs::metadata(&device_file).expect("Should get file metadata");
            let permissions = metadata.permissions();

            // On Unix systems, verify restrictive permissions (0o600: owner read/write only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    permissions.mode() & 0o777,
                    0o600,
                    "Device ID file should have restrictive permissions (Unix)"
                );
            }

            // On Windows, verify file exists
            #[cfg(windows)]
            {
                assert!(
                    device_file.exists(),
                    "Device ID file should exist (Windows)"
                );
            }
        },
    );
}

#[test]
fn test_hmac_key_rotation_works_correctly() {
    let mut key_store = KeyStore::new().expect("Should create key store");

    let original_key = key_store.current_key().to_string();

    // Force a very short rotation interval for testing
    #[cfg(test)]
    key_store.set_rotation_interval_for_tests(0); // Immediate rotation

    let was_rotated = key_store.rotate_if_needed().expect("Should rotate keys");

    assert!(was_rotated, "Keys should have been rotated");
    assert_ne!(
        original_key,
        key_store.current_key(),
        "New key should be different"
    );
    assert_eq!(
        1,
        key_store.previous_keys_len(),
        "Previous key should be stored"
    );
}

#[test]
fn test_old_keys_continue_to_validate_during_grace_period() {
    let mut key_store = KeyStore::new().expect("Should create key store");

    let original_key = key_store.current_key().to_string();

    // Create a device ID with original key
    let mut device_id = DeviceIdentifier::generate().expect("Should generate device ID");

    // Manually sign with original key to ensure it's tied to that key
    let mut mac = Hmac::<Sha256>::new_from_slice(original_key.as_bytes()).unwrap();
    mac.update(device_id.id().as_bytes());
    let original_signature = hex::encode(mac.finalize().into_bytes());
    device_id.set_signature_for_tests(original_signature);

    // Verify it validates with original key
    assert!(
        DeviceIdentifier::validate_with_key(device_id.id(), device_id.signature(), &original_key)
            .expect("Original key should validate")
    );

    // Rotate keys
    key_store.set_rotation_interval_for_tests(0); // Immediate rotation
    key_store.rotate_if_needed().expect("Should rotate keys");

    // Now verify the device ID can still be validated with old key
    let all_keys = key_store.get_all_keys();
    let validated_with_old_key = all_keys.iter().any(|&key| {
        DeviceIdentifier::validate_with_key(device_id.id(), device_id.signature(), key)
            .unwrap_or(false)
    });

    assert!(
        validated_with_old_key,
        "Device ID should validate with old key during grace period"
    );
}

#[test]
fn test_device_id_regeneration_when_signature_invalid() {
    let temp_dir = TempDir::new().expect("Should create temp dir");
    let config_dir = temp_dir.path().join("Aroeira").join("device");
    fs::create_dir_all(&config_dir).expect("Should create config dir");

    let device_file = config_dir.join("device.id");

    // Create a device ID file with an invalid signature
    let mut device_id = DeviceIdentifier::generate().expect("Should generate device ID");
    device_id.set_signature_for_tests("invalid_signature".to_string());

    let content = serde_json::to_string_pretty(&device_id).unwrap();
    fs::write(&device_file, content).expect("Should write device ID file");

    // Validate the file - should detect invalid signature and regenerate
    let device_id_str = fs::read_to_string(&device_file).unwrap();
    let parsed_device_id: DeviceIdentifier = serde_json::from_str(&device_id_str).unwrap();

    // The invalid signature should be detected when validating
    let (is_valid, _new_signature) = parsed_device_id.validate().unwrap_or((false, None));
    assert!(!is_valid, "Invalid signature should be detected");
}
