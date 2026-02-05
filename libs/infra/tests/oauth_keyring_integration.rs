//! Integration tests for PKCE session storage using OS keyring
//!
//! These tests verify the actual interaction with the platform's secure storage:
//! - macOS: Keychain
//! - Windows: Credential Manager (Data Protection API)
//! - Linux: Secret Service API (GNOME Keyring, `KWallet`, etc.)
//!
//! # Test Isolation
//!
//! Each test uses unique identifiers (UUIDs) to avoid conflicts between test runs.
//! Tests clean up entries they create to avoid polluting the user's keyring.
//!
//! # CI Considerations
//!
//! These tests require an available keyring. In CI environments without a
//! keyring (headless Linux), tests gracefully skip or handle keyring unavailability.

use infra::services::oauth::{KeyringPkceStorage, PkceSessionStorage};
use std::sync::Arc;
use uuid::Uuid;

/// Creates a unique state hash for testing
fn test_state_hash() -> String {
    format!("test-state-{}", Uuid::new_v4())
}

/// Checks if keyring is available and functional by attempting a roundtrip
fn keyring_available() -> bool {
    use infra::services::oauth::{KeyringPkceStorage, PkceSessionStorage};

    let storage = KeyringPkceStorage;
    let test_key = format!("keyring-test-{}", Uuid::new_v4());
    let test_data = "test-data";

    storage.delete_session(&test_key).ok();

    if storage.save_session(&test_key, test_data).is_err() {
        return false;
    }

    let retrieved = storage.get_session(&test_key);
    storage.delete_session(&test_key).ok();

    matches!(retrieved, Ok(Some(data)) if data == test_data)
}

#[tokio::test]
async fn test_keyring_availability() {
    if !keyring_available() {
        eprintln!("Keyring not available - skipping keyring integration tests");
    }
}

#[tokio::test]
async fn test_save_and_retrieve_session_roundtrip() {
    if !keyring_available() {
        eprintln!("Skipping test: keyring not available");
        return;
    }

    let storage = KeyringPkceStorage;
    let state_hash = test_state_hash();
    let session_data =
        r#"{"verifier":"test-verifier-123","state":"test-state-456","provider":"Google"}"#;

    storage.delete_session(&state_hash).ok();

    let save_result = storage.save_session(&state_hash, session_data);
    assert!(save_result.is_ok(), "Save failed: {:?}", save_result.err());

    let get_result = storage.get_session(&state_hash);
    assert!(get_result.is_ok(), "Get failed: {:?}", get_result.err());
    assert_eq!(get_result.unwrap(), Some(session_data.to_string()));

    storage.delete_session(&state_hash).ok();
}

#[tokio::test]
async fn test_retrieve_nonexistent_session_returns_none() {
    if !keyring_available() {
        eprintln!("Skipping test: keyring not available");
        return;
    }

    let storage = KeyringPkceStorage;
    let state_hash = test_state_hash();

    storage.delete_session(&state_hash).ok();

    let result = storage.get_session(&state_hash);
    assert!(
        result.is_ok(),
        "Retrieval should not fail: {:?}",
        result.err()
    );
    assert_eq!(
        result.unwrap(),
        None,
        "Non-existent session should return None"
    );
}

#[tokio::test]
async fn test_delete_session_removes_entry() {
    if !keyring_available() {
        eprintln!("Skipping test: keyring not available");
        return;
    }

    let storage = KeyringPkceStorage;
    let state_hash = test_state_hash();
    let session_data =
        r#"{"verifier":"test-verifier-789","state":"test-state-abc","provider":"GitHub"}"#;

    storage
        .save_session(&state_hash, session_data)
        .expect("Failed to save session");

    let verify_exists = storage.get_session(&state_hash);
    assert!(
        verify_exists.unwrap().is_some(),
        "Entry should exist before deletion"
    );

    let delete_result = storage.delete_session(&state_hash);
    assert!(
        delete_result.is_ok(),
        "Delete failed: {:?}",
        delete_result.err()
    );

    let retrieve_after_delete = storage.get_session(&state_hash);
    assert_eq!(
        retrieve_after_delete.unwrap(),
        None,
        "Entry should not exist after deletion"
    );
}

#[tokio::test]
async fn test_consume_once_pattern() {
    if !keyring_available() {
        eprintln!("Skipping test: keyring not available");
        return;
    }

    let storage = KeyringPkceStorage;
    let state_hash = test_state_hash();
    let session_data = r#"{"verifier":"sensitive-data","state":"csrf-token","provider":"Google"}"#;

    storage
        .save_session(&state_hash, session_data)
        .expect("Failed to save session");

    let first_retrieve = storage.get_session(&state_hash);
    assert!(first_retrieve.is_ok(), "First retrieve should succeed");
    assert_eq!(first_retrieve.unwrap(), Some(session_data.to_string()));

    storage
        .delete_session(&state_hash)
        .expect("Delete should succeed");

    let second_retrieve = storage.get_session(&state_hash);
    assert_eq!(
        second_retrieve.unwrap(),
        None,
        "Second retrieve should fail after consume"
    );
}

#[tokio::test]
async fn test_large_session_data() {
    if !keyring_available() {
        eprintln!("Skipping test: keyring not available");
        return;
    }

    let storage = KeyringPkceStorage;
    let state_hash = test_state_hash();

    let large_verifier = "x".repeat(4000);
    let session_data =
        format!(r#"{{"verifier":"{large_verifier}","state":"test-state","provider":"Google"}}"#);

    storage.delete_session(&state_hash).ok();

    let save_result = storage.save_session(&state_hash, &session_data);

    if save_result.is_ok() {
        let retrieve_result = storage.get_session(&state_hash);
        assert!(retrieve_result.is_ok(), "Should retrieve large data");
        assert_eq!(retrieve_result.unwrap(), Some(session_data));
        storage.delete_session(&state_hash).ok();
    }
}

#[tokio::test]
async fn test_unicode_session_data() {
    if !keyring_available() {
        eprintln!("Skipping test: keyring not available");
        return;
    }

    let storage = KeyringPkceStorage;
    let state_hash = test_state_hash();

    let session_data =
        r#"{"verifier":"tëst-vérïfïër-日本語","state":"tëst-stäté","provider":"Google"}"#;

    storage.delete_session(&state_hash).ok();

    storage
        .save_session(&state_hash, session_data)
        .expect("Should save unicode data");
    let retrieved = storage
        .get_session(&state_hash)
        .expect("Should retrieve unicode data");

    assert_eq!(retrieved, Some(session_data.to_string()));

    storage.delete_session(&state_hash).ok();
}

#[tokio::test]
async fn test_special_characters_in_state_hash() {
    if !keyring_available() {
        eprintln!("Skipping test: keyring not available");
        return;
    }

    let storage = KeyringPkceStorage;
    let state_hash = "abc123def456789_special-chars.test";
    let session_data = r#"{"verifier":"test","state":"test","provider":"GitHub"}"#;

    storage.delete_session(state_hash).ok();

    storage
        .save_session(state_hash, session_data)
        .expect("Should save with special chars");
    let retrieved = storage.get_session(state_hash).expect("Should retrieve");

    assert_eq!(retrieved, Some(session_data.to_string()));

    storage.delete_session(state_hash).ok();
}

#[tokio::test]
async fn test_multiple_sessions_isolation() {
    if !keyring_available() {
        eprintln!("Skipping test: keyring not available");
        return;
    }

    let storage = KeyringPkceStorage;
    let state_hash_1 = format!("{}-1", test_state_hash());
    let state_hash_2 = format!("{}-2", test_state_hash());

    let session_data_1 = r#"{"verifier":"verifier-1","state":"state-1","provider":"Google"}"#;
    let session_data_2 = r#"{"verifier":"verifier-2","state":"state-2","provider":"GitHub"}"#;

    storage.delete_session(&state_hash_1).ok();
    storage.delete_session(&state_hash_2).ok();

    storage
        .save_session(&state_hash_1, session_data_1)
        .expect("Failed to save session 1");
    storage
        .save_session(&state_hash_2, session_data_2)
        .expect("Failed to save session 2");

    let retrieved_1 = storage
        .get_session(&state_hash_1)
        .expect("Should retrieve session 1");
    let retrieved_2 = storage
        .get_session(&state_hash_2)
        .expect("Should retrieve session 2");

    assert_eq!(retrieved_1, Some(session_data_1.to_string()));
    assert_eq!(retrieved_2, Some(session_data_2.to_string()));

    storage
        .delete_session(&state_hash_1)
        .expect("Failed to delete session 1");

    let check_1 = storage.get_session(&state_hash_1);
    let check_2 = storage.get_session(&state_hash_2);

    assert_eq!(check_1.unwrap(), None, "Session 1 should be deleted");
    assert_eq!(
        check_2.unwrap(),
        Some(session_data_2.to_string()),
        "Session 2 should still exist"
    );

    storage.delete_session(&state_hash_2).ok();
}

#[tokio::test]
async fn test_keyring_storage_trait_interface() {
    if !keyring_available() {
        eprintln!("Skipping test: keyring not available");
        return;
    }

    let storage = KeyringPkceStorage;
    let state_hash = test_state_hash();
    let session_json = r#"{"verifier":"trait-test","state":"test","provider":"Google"}"#;

    storage.delete_session(&state_hash).ok();

    let save_result = storage.save_session(&state_hash, session_json);
    assert!(save_result.is_ok(), "Save should succeed");

    let get_result = storage.get_session(&state_hash);
    assert!(get_result.is_ok(), "Get should succeed");
    assert_eq!(get_result.unwrap(), Some(session_json.to_string()));

    let delete_result = storage.delete_session(&state_hash);
    assert!(delete_result.is_ok(), "Delete should succeed");

    let get_after_delete = storage.get_session(&state_hash);
    assert_eq!(get_after_delete.unwrap(), None);
}

#[tokio::test]
async fn test_concurrent_access() {
    if !keyring_available() {
        eprintln!("Skipping test: keyring not available");
        return;
    }

    let storage = Arc::new(KeyringPkceStorage);
    let state_hash = test_state_hash();
    let session_data = r#"{"verifier":"concurrent-test","state":"test","provider":"Google"}"#;

    storage
        .save_session(&state_hash, session_data)
        .expect("Failed to set initial session");

    let mut handles = vec![];
    for _ in 0..5 {
        let storage_clone = Arc::clone(&storage);
        let state_hash_clone = state_hash.clone();
        let handle =
            tokio::task::spawn_blocking(move || storage_clone.get_session(&state_hash_clone));
        handles.push(handle);
    }

    for handle in handles {
        let result = handle.await.expect("Task should not panic");
        assert!(result.is_ok(), "Concurrent read should succeed");
        assert_eq!(result.unwrap(), Some(session_data.to_string()));
    }

    storage.delete_session(&state_hash).ok();
}
