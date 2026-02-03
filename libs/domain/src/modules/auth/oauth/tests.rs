//! TDD RED PHASE: Tests written BEFORE any implementation exists.
//! These tests define the expected behavior of our OAuth types.
//! Running `cargo test -p domain` should FAIL to compile at this point.

#[cfg(test)]
use super::*;
use proptest::prelude::*;

// ===========================================
// AuthProvider Tests
// ===========================================

#[test]
fn auth_provider_google_serializes_to_lowercase() {
    let provider = AuthProvider::Google;
    let json = serde_json::to_string(&provider).unwrap();
    assert_eq!(json, "\"google\"");
}

#[test]
fn auth_provider_github_serializes_to_lowercase() {
    let provider = AuthProvider::GitHub;
    let json = serde_json::to_string(&provider).unwrap();
    assert_eq!(json, "\"github\"");
}

#[test]
fn auth_provider_deserializes_from_lowercase() {
    let google: AuthProvider = serde_json::from_str("\"google\"").unwrap();
    assert_eq!(google, AuthProvider::Google);

    let github: AuthProvider = serde_json::from_str("\"github\"").unwrap();
    assert_eq!(github, AuthProvider::GitHub);
}

#[test]
fn auth_provider_rejects_unknown_provider() {
    let result: Result<AuthProvider, _> = serde_json::from_str("\"facebook\"");
    assert!(result.is_err());
}

#[test]
fn auth_provider_display_shows_provider_name() {
    assert_eq!(AuthProvider::Google.to_string(), "Google");
    assert_eq!(AuthProvider::GitHub.to_string(), "GitHub");
}

// ===========================================
// OAuthError Tests
// ===========================================

#[test]
fn oauth_error_session_not_found_has_clear_message() {
    let err = OAuthError::SessionNotFound;
    assert_eq!(err.to_string(), "Session not found or expired");
}

#[test]
fn oauth_error_state_mismatch_warns_about_csrf() {
    let err = OAuthError::StateMismatch;
    assert!(err.to_string().contains("CSRF"));
}

#[test]
fn oauth_error_code_exchange_includes_reason() {
    let err = OAuthError::CodeExchangeFailed("token expired".to_string());
    assert!(err.to_string().contains("token expired"));
}

#[test]
fn oauth_error_provider_not_configured_includes_name() {
    let err = OAuthError::ProviderNotConfigured("Google".to_string());
    assert!(err.to_string().contains("Google"));
}

#[test]
fn oauth_error_token_request_includes_reason() {
    let err = OAuthError::TokenRequestFailed("network timeout".to_string());
    assert!(err.to_string().contains("network timeout"));
}

#[test]
fn oauth_error_user_info_includes_reason() {
    let err = OAuthError::UserInfoFailed("invalid response".to_string());
    assert!(err.to_string().contains("invalid response"));
}

// ===========================================
// OAuthPkceSession Tests
// ===========================================

#[test]
fn pkce_session_state_must_be_non_empty() {
    let session = OAuthPkceSession::new(
        String::new(),  // Empty state - invalid!
        "a".repeat(43), // Valid verifier
        AuthProvider::Google,
    );
    assert!(!session.is_valid());
}

#[test]
fn pkce_session_verifier_must_be_at_least_43_chars() {
    // PKCE spec: code_verifier must be 43-128 characters (RFC 7636)
    let session = OAuthPkceSession::new(
        "valid_state".to_string(),
        "short".to_string(), // Too short - only 5 chars!
        AuthProvider::Google,
    );
    assert!(!session.is_valid());
}

#[test]
fn pkce_session_verifier_must_not_exceed_128_chars() {
    let session = OAuthPkceSession::new(
        "valid_state".to_string(),
        "a".repeat(129), // Too long!
        AuthProvider::Google,
    );
    assert!(!session.is_valid());
}

#[test]
fn pkce_session_valid_when_all_requirements_met() {
    let session = OAuthPkceSession::new(
        "random_state_123".to_string(),
        "a".repeat(43), // Exactly 43 chars - minimum valid
        AuthProvider::GitHub,
    );
    assert!(session.is_valid());
}

#[test]
fn pkce_session_valid_with_max_verifier_length() {
    let session = OAuthPkceSession::new(
        "random_state".to_string(),
        "a".repeat(128), // Exactly 128 chars - maximum valid
        AuthProvider::Google,
    );
    assert!(session.is_valid());
}

#[test]
fn pkce_session_expires_after_10_minutes() {
    use chrono::{Duration, Utc};

    let mut session =
        OAuthPkceSession::new("state".to_string(), "a".repeat(43), AuthProvider::Google);

    // Fresh session should not be expired
    assert!(!session.is_expired());

    // Simulate 11 minutes passing
    session.created_at = Utc::now() - Duration::minutes(11);
    assert!(session.is_expired());
}

#[test]
fn pkce_session_not_expired_just_before_10_minutes() {
    use chrono::{Duration, Utc};

    let mut session =
        OAuthPkceSession::new("state".to_string(), "a".repeat(43), AuthProvider::Google);

    // Just under 10 minutes (9 min 59 sec) should still be valid
    // Using 9 minutes 59 seconds to avoid timing race conditions
    session.created_at = Utc::now() - Duration::seconds(599);
    assert!(!session.is_expired());
}

#[test]
fn pkce_session_stores_correct_provider() {
    let google_session =
        OAuthPkceSession::new("state1".to_string(), "a".repeat(50), AuthProvider::Google);
    assert_eq!(google_session.provider, AuthProvider::Google);

    let github_session =
        OAuthPkceSession::new("state2".to_string(), "b".repeat(50), AuthProvider::GitHub);
    assert_eq!(github_session.provider, AuthProvider::GitHub);
}

// ===========================================
// OAuthUser Tests
// ===========================================

#[test]
fn oauth_user_creation_with_all_fields() {
    let user = OAuthUser {
        provider: AuthProvider::Google,
        provider_user_id: "google-12345".to_string(),
        email: "test@example.com".to_string(),
        name: Some("Test User".to_string()),
        avatar_url: Some("https://example.com/avatar.png".to_string()),
    };

    assert_eq!(user.provider, AuthProvider::Google);
    assert_eq!(user.provider_user_id, "google-12345");
    assert_eq!(user.email, "test@example.com");
    assert_eq!(user.name, Some("Test User".to_string()));
    assert!(user.avatar_url.is_some());
}

#[test]
fn oauth_user_creation_with_minimal_fields() {
    let user = OAuthUser {
        provider: AuthProvider::GitHub,
        provider_user_id: "gh-67890".to_string(),
        email: "user@github.com".to_string(),
        name: None,
        avatar_url: None,
    };

    assert_eq!(user.provider, AuthProvider::GitHub);
    assert!(user.name.is_none());
    assert!(user.avatar_url.is_none());
}

#[test]
fn oauth_user_serialization_includes_required_fields() {
    let user = OAuthUser {
        provider: AuthProvider::Google,
        provider_user_id: "12345".to_string(),
        email: "test@example.com".to_string(),
        name: Some("Test User".to_string()),
        avatar_url: None,
    };

    let json = serde_json::to_string(&user).unwrap();

    // Should include provider
    assert!(json.contains("google"));
    // Should include email
    assert!(json.contains("test@example.com"));
    // Should include name
    assert!(json.contains("Test User"));
}

#[test]
fn oauth_user_deserialization_works() {
    let json = r#"{
        "provider": "github",
        "provider_user_id": "gh-123",
        "email": "dev@github.com",
        "name": "Dev User",
        "avatar_url": "https://avatars.github.com/u/123"
    }"#;

    let user: OAuthUser = serde_json::from_str(json).unwrap();

    assert_eq!(user.provider, AuthProvider::GitHub);
    assert_eq!(user.provider_user_id, "gh-123");
    assert_eq!(user.email, "dev@github.com");
    assert_eq!(user.name, Some("Dev User".to_string()));
    assert_eq!(
        user.avatar_url,
        Some("https://avatars.github.com/u/123".to_string())
    );
}

// ===========================================
// Property-Based Tests (Edge Cases)
// ===========================================

proptest! {
    #[test]
    fn auth_provider_roundtrip_never_loses_data(
        is_google in prop::bool::ANY,
    ) {
        let provider = if is_google {
            AuthProvider::Google
        } else {
            AuthProvider::GitHub
        };

        let json = serde_json::to_string(&provider).unwrap();
        let restored: AuthProvider = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(provider, restored);
    }

    #[test]
    fn oauth_user_email_preserved_through_serialization(
        local_part in "[a-z0-9]{1,20}",
        domain in "[a-z]{2,10}\\.[a-z]{2,4}",
    ) {
        let email = format!("{}@{}", local_part, domain);

        let user = OAuthUser {
            provider: AuthProvider::Google,
            provider_user_id: "id123".to_string(),
            email: email.clone(),
            name: None,
            avatar_url: None,
        };

        let json = serde_json::to_string(&user).unwrap();
        let restored: OAuthUser = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(user.email, restored.email);
    }

    #[test]
    fn pkce_verifier_length_validation_is_strict(
        length in 0usize..200,
    ) {
        let verifier = "a".repeat(length);
        let session = OAuthPkceSession::new(
            "valid_state".to_string(),
            verifier,
            AuthProvider::Google,
        );

        // PKCE spec: 43-128 characters (RFC 7636)
        let expected_valid = (43..=128).contains(&length);
        prop_assert_eq!(session.is_valid(), expected_valid);
    }

    #[test]
    fn pkce_session_with_empty_state_is_always_invalid(
        verifier_len in 43usize..=128,
    ) {
        let session = OAuthPkceSession::new(
            String::new(), // Empty state
            "a".repeat(verifier_len),
            AuthProvider::GitHub,
        );

        prop_assert!(!session.is_valid());
    }

    #[test]
    fn oauth_user_name_optional_serialization(
        has_name in prop::bool::ANY,
        name_value in "[A-Za-z ]{1,50}",
    ) {
        let name = if has_name { Some(name_value) } else { None };

        let user = OAuthUser {
            provider: AuthProvider::Google,
            provider_user_id: "test-id".to_string(),
            email: "test@test.com".to_string(),
            name: name.clone(),
            avatar_url: None,
        };

        let json = serde_json::to_string(&user).unwrap();
        let restored: OAuthUser = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(user.name, restored.name);
    }
}
