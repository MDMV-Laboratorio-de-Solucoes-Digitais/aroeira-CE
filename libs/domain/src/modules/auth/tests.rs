#[cfg(test)]
use super::*;
use proptest::prelude::*;
use uuid::Uuid;

#[test]
fn test_user_creation() {
    let id = Uuid::new_v4();
    let email = "test@example.com".to_string();
    let user = User {
        id,
        email: email.clone(),
        password_hash: "hashed_secret".to_string(),
        email_verified: false,
        verification_token: None,
        verification_token_expires_at: None,
    };

    assert_eq!(user.id, id);
    assert_eq!(user.email, email);
}

#[test]
fn test_auth_error_display() {
    let err = AuthError::UserNotFound;
    assert_eq!(err.to_string(), "User not found");

    let err = AuthError::EmailServiceError("Connection failed".to_string());
    assert_eq!(err.to_string(), "Email service error: Connection failed");
}

proptest! {
    #[test]
    fn test_user_serialization_roundtrip(
        id_bytes in prop::array::uniform16(0u8..255),
        email in "[a-z0-9]+@[a-z]+\\.[a-z]+", // Simplified email regex for pbt
        is_verified in prop::bool::ANY,
    ) {
        let id = Uuid::from_bytes(id_bytes);
        let user = User {
            id,
            email,
            password_hash: "secret".to_string(), // Skipped in serde
            email_verified: is_verified,
            verification_token: None, // Skipped in serde
            verification_token_expires_at: None, // Skipped in serde
        };

        let serialized = serde_json::to_string(&user).unwrap();
        let deserialized: User = serde_json::from_str(&serialized).unwrap();

        assert_eq!(user.id, deserialized.id);
        assert_eq!(user.email, deserialized.email);
        assert_eq!(user.email_verified, deserialized.email_verified);
    }
}
