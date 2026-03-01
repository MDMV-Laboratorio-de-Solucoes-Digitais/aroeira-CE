use super::*;
use crate::services::secure_storage::SecureStorageEnum;
use domain::modules::auth::{AuthError, EmailService, User, UserRepository};
use domain::modules::notes::{Note, NoteError, NoteRepository};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

struct MockUserRepository;
impl MockUserRepository {
    fn new() -> Self {
        Self
    }
}

impl UserRepository for MockUserRepository {
    async fn find_by_email(&self, _email: &str) -> Result<Option<User>, AuthError> {
        Ok(None)
    }
    async fn save(&self, _user: &User) -> Result<User, AuthError> {
        Err(AuthError::RepositoryError(
            "Mock UserRepository::save not implemented".to_string(),
        ))
    }
    async fn find_by_verification_token(&self, _token: &str) -> Result<Option<User>, AuthError> {
        Ok(None)
    }

    async fn update_verification_status(
        &self,
        _user_id: Uuid,
        _verified: bool,
        _token: Option<String>,
        _expires: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    async fn update(&self, _user: &User) -> Result<User, AuthError> {
        Err(AuthError::RepositoryError(
            "Mock UserRepository::update not implemented".to_string(),
        ))
    }
}

struct MockNoteRepository;
impl MockNoteRepository {
    fn new() -> Self {
        Self
    }
}

impl NoteRepository for MockNoteRepository {
    async fn find_all_by_user(&self, _user_id: Uuid) -> Result<Vec<Note>, NoteError> {
        Err(NoteError::RepositoryError(
            "Mock find_all_by_user unimplemented".to_string(),
        ))
    }
    async fn find_by_id(&self, _id: Uuid) -> Result<Option<Note>, NoteError> {
        Err(NoteError::RepositoryError(
            "Mock find_by_id unimplemented".to_string(),
        ))
    }
    async fn find_by_id_and_user(
        &self,
        _id: Uuid,
        _user_id: Uuid,
    ) -> Result<Option<Note>, NoteError> {
        Err(NoteError::RepositoryError(
            "Mock find_by_id_and_user unimplemented".to_string(),
        ))
    }
    async fn create(&self, _note: &Note) -> Result<Note, NoteError> {
        Err(NoteError::RepositoryError(
            "Mock create unimplemented".to_string(),
        ))
    }
    async fn update(&self, _note: &Note) -> Result<Note, NoteError> {
        Err(NoteError::RepositoryError(
            "Mock update unimplemented".to_string(),
        ))
    }
    async fn delete(&self, _id: Uuid, _user_id: Uuid) -> Result<(), NoteError> {
        Err(NoteError::RepositoryError(
            "Mock delete unimplemented".to_string(),
        ))
    }
}

struct MockEmailService;
impl MockEmailService {
    fn new() -> Self {
        Self
    }
}

impl EmailService for MockEmailService {
    async fn send_verification_email(&self, _email: &str, _token: &str) -> Result<(), AuthError> {
        Ok(())
    }
    async fn send_existing_account_notification(&self, _email: &str) -> Result<(), AuthError> {
        Ok(())
    }
    fn is_mock(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn test_handle_successful_login_stores_token_and_clears_limits() {
    let mock_storage =
        SecureStorageEnum::Mock(crate::services::secure_storage::MockSecureStorage::new());
    let login_attempts = Arc::new(Mutex::new(HashMap::new()));
    let global_login_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_login_attempts = Arc::new(Mutex::new(HashMap::new()));

    let user_id = Uuid::new_v4();
    let email_hash = "test_hash";
    let device_id = "test_device";

    {
        login_attempts
            .lock()
            .await
            .insert(email_hash.to_string(), RateLimitEntry::new());
        global_login_attempts
            .lock()
            .await
            .add_attempt(Instant::now(), Duration::from_secs(60));
        device_login_attempts
            .lock()
            .await
            .insert(device_id.to_string(), RateLimitEntry::new());
    }

    let context = LoginContext {
        secure_storage: &mock_storage,
        jwt_secret: "test_secret",
        jwt_expiration_hours: 24,
        jwt_issuer: "test_issuer",
        jwt_audience: "test_audience",
        global_login_attempts: &global_login_attempts,
        device_login_attempts: &device_login_attempts,
        login_attempts: &login_attempts,
    };

    let result = handle_successful_login(user_id, email_hash, device_id, &context).await;

    assert!(result.is_ok());

    let stored_token = mock_storage
        .get(crate::services::secure_storage::AUTH_TOKEN_KEY)
        .await
        .unwrap();
    assert!(stored_token.is_some());

    assert!(!login_attempts.lock().await.contains_key(email_hash));
    assert!(!device_login_attempts.lock().await.contains_key(device_id));
}

#[tokio::test]
async fn test_handle_successful_login_fails_if_storage_fails() {
    let mock_storage =
        SecureStorageEnum::Mock(crate::services::secure_storage::MockSecureStorage::new_failing());
    let login_attempts = Arc::new(Mutex::new(HashMap::new()));
    let global_login_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_login_attempts = Arc::new(Mutex::new(HashMap::new()));

    let user_id = Uuid::new_v4();
    let email_hash = "test_hash";
    let device_id = "test_device";

    let context = LoginContext {
        secure_storage: &mock_storage,
        jwt_secret: "test_secret",
        jwt_expiration_hours: 24,
        jwt_issuer: "test_issuer",
        jwt_audience: "test_audience",
        global_login_attempts: &global_login_attempts,
        device_login_attempts: &device_login_attempts,
        login_attempts: &login_attempts,
    };

    let result = handle_successful_login(user_id, email_hash, device_id, &context).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Failed to store authentication token"));
}
