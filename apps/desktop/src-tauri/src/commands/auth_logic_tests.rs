use super::*;
use crate::services::secure_storage::SecureStorage;
use async_trait::async_trait;
use domain::modules::auth::{AuthError, EmailService, User, UserRepository};
use domain::modules::notes::{Note, NoteError, NoteRepository};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

// Mock Secure Storage
struct MockSecureStorage {
    storage: Arc<RwLock<HashMap<String, String>>>,
    should_fail: bool,
}

impl MockSecureStorage {
    fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            should_fail: false,
        }
    }

    fn new_failing() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            should_fail: true,
        }
    }
}

#[async_trait]
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

// Helper to create a mock AppState with specific secure storage
fn create_mock_state_with_storage(secure_storage: Arc<dyn SecureStorage>) -> AppState {
    let user_repo = Arc::new(MockUserRepository::new());
    let note_repo = Arc::new(MockNoteRepository::new());
    let email_service = Arc::new(MockEmailService::new());

    AppState {
        user_repo,
        note_repo,
        email_service,
        secure_storage,
        jwt_secret: secrecy::SecretBox::new("test_secret".to_string().into_boxed_str()),
        password_min_length: 8,
        jwt_expiration_hours: 24,
        jwt_issuer: "test_issuer".to_string(),
        jwt_audience: "test_audience".to_string(),
        rate_limit_key: secrecy::SecretBox::new(
            "0123456789abcdef0123456789abcdef"
                .to_string()
                .into_boxed_str(),
        ),
        login_attempts: Arc::new(Mutex::new(HashMap::new())),
        global_login_attempts: Arc::new(Mutex::new(RateLimitEntry::new())),
        device_login_attempts: Arc::new(Mutex::new(HashMap::new())),
        register_attempts: Arc::new(Mutex::new(HashMap::new())),
        global_register_attempts: Arc::new(Mutex::new(RateLimitEntry::new())),
        device_register_attempts: Arc::new(Mutex::new(HashMap::new())),
        password_security_level: crate::PasswordSecurityLevel::Secure,
    }
}

// Minimal Mocks for dependencies not being tested here
struct MockUserRepository;
impl MockUserRepository {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl UserRepository for MockUserRepository {
    async fn find_by_email(&self, _email: &str) -> Result<Option<User>, AuthError> {
        Ok(None)
    }
    async fn save(&self, _user: &User) -> Result<User, AuthError> {
        // Not required for currently implemented tests. Returning error instead of panic.
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
        // Not required for currently implemented tests. Returning error instead of panic.
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

#[async_trait]
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

#[async_trait]
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
    let mock_storage = Arc::new(MockSecureStorage::new());
    let state = create_mock_state_with_storage(mock_storage.clone());

    // Simulate existing rate limit entries
    let user_id = Uuid::new_v4();
    let email_hash = "test_hash";
    let device_id = "test_device";

    // Add failing entries
    {
        state
            .login_attempts
            .lock()
            .await
            .insert(email_hash.to_string(), RateLimitEntry::new());
        state
            .global_login_attempts
            .lock()
            .await
            .add_attempt(Instant::now(), Duration::from_secs(60));
        state
            .device_login_attempts
            .lock()
            .await
            .insert(device_id.to_string(), RateLimitEntry::new());
    }

    // Call handle_successful_login
    // Note: create_mock_state_with_storage returns AppState, but handle_successful_login takes &AppState
    let result = handle_successful_login(user_id, email_hash, device_id, &state).await;

    assert!(result.is_ok());

    // Verify token is stored
    let stored_token = mock_storage
        .get(crate::services::secure_storage::AUTH_TOKEN_KEY)
        .await
        .unwrap();
    assert!(stored_token.is_some());

    // Verify rate limits are cleared
    assert!(!state.login_attempts.lock().await.contains_key(email_hash));
    assert!(
        !state
            .device_login_attempts
            .lock()
            .await
            .contains_key(device_id)
    );
}

#[tokio::test]
async fn test_handle_successful_login_fails_if_storage_fails() {
    let mock_storage = Arc::new(MockSecureStorage::new_failing());
    let state = create_mock_state_with_storage(mock_storage);

    let user_id = Uuid::new_v4();
    let email_hash = "test_hash";
    let device_id = "test_device";

    let result = handle_successful_login(user_id, email_hash, device_id, &state).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Failed to store authentication token"));
}
