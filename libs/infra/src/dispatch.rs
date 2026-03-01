//! Enum dispatch for domain traits.
//!
//! This module provides enum wrappers for trait implementations, enabling
//! static dispatch instead of dynamic dispatch (`dyn Trait`). This allows
//! using native async fn in traits without requiring object safety.
//!
//! # Design
//!
//! Each enum wraps all known implementations of a trait and delegates
//! method calls to the inner type via pattern matching. This provides:
//! - Zero runtime overhead (no vtable lookups)
//! - Compile-time type safety
//! - Support for non-object-safe trait methods (async fn in traits)

use crate::database::repositories::{note_repo::NoteRepositoryImpl, user_repo::UserRepositoryImpl};
use crate::services::email::{MockEmailService, SmtpEmailService};
use domain::modules::auth::{AuthError, EmailService, User, UserRepository};
use domain::modules::notes::{Note, NoteError, NoteRepository};
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use uuid::Uuid;

// ===========================================
// UserRepositoryEnum
// ===========================================

/// Enum wrapper for `UserRepository` implementations.
///
/// Provides static dispatch over `UserRepositoryImpl` (production) and
/// `MockUserRepository` (testing).
pub enum UserRepositoryEnum {
    /// Production implementation using `SeaORM`.
    Production(UserRepositoryImpl),
    /// Mock implementation for testing.
    Mock(MockUserRepository),
}

impl UserRepositoryEnum {
    /// Creates a new production `UserRepository` with the given database connection.
    #[must_use]
    pub fn new_production(db: Arc<DatabaseConnection>) -> Self {
        Self::Production(UserRepositoryImpl::new(db))
    }

    /// Creates a new mock `UserRepository` for testing.
    #[must_use]
    pub fn new_mock() -> Self {
        Self::Mock(MockUserRepository::new())
    }
}

impl UserRepository for UserRepositoryEnum {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        match self {
            Self::Production(repo) => repo.find_by_email(email).await,
            Self::Mock(mock) => mock.find_by_email(email).await,
        }
    }

    async fn save(&self, user: &User) -> Result<User, AuthError> {
        match self {
            Self::Production(repo) => repo.save(user).await,
            Self::Mock(mock) => mock.save(user).await,
        }
    }

    async fn find_by_verification_token(&self, token: &str) -> Result<Option<User>, AuthError> {
        match self {
            Self::Production(repo) => repo.find_by_verification_token(token).await,
            Self::Mock(mock) => mock.find_by_verification_token(token).await,
        }
    }

    async fn update_verification_status(
        &self,
        user_id: Uuid,
        verified: bool,
        token: Option<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), AuthError> {
        match self {
            Self::Production(repo) => {
                repo.update_verification_status(user_id, verified, token, expires_at)
                    .await
            }
            Self::Mock(mock) => {
                mock.update_verification_status(user_id, verified, token, expires_at)
                    .await
            }
        }
    }

    async fn update(&self, user: &User) -> Result<User, AuthError> {
        match self {
            Self::Production(repo) => repo.update(user).await,
            Self::Mock(mock) => mock.update(user).await,
        }
    }
}

// ===========================================
// MockUserRepository
// ===========================================

/// Mock implementation of `UserRepository` for testing.
///
/// This implementation returns `None` for most queries and errors for
/// write operations, suitable for unit tests that don't need persistence.
pub struct MockUserRepository {
    /// In-memory storage for testing specific scenarios.
    users: std::sync::RwLock<std::collections::HashMap<String, User>>,
}

impl MockUserRepository {
    /// Creates a new empty mock repository.
    #[must_use]
    pub fn new() -> Self {
        Self {
            users: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Creates a mock repository pre-populated with users.
    #[must_use]
    pub fn with_users(users: Vec<User>) -> Self {
        let map = users.into_iter().map(|u| (u.email.clone(), u)).collect();
        Self {
            users: std::sync::RwLock::new(map),
        }
    }

    /// Inserts a user into the mock storage.
    ///
    /// # Panics
    ///
    /// Panics if the `RwLock` is poisoned.
    pub fn insert_user(&self, user: User) {
        self.users.write().unwrap().insert(user.email.clone(), user);
    }
}

impl Default for MockUserRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl UserRepository for MockUserRepository {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let users = self.users.read().unwrap();
        Ok(users.get(email).cloned())
    }

    async fn save(&self, user: &User) -> Result<User, AuthError> {
        let mut users = self.users.write().unwrap();
        users.insert(user.email.clone(), user.clone());
        Ok(user.clone())
    }

    async fn find_by_verification_token(&self, token: &str) -> Result<Option<User>, AuthError> {
        // For simplicity, search through all users for the token
        let users = self.users.read().unwrap();
        Ok(users
            .values()
            .find(|u| u.verification_token.as_deref() == Some(token))
            .cloned())
    }

    async fn update_verification_status(
        &self,
        user_id: Uuid,
        verified: bool,
        token: Option<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), AuthError> {
        let mut users = self.users.write().unwrap();
        for user in users.values_mut() {
            if user.id == user_id {
                user.email_verified = verified;
                user.verification_token = token;
                user.verification_token_expires_at = expires_at;
                return Ok(());
            }
        }
        Err(AuthError::UserNotFound)
    }

    async fn update(&self, user: &User) -> Result<User, AuthError> {
        let mut users = self.users.write().unwrap();
        if users.contains_key(&user.email) {
            users.insert(user.email.clone(), user.clone());
            Ok(user.clone())
        } else {
            Err(AuthError::UserNotFound)
        }
    }
}

// ===========================================
// NoteRepositoryEnum
// ===========================================

/// Enum wrapper for `NoteRepository` implementations.
///
/// Provides static dispatch over `NoteRepositoryImpl` (production) and
/// `MockNoteRepository` (testing).
pub enum NoteRepositoryEnum {
    /// Production implementation using `SeaORM`.
    Production(NoteRepositoryImpl),
    /// Mock implementation for testing.
    Mock(MockNoteRepository),
}

impl NoteRepositoryEnum {
    /// Creates a new production `NoteRepository` with the given database connection.
    #[must_use]
    pub fn new_production(db: Arc<DatabaseConnection>) -> Self {
        Self::Production(NoteRepositoryImpl::new(db))
    }

    /// Creates a new mock `NoteRepository` for testing.
    #[must_use]
    pub fn new_mock() -> Self {
        Self::Mock(MockNoteRepository::new())
    }
}

impl NoteRepository for NoteRepositoryEnum {
    async fn find_all_by_user(&self, user_id: Uuid) -> Result<Vec<Note>, NoteError> {
        match self {
            Self::Production(repo) => repo.find_all_by_user(user_id).await,
            Self::Mock(mock) => mock.find_all_by_user(user_id).await,
        }
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Note>, NoteError> {
        match self {
            Self::Production(repo) => repo.find_by_id(id).await,
            Self::Mock(mock) => mock.find_by_id(id).await,
        }
    }

    async fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Note>, NoteError> {
        match self {
            Self::Production(repo) => repo.find_by_id_and_user(id, user_id).await,
            Self::Mock(mock) => mock.find_by_id_and_user(id, user_id).await,
        }
    }

    async fn create(&self, note: &Note) -> Result<Note, NoteError> {
        match self {
            Self::Production(repo) => repo.create(note).await,
            Self::Mock(mock) => mock.create(note).await,
        }
    }

    async fn update(&self, note: &Note) -> Result<Note, NoteError> {
        match self {
            Self::Production(repo) => repo.update(note).await,
            Self::Mock(mock) => mock.update(note).await,
        }
    }

    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<(), NoteError> {
        match self {
            Self::Production(repo) => repo.delete(id, user_id).await,
            Self::Mock(mock) => mock.delete(id, user_id).await,
        }
    }
}

// ===========================================
// MockNoteRepository
// ===========================================

/// Mock implementation of `NoteRepository` for testing.
pub struct MockNoteRepository {
    notes: std::sync::RwLock<std::collections::HashMap<Uuid, Note>>,
}

impl MockNoteRepository {
    /// Creates a new empty mock repository.
    #[must_use]
    pub fn new() -> Self {
        Self {
            notes: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Adds a note to the mock storage.
    ///
    /// # Panics
    ///
    /// Panics if the `RwLock` is poisoned.
    pub fn add_note(&self, note: Note) {
        self.notes.write().unwrap().insert(note.id, note);
    }
}

impl Default for MockNoteRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteRepository for MockNoteRepository {
    async fn find_all_by_user(&self, user_id: Uuid) -> Result<Vec<Note>, NoteError> {
        let notes = self.notes.read().unwrap();
        Ok(notes
            .values()
            .filter(|n| n.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Note>, NoteError> {
        let notes = self.notes.read().unwrap();
        Ok(notes.get(&id).cloned())
    }

    async fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Note>, NoteError> {
        let notes = self.notes.read().unwrap();
        Ok(notes.get(&id).filter(|n| n.user_id == user_id).cloned())
    }

    async fn create(&self, note: &Note) -> Result<Note, NoteError> {
        let mut notes = self.notes.write().unwrap();
        notes.insert(note.id, note.clone());
        Ok(note.clone())
    }

    async fn update(&self, note: &Note) -> Result<Note, NoteError> {
        use std::collections::hash_map::Entry;

        let mut notes = self.notes.write().unwrap();
        match notes.entry(note.id) {
            Entry::Occupied(mut e) => {
                e.insert(note.clone());
                Ok(note.clone())
            }
            Entry::Vacant(_) => Err(NoteError::NotFound),
        }
    }

    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<(), NoteError> {
        let mut notes = self.notes.write().unwrap();
        if let Some(note) = notes.get(&id) {
            if note.user_id == user_id {
                notes.remove(&id);
                Ok(())
            } else {
                Err(NoteError::Forbidden)
            }
        } else {
            Err(NoteError::NotFound)
        }
    }
}

// ===========================================
// EmailServiceEnum
// ===========================================

/// Enum wrapper for `EmailService` implementations.
///
/// Provides static dispatch over `SmtpEmailService` (production) and
/// `MockEmailService` (development/testing).
pub enum EmailServiceEnum {
    /// Production SMTP email service.
    Smtp(SmtpEmailService),
    /// Mock email service for development and testing.
    Mock(MockEmailService),
}

impl EmailServiceEnum {
    /// Creates a new mock email service for development/testing.
    #[must_use]
    pub fn new_mock() -> Self {
        Self::Mock(MockEmailService::new())
    }

    /// Creates a new SMTP email service for production.
    #[must_use]
    pub fn new_smtp() -> Self {
        Self::Smtp(SmtpEmailService::new())
    }
}

impl EmailService for EmailServiceEnum {
    async fn send_verification_email(&self, email: &str, token: &str) -> Result<(), AuthError> {
        match self {
            Self::Smtp(service) => service.send_verification_email(email, token).await,
            Self::Mock(mock) => mock.send_verification_email(email, token).await,
        }
    }

    async fn send_existing_account_notification(&self, email: &str) -> Result<(), AuthError> {
        match self {
            Self::Smtp(service) => service.send_existing_account_notification(email).await,
            Self::Mock(mock) => mock.send_existing_account_notification(email).await,
        }
    }

    fn is_mock(&self) -> bool {
        match self {
            Self::Smtp(_) => false,
            Self::Mock(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_service_enum_is_mock() {
        let mock = EmailServiceEnum::new_mock();
        assert!(mock.is_mock());

        let smtp = EmailServiceEnum::new_smtp();
        assert!(!smtp.is_mock());
    }

    #[tokio::test]
    async fn test_mock_user_repository() {
        let repo = MockUserRepository::new();
        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            email_verified: false,
            verification_token: None,
            verification_token_expires_at: None,
        };

        repo.save(&user).await.unwrap();
        let found = repo.find_by_email("test@example.com").await.unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_mock_note_repository() {
        let repo = MockNoteRepository::new();
        let user_id = Uuid::new_v4();
        let note = Note {
            id: Uuid::new_v4(),
            user_id,
            title: "Test".to_string(),
            content: "Content".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        repo.create(&note).await.unwrap();
        let found = repo.find_all_by_user(user_id).await.unwrap();
        assert_eq!(found.len(), 1);
    }
}
