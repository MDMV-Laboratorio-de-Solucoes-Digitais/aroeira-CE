pub mod oauth;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub password_hash: String,
    pub email_verified: bool,
    #[serde(skip_serializing, skip_deserializing)]
    pub verification_token: Option<String>,
    #[serde(skip_serializing, skip_deserializing)]
    pub verification_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Email already exists")]
    EmailAlreadyExists,
    #[error("Email not verified")]
    EmailNotVerified,
    #[error("Invalid verification token")]
    InvalidVerificationToken,
    #[error("Email service error: {0}")]
    EmailServiceError(String),
    #[error("Repository error: {0}")]
    RepositoryError(String),
}

// Port (Interface)
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
    async fn save(&self, user: &User) -> Result<User, AuthError>;
    async fn find_by_verification_token(&self, token: &str) -> Result<Option<User>, AuthError>;

    /// Atomically updates a user's verification status and token.
    /// This prevents race conditions by only updating specific fields.
    async fn update_verification_status(
        &self,
        user_id: Uuid,
        verified: bool,
        token: Option<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), AuthError>;

    /// Legacy update method - Use with caution, prone to race conditions.
    /// Deprecated: Preferred to use specialized atomic update methods.
    async fn update(&self, user: &User) -> Result<User, AuthError>;
}

/// Email service trait for sending verification and notification emails.
/// Implementations can be mock (for development) or real (for production).
#[async_trait]
pub trait EmailService: Send + Sync {
    /// Send verification email to new user
    async fn send_verification_email(&self, email: &str, token: &str) -> Result<(), AuthError>;

    /// Send notification when someone tries to register with an existing email
    async fn send_existing_account_notification(&self, email: &str) -> Result<(), AuthError>;

    /// Returns true if this is a mock implementation (verification not required)
    fn is_mock(&self) -> bool;
}
#[cfg(test)]
mod tests;
