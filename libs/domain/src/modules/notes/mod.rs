use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub id: Uuid,
    pub user_id: Uuid,
    pub title: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Error, Debug)]
pub enum NoteError {
    #[error("Note not found")]
    NotFound,
    #[error("Access forbidden: insufficient permissions")]
    Forbidden,
    #[error("Unauthorized: user does not have permission to access this resource")]
    Unauthorized,
    #[error("Resource conflict: the requested operation conflicts with existing data")]
    Conflict,
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Repository error: {0}")]
    RepositoryError(String),
}

// Port (Interface)
#[async_trait]
pub trait NoteRepository: Send + Sync {
    async fn find_all_by_user(&self, user_id: Uuid) -> Result<Vec<Note>, NoteError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Note>, NoteError>;
    async fn find_by_id_and_user(&self, id: Uuid, user_id: Uuid)
    -> Result<Option<Note>, NoteError>;
    async fn create(&self, note: &Note) -> Result<Note, NoteError>;
    async fn update(&self, note: &Note) -> Result<Note, NoteError>;
    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<(), NoteError>;
}
