use crate::database::entities::notes;
use crate::database::utils::{is_foreign_key_violation, is_unique_constraint_violation};
use domain::modules::notes::{Note, NoteError, NoteRepository};
use sea_orm::prelude::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::sync::Arc;
use uuid::Uuid;

// Implement From trait to convert from SeaORM Model to domain Note
impl From<notes::Model> for Note {
    fn from(model: notes::Model) -> Self {
        Self {
            id: model.id,
            user_id: model.user_id,
            title: model.title,
            content: model.content,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

pub struct NoteRepositoryImpl {
    db: Arc<DatabaseConnection>,
}

impl NoteRepositoryImpl {
    #[must_use]
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl NoteRepository for NoteRepositoryImpl {
    async fn find_all_by_user(&self, user_id: Uuid) -> Result<Vec<Note>, NoteError> {
        let models = notes::Entity::find()
            .filter(notes::Column::UserId.eq(user_id))
            .all(self.db.as_ref())
            .await
            .map_err(|e| NoteError::RepositoryError(e.to_string()))?;

        Ok(models.into_iter().map(Note::from).collect())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Note>, NoteError> {
        let model = notes::Entity::find_by_id(id)
            .one(self.db.as_ref())
            .await
            .map_err(|e| NoteError::RepositoryError(e.to_string()))?;

        Ok(model.map(Note::from))
    }

    async fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Note>, NoteError> {
        let model = notes::Entity::find()
            .filter(notes::Column::Id.eq(id))
            .filter(notes::Column::UserId.eq(user_id))
            .one(self.db.as_ref())
            .await
            .map_err(|e| NoteError::RepositoryError(e.to_string()))?;

        Ok(model.map(Note::from))
    }

    async fn create(&self, note: &Note) -> Result<Note, NoteError> {
        let active_model = notes::ActiveModel {
            id: Set(note.id),
            user_id: Set(note.user_id),
            title: Set(note.title.clone()),
            content: Set(note.content.clone()),
            created_at: Set(note.created_at),
            updated_at: Set(note.updated_at),
        };

        match notes::Entity::insert(active_model)
            .exec(self.db.as_ref())
            .await
        {
            Ok(_) => Ok(note.clone()),
            Err(e) => {
                if is_foreign_key_violation(&e) {
                    tracing::warn!(
                        user_id = %note.user_id,
                        "Failed to insert note: User not found (FK violation)"
                    );
                    return Err(NoteError::UserNotFound(note.user_id.to_string()));
                }

                if is_unique_constraint_violation(&e) {
                    tracing::warn!(
                        note_id = %note.id,
                        attempted_user_id = %note.user_id,
                        "Failed to insert note due to unique constraint"
                    );
                    Err(NoteError::Conflict)
                } else {
                    tracing::error!(
                        error = %e.to_string(),
                        "Database error inserting note"
                    );
                    Err(NoteError::RepositoryError(e.to_string()))
                }
            }
        }
    }

    async fn update(&self, note: &Note) -> Result<Note, NoteError> {
        let update_res = notes::Entity::update_many()
            .filter(notes::Column::Id.eq(note.id))
            .filter(notes::Column::UserId.eq(note.user_id))
            .col_expr(notes::Column::Title, Expr::value(note.title.clone()))
            .col_expr(notes::Column::Content, Expr::value(note.content.clone()))
            .col_expr(notes::Column::UpdatedAt, Expr::value(note.updated_at))
            .exec(self.db.as_ref())
            .await
            .map_err(|e| NoteError::RepositoryError(e.to_string()))?;

        if update_res.rows_affected > 0 {
            // The update was successful, return the note object passed in.
            // This avoids an unnecessary round trip to the database.
            // The ownership was already verified by the WHERE clause filtering by user_id.
            Ok(note.clone())
        } else {
            // If no rows were affected, the note doesn't exist or doesn't belong to the user
            Err(NoteError::NotFound)
        }
    }

    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<(), NoteError> {
        let res = notes::Entity::delete_many()
            .filter(notes::Column::Id.eq(id))
            .filter(notes::Column::UserId.eq(user_id))
            .exec(self.db.as_ref())
            .await
            .map_err(|e| NoteError::RepositoryError(e.to_string()))?;

        if res.rows_affected == 0 {
            return Err(NoteError::NotFound);
        }
        Ok(())
    }
}
