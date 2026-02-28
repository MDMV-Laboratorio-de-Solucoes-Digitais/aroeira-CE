use crate::database::entities::users;
use crate::database::utils::is_unique_constraint_violation;
use crate::utils::encode_hex;
use chrono::Utc;
use domain::modules::auth::{AuthError, User, UserRepository};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set, prelude::*};
use std::sync::Arc;

// Implement From trait to convert from SeaORM Model to domain User
impl From<users::Model> for User {
    fn from(model: users::Model) -> Self {
        Self {
            id: model.id,
            email: model.email,
            password_hash: model.password_hash,
            email_verified: model.email_verified,
            verification_token: model.verification_token,
            verification_token_expires_at: model
                .verification_token_expires_at
                .map(|dt| dt.with_timezone(&Utc)),
        }
    }
}

pub struct UserRepositoryImpl {
    db: Arc<DatabaseConnection>,
}

impl UserRepositoryImpl {
    #[must_use]
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

impl UserRepository for UserRepositoryImpl {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let model = users::Entity::find()
            .filter(users::Column::Email.eq(email))
            .one(self.db.as_ref())
            .await
            .map_err(|e| AuthError::RepositoryError(e.to_string()))?;

        Ok(model.map(User::from))
    }

    async fn save(&self, user: &User) -> Result<User, AuthError> {
        let active_model = users::ActiveModel {
            id: Set(user.id),
            email: Set(user.email.clone()),
            password_hash: Set(user.password_hash.clone()),
            email_verified: Set(user.email_verified),
            verification_token: Set(user.verification_token.clone()),
            verification_token_expires_at: Set(user.verification_token_expires_at.map(|dt| {
                dt.with_timezone(
                    &chrono::FixedOffset::east_opt(0).expect("FixedOffset::east(0) is valid"),
                )
            })),
        };

        match users::Entity::insert(active_model)
            .exec(self.db.as_ref())
            .await
        {
            Ok(_) => Ok(user.clone()),
            Err(e) => {
                if is_unique_constraint_violation(&e) {
                    return Err(AuthError::EmailAlreadyExists);
                }
                Err(AuthError::RepositoryError(e.to_string()))
            }
        }
    }

    async fn find_by_verification_token(&self, token: &str) -> Result<Option<User>, AuthError> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = encode_hex(hasher.finalize());

        let model = users::Entity::find()
            .filter(users::Column::VerificationToken.eq(token_hash))
            .one(self.db.as_ref())
            .await
            .map_err(|e| AuthError::RepositoryError(e.to_string()))?;

        Ok(model.map(User::from))
    }

    async fn update_verification_status(
        &self,
        user_id: Uuid,
        verified: bool,
        token: Option<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), AuthError> {
        let active_model = users::ActiveModel {
            email_verified: Set(verified),
            verification_token: Set(token),
            verification_token_expires_at: Set(expires_at.map(|dt| {
                dt.with_timezone(
                    &chrono::FixedOffset::east_opt(0).expect("FixedOffset::east(0) is valid"),
                )
            })),
            ..Default::default()
        };

        let res = users::Entity::update_many()
            .set(active_model)
            .filter(users::Column::Id.eq(user_id))
            .exec(self.db.as_ref())
            .await
            .map_err(|e| AuthError::RepositoryError(e.to_string()))?;

        if res.rows_affected == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }

    async fn update(&self, user: &User) -> Result<User, AuthError> {
        let active_model = users::ActiveModel {
            id: Set(user.id),
            email: Set(user.email.clone()),
            password_hash: Set(user.password_hash.clone()),
            email_verified: Set(user.email_verified),
            verification_token: Set(user.verification_token.clone()),
            verification_token_expires_at: Set(user.verification_token_expires_at.map(|dt| {
                dt.with_timezone(
                    &chrono::FixedOffset::east_opt(0).expect("FixedOffset::east(0) is valid"),
                )
            })),
        };

        users::Entity::update(active_model)
            .exec(self.db.as_ref())
            .await
            .map_err(|e| AuthError::RepositoryError(e.to_string()))?;

        Ok(user.clone())
    }
}
