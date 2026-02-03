use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub email: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub password_hash: String,
    pub email_verified: bool,
    #[serde(skip_serializing, skip_deserializing)]
    pub verification_token: Option<String>,
    #[serde(skip_serializing, skip_deserializing)]
    pub verification_token_expires_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::notes::Entity")]
    Notes,
}

impl Related<super::notes::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Notes.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
