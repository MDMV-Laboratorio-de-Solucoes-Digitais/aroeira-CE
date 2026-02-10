use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Notes::Table)
                    .rename_column(Notes::OwnerId, Notes::UserId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Notes::Table)
                    .rename_column(Notes::UserId, Notes::OwnerId)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Notes {
    Table,
    OwnerId,
    UserId,
}
