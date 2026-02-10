use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Users Table
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Users::Id).string().not_null().primary_key())
                    .col(
                        ColumnDef::new(Users::Email)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Users::PasswordHash).string().not_null())
                    .col(
                        ColumnDef::new(Users::EmailVerified)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Users::VerificationToken).string())
                    .col(ColumnDef::new(Users::VerificationTokenExpiresAt).date_time())
                    .to_owned(),
            )
            .await?;

        // Notes Table
        manager
            .create_table(
                Table::create()
                    .table(Notes::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Notes::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Notes::Title).string().not_null())
                    .col(ColumnDef::new(Notes::Content).string().not_null())
                    .col(ColumnDef::new(Notes::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(Notes::UpdatedAt).date_time().not_null())
                    .col(ColumnDef::new(Notes::OwnerId).string().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-notes-owner_id")
                            .from(Notes::Table, Notes::OwnerId)
                            .to(Users::Table, Users::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Notes::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Email,
    PasswordHash,
    EmailVerified,
    VerificationToken,
    VerificationTokenExpiresAt,
}

#[derive(DeriveIden)]
enum Notes {
    Table,
    Id,
    Title,
    Content,
    CreatedAt,
    UpdatedAt,
    OwnerId,
}
