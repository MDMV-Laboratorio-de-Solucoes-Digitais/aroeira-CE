pub use sea_orm_migration::prelude::*;

mod m20220101_000001_create_table;
mod m20250210_000002_rename_owner_to_user;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_create_table::Migration),
            Box::new(m20250210_000002_rename_owner_to_user::Migration),
        ]
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
