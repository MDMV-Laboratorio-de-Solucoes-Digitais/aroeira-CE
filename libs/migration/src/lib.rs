// Required: sea-orm-migration trait uses elided lifetimes
#![allow(elided_lifetimes_in_paths)]

pub use sea_orm_migration::prelude::*;
pub use sea_orm_migration::{MigrationTrait, MigratorTrait};

mod migration_20220101_create_table;
mod migration_20250210_rename_owner_to_user;

#[derive(Clone, Copy, Debug)]
pub struct Migrator;

impl MigratorTrait for Migrator {
    #[inline]
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(migration_20220101_create_table::Migration),
            Box::new(migration_20250210_rename_owner_to_user::Migration),
        ]
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
