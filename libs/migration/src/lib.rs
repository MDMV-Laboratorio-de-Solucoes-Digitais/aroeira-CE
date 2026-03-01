// Required: sea-orm-migration trait uses elided lifetimes
#![allow(elided_lifetimes_in_paths)]
// Migration crate is largely generated code; allow pedantic lints
#![allow(clippy::pub_use)]
#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::implicit_return)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::multiple_crate_versions)]

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
