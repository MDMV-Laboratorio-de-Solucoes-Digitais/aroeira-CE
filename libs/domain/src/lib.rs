//! Domain layer - pure business logic with no external dependencies.
//!
//! This crate defines traits (ports) for repositories and services,
//! along with domain entities and error types.

// Allow async fn in traits - we use native async fn instead of async_trait
// because we now use enum dispatch instead of dyn Trait for dependency injection.
#![allow(async_fn_in_trait)]

pub mod modules {
    pub mod auth;
    pub mod notes;
}
