pub mod constants;
pub mod database;
pub mod device_identifier;
pub mod dispatch;
pub mod security;
pub mod services;
pub mod utils;

pub use dispatch::{
    EmailServiceEnum, MockNoteRepository, MockUserRepository, NoteRepositoryEnum,
    UserRepositoryEnum,
};
pub use services::email::{MockEmailService, SmtpEmailService};

#[must_use]
pub fn hello() -> String {
    "Hello from Infra".to_string()
}
