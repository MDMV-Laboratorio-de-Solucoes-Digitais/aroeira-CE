pub mod database;
pub mod device_identifier;
pub mod security;
pub mod services;
pub mod utils;

pub use services::email::{MockEmailService, SmtpEmailService};

#[must_use]
pub fn hello() -> String {
    "Hello from Infra".to_string()
}
