use domain::modules::auth::{AuthError, EmailService};

/// Mock email service for development and testing.
/// Does not actually send emails, but logs the intent.
/// When using this service, email verification is not required.
pub struct MockEmailService;

impl MockEmailService {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for MockEmailService {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailService for MockEmailService {
    async fn send_verification_email(&self, _email: &str, _token: &str) -> Result<(), AuthError> {
        // SECURITY: Never log tokens, even partially, as this could aid attackers
        tracing::info!("Mock email service: would send verification email");
        Ok(())
    }

    async fn send_existing_account_notification(&self, _email: &str) -> Result<(), AuthError> {
        tracing::info!("Mock email service: would send existing account notification");
        Ok(())
    }

    fn is_mock(&self) -> bool {
        true
    }
}

/// Production-ready SMTP email service (Stub).
/// Currently returns errors as SMTP integration is not yet configured.
/// This prevents insecure fallback to Mock service in production.
pub struct SmtpEmailService;

impl SmtpEmailService {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for SmtpEmailService {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailService for SmtpEmailService {
    async fn send_verification_email(&self, _email: &str, _token: &str) -> Result<(), AuthError> {
        // Placeholder for real SMTP implementation
        tracing::error!("SMTP service not configured - cannot send verification email");
        Err(AuthError::EmailServiceError(
            "Email configuration missing".to_string(),
        ))
    }

    async fn send_existing_account_notification(&self, _email: &str) -> Result<(), AuthError> {
        tracing::error!("SMTP service not configured - cannot send notification email");
        Err(AuthError::EmailServiceError(
            "Email configuration missing".to_string(),
        ))
    }

    fn is_mock(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_email_service_is_mock() {
        let service = MockEmailService::new();
        assert!(service.is_mock());
    }

    #[tokio::test]
    async fn test_mock_email_service_send_verification() {
        let service = MockEmailService::new();
        let result = service
            .send_verification_email("test@example.com", "token123")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_email_service_send_notification() {
        let service = MockEmailService::new();
        let result = service
            .send_existing_account_notification("test@example.com")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_smtp_email_service_is_not_mock() {
        let service = SmtpEmailService::new();
        assert!(!service.is_mock());
    }
}
