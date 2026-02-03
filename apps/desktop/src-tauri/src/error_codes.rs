//! Error codes for structured error handling
//!
//! This module defines error codes that can be used throughout application
//! to provide programmatic error handling instead of relying on brittle string matching.
//!

use serde::{Deserialize, Serialize};

/// Error codes for different types of errors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    // Authentication errors
    /// Authentication token is missing or invalid
    AuthRequired,
    /// Invalid credentials provided
    InvalidCredentials,
    /// Token has expired
    TokenExpired,
    /// Token is malformed or invalid
    InvalidToken,
    /// Email has not been verified
    EmailNotVerified,

    // Rate limiting errors
    /// Too many requests - rate limit exceeded
    RateLimited,
    /// Too many attempts from this device
    DeviceRateLimited,
    /// Too many global attempts
    GlobalRateLimited,

    // Validation errors
    /// Invalid input data
    ValidationError,
    /// Invalid email format
    InvalidEmail,
    /// Invalid password format
    InvalidPassword,
    /// Passwords do not match
    PasswordsDoNotMatch,
    /// Invalid note ID format
    InvalidNoteId,

    // Resource errors
    /// Resource not found
    NotFound,
    /// Note not found
    NoteNotFound,
    /// User not found
    UserNotFound,

    // Authorization errors
    /// User is not authorized to perform this action
    Forbidden,
    /// Unauthorized access
    Unauthorized,

    // Conflict errors
    /// Resource already exists
    Conflict,
    /// Email already registered
    EmailExists,

    // Server errors
    /// Internal server error
    InternalError,
    /// Database error
    DatabaseError,
    /// Secure storage error
    SecureStorageError,
    /// Authentication service unavailable
    AuthUnavailable,

    // Network errors
    /// Network connection error
    NetworkError,
    /// Request timeout
    Timeout,

    // Configuration errors
    /// Invalid configuration
    InvalidConfig,
    /// Missing required configuration
    MissingConfig,
}

impl ErrorCode {
    /// Gets the HTTP status code associated with this error
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        match self {
            // Authentication errors -> 401
            Self::AuthRequired
            | Self::InvalidCredentials
            | Self::TokenExpired
            | Self::InvalidToken => 401,

            // Authorization errors -> 403
            Self::Forbidden | Self::Unauthorized | Self::EmailNotVerified => 403,

            // Not found errors -> 404
            Self::NotFound | Self::NoteNotFound | Self::UserNotFound => 404,

            // Conflict errors -> 409
            Self::Conflict | Self::EmailExists => 409,

            // Rate limiting errors -> 429
            Self::RateLimited | Self::DeviceRateLimited | Self::GlobalRateLimited => 429,

            // Validation errors -> 400
            Self::ValidationError
            | Self::InvalidEmail
            | Self::InvalidPassword
            | Self::PasswordsDoNotMatch
            | Self::InvalidNoteId => 400,

            // Server errors -> 500
            Self::InternalError
            | Self::DatabaseError
            | Self::SecureStorageError
            | Self::AuthUnavailable
            | Self::InvalidConfig
            | Self::MissingConfig => 500,

            // Network errors -> 502 or 504
            Self::NetworkError => 502,
            Self::Timeout => 504,
        }
    }

    /// Gets the default error message for this error code
    #[must_use]
    pub const fn default_message(&self) -> &'static str {
        match self {
            // Authentication errors
            Self::AuthRequired => "Authentication required",
            Self::InvalidCredentials => "Invalid credentials",
            Self::TokenExpired => "Token has expired",
            Self::InvalidToken => "Invalid token",
            Self::EmailNotVerified => "Email not verified",

            // Rate limiting errors
            Self::RateLimited => "Too many requests",
            Self::DeviceRateLimited => "Too many requests from this device",
            Self::GlobalRateLimited => "Too many global requests",

            // Validation errors
            Self::ValidationError => "Invalid input",
            Self::InvalidEmail => "Invalid email format",
            Self::InvalidPassword => "Invalid password format",
            Self::PasswordsDoNotMatch => "Passwords do not match",
            Self::InvalidNoteId => "Invalid note ID",

            // Resource errors
            Self::NotFound => "Resource not found",
            Self::NoteNotFound => "Note not found",
            Self::UserNotFound => "User not found",

            // Authorization errors
            Self::Forbidden => "Access forbidden",
            Self::Unauthorized => "Unauthorized access",

            // Conflict errors
            Self::Conflict => "Resource conflict",
            Self::EmailExists => "Email already registered",

            // Server errors
            Self::InternalError => "Internal server error",
            Self::DatabaseError => "Database error",
            Self::SecureStorageError => "Secure storage error",
            Self::AuthUnavailable => "Authentication service unavailable",

            // Network errors
            Self::NetworkError => "Network error",
            Self::Timeout => "Request timeout",

            // Configuration errors
            Self::InvalidConfig => "Invalid configuration",
            Self::MissingConfig => "Missing required configuration",
        }
    }

    /// Checks if this error is retryable
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited
                | Self::DeviceRateLimited
                | Self::GlobalRateLimited
                | Self::NetworkError
                | Self::Timeout
                | Self::InternalError
                | Self::DatabaseError
        )
    }

    /// Checks if this error is an authentication error
    #[must_use]
    pub const fn is_auth_error(&self) -> bool {
        matches!(
            self,
            Self::AuthRequired
                | Self::InvalidCredentials
                | Self::TokenExpired
                | Self::InvalidToken
                | Self::EmailNotVerified
        )
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant_name = match self {
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::InvalidToken => "INVALID_TOKEN",
            Self::EmailNotVerified => "EMAIL_NOT_VERIFIED",
            Self::RateLimited => "RATE_LIMITED",
            Self::DeviceRateLimited => "DEVICE_RATE_LIMITED",
            Self::GlobalRateLimited => "GLOBAL_RATE_LIMITED",
            Self::ValidationError => "VALIDATION_ERROR",
            Self::InvalidEmail => "INVALID_EMAIL",
            Self::InvalidPassword => "INVALID_PASSWORD",
            Self::PasswordsDoNotMatch => "PASSWORDS_DO_NOT_MATCH",
            Self::InvalidNoteId => "INVALID_NOTE_ID",
            Self::NotFound => "NOT_FOUND",
            Self::NoteNotFound => "NOTE_NOT_FOUND",
            Self::UserNotFound => "USER_NOT_FOUND",
            Self::Forbidden => "FORBIDDEN",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Conflict => "CONFLICT",
            Self::EmailExists => "EMAIL_EXISTS",
            Self::InternalError => "INTERNAL_ERROR",
            Self::DatabaseError => "DATABASE_ERROR",
            Self::SecureStorageError => "SECURE_STORAGE_ERROR",
            Self::AuthUnavailable => "AUTH_UNAVAILABLE",
            Self::NetworkError => "NETWORK_ERROR",
            Self::Timeout => "TIMEOUT",
            Self::InvalidConfig => "INVALID_CONFIG",
            Self::MissingConfig => "MISSING_CONFIG",
        };
        write!(f, "{variant_name}")
    }
}

/// Structured error response that includes an error code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The error code
    pub code: ErrorCode,
    /// Human-readable error message
    pub message: String,
    /// Optional additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ErrorResponse {
    /// Create a new error response with just a code
    #[must_use]
    pub fn from_code(code: ErrorCode) -> Self {
        Self {
            code,
            message: code.default_message().to_string(),
            details: None,
        }
    }

    /// Create a new error response with a code and custom message
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    /// Create a new error response with a code, message, and details
    pub fn with_details(
        code: ErrorCode,
        message: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            details: Some(details.into()),
        }
    }

    /// Convert to JSON string
    /// # Errors
    ///
    /// Returns an error if serialization fails
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse from JSON string
    /// # Errors
    ///
    /// Returns an error if deserialization fails
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl std::fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for ErrorResponse {}

/// Convert `ErrorCode` to `ErrorResponse`
impl From<ErrorCode> for ErrorResponse {
    fn from(code: ErrorCode) -> Self {
        Self::from_code(code)
    }
}

/// Convert `ErrorResponse` to String for Tauri commands
impl From<ErrorResponse> for String {
    fn from(err: ErrorResponse) -> Self {
        err.to_json().unwrap_or_else(|_| err.message.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_http_status() {
        assert_eq!(ErrorCode::AuthRequired.http_status(), 401);
        assert_eq!(ErrorCode::Forbidden.http_status(), 403);
        assert_eq!(ErrorCode::NotFound.http_status(), 404);
        assert_eq!(ErrorCode::RateLimited.http_status(), 429);
        assert_eq!(ErrorCode::InternalError.http_status(), 500);
    }

    #[test]
    fn test_error_code_default_message() {
        assert_eq!(
            ErrorCode::AuthRequired.default_message(),
            "Authentication required"
        );
        assert_eq!(
            ErrorCode::InvalidCredentials.default_message(),
            "Invalid credentials"
        );
    }

    #[test]
    fn test_is_retryable() {
        assert!(ErrorCode::RateLimited.is_retryable());
        assert!(ErrorCode::NetworkError.is_retryable());
        assert!(!ErrorCode::InvalidCredentials.is_retryable());
        assert!(!ErrorCode::ValidationError.is_retryable());
    }

    #[test]
    fn test_is_auth_error() {
        assert!(ErrorCode::AuthRequired.is_auth_error());
        assert!(ErrorCode::InvalidCredentials.is_auth_error());
        assert!(!ErrorCode::RateLimited.is_auth_error());
        assert!(!ErrorCode::ValidationError.is_auth_error());
    }

    #[test]
    fn test_error_response_serialization() {
        let err = ErrorResponse::from_code(ErrorCode::AuthRequired);
        let json = err.to_json().unwrap();
        assert!(json.contains("AUTH_REQUIRED"));
        assert!(json.contains("Authentication required"));
    }

    #[test]
    fn test_error_response_deserialization() {
        let json = r#"{"code":"AUTH_REQUIRED","message":"Authentication required","details":null}"#;
        let err = ErrorResponse::from_json(json).unwrap();
        assert_eq!(err.code, ErrorCode::AuthRequired);
        assert_eq!(err.message, "Authentication required");
    }

    #[test]
    fn test_error_response_with_details() {
        let err = ErrorResponse::with_details(
            ErrorCode::RateLimited,
            "Too many requests",
            "Try again in 60 seconds",
        );
        assert_eq!(err.code, ErrorCode::RateLimited);
        assert_eq!(err.message, "Too many requests");
        assert_eq!(err.details, Some("Try again in 60 seconds".to_string()));
    }
}
