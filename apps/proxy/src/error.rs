use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("GitHub OAuth error: {0}")]
    GitHubError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::GitHubError(_) => (
                StatusCode::BAD_GATEWAY,
                "OAuth provider error. Please try again.".to_string(),
            ),
            Self::ConfigError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Service configuration error".to_string(),
            ),
        };

        let body = Json(json!({
            "error": error_message,
            "code": status.as_u16(),
        }));

        (status, body).into_response()
    }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        Self::GitHubError(format!("HTTP client error: {err}"))
    }
}

impl From<config::ConfigError> for AppError {
    fn from(err: config::ConfigError) -> Self {
        Self::ConfigError(err.to_string())
    }
}
