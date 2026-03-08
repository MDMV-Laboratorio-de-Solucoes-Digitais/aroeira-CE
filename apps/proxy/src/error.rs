use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Environment variable error: {0}")]
    EnvError(#[from] std::env::VarError),
    #[error("GitHub API error: {0}")]
    GitHubError(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::GitHubError(_) => (
                StatusCode::BAD_GATEWAY,
                "OAuth provider error. Please try again.".to_owned(),
            ),
            Self::EnvError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_owned(),
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
