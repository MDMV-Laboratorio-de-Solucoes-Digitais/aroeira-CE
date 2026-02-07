use axum::{routing::post, Router};

pub mod oauth;

pub fn router() -> Router<crate::AppState> {
    Router::new().route("/github/token", post(oauth::github_token_exchange))
}
