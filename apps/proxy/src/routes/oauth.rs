use crate::{
    error::AppError,
    models::{GitHubRawTokenResponse, GitHubTokenRequest, GitHubTokenResponse},
    AppState,
};
use axum::{extract::State, Json};
use secrecy::ExposeSecret;
use url::Url;
use validator::Validate;

pub async fn github_token_exchange(
    State(state): State<AppState>,
    Json(request): Json<GitHubTokenRequest>,
) -> Result<Json<GitHubTokenResponse>, AppError> {
    request
        .validate()
        .map_err(|e| AppError::BadRequest(format!("Validation failed: {e}")))?;

    tracing::info!(
        "Processing GitHub token exchange for state: {}",
        request.state
    );

    let client_id = state.config.github_client_id.clone();
    let client_secret = state.config.github_client_secret.expose_secret();

    // Validate GitHub token URL before making request (SSRF protection)
    let parsed_url = Url::parse(&state.config.github_token_url).map_err(|e| {
        tracing::error!("Invalid GitHub token URL in configuration: {}", e);
        AppError::BadRequest(format!("Validation failed: {e}"))
    })?;

    let scheme = parsed_url.scheme();
    let host = parsed_url.host_str().unwrap_or_default();

    // Only allow HTTPS requests to trusted GitHub hosts
    let allowed_hosts = ["github.com", "api.github.com"];
    if scheme != "https" || !allowed_hosts.contains(&host) {
        tracing::error!(
            "Blocked GitHub token exchange due to untrusted URL: scheme='{}', host='{}'",
            scheme,
            host
        );
        return Err(AppError::GitHubError(
            "Untrusted OAuth provider URL".to_string(),
        ));
    }

    let params = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret),
        ("code", request.code.as_str()),
        ("redirect_uri", request.redirect_uri.as_str()),
        ("state", request.state.as_str()),
    ];

    let response = state
        .http_client
        .post(parsed_url)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await?;

    let status = response.status();

    if !status.is_success() {
        let error_body = response.text().await.unwrap_or_default();
        tracing::warn!(
            "GitHub token exchange failed: status={}, body={}",
            status,
            error_body
        );
        return Err(AppError::GitHubError("Token exchange failed".to_string()));
    }

    let raw_response: GitHubRawTokenResponse = response.json().await.map_err(|e| {
        tracing::error!("Failed to parse GitHub response: {}", e);
        AppError::GitHubError("Invalid response from OAuth provider".to_string())
    })?;

    tracing::info!(
        "GitHub token exchange successful for state: {}",
        request.state
    );

    Ok(Json(GitHubTokenResponse {
        access_token: raw_response.access_token,
        refresh_token: raw_response.refresh_token,
        token_type: raw_response.token_type,
        expires_in: raw_response.expires_in,
        scope: raw_response.scope,
    }))
}
