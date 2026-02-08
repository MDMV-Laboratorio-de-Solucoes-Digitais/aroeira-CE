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
    request.validate().map_err(|e| {
        tracing::warn!("GitHub token exchange validation failed: {}", e);
        AppError::BadRequest("Invalid request parameters".to_string())
    })?;

    tracing::info!(
        "Processing GitHub token exchange (state_len={})",
        request.state.len()
    );

    let client_id = state.config.github_client_id.clone();
    let client_secret = state.config.github_client_secret.expose_secret();

    // Validate GitHub token URL before making request (SSRF protection)
    let parsed_url = Url::parse(&state.config.github_token_url).map_err(|e| {
        tracing::error!("Invalid GitHub token URL in configuration: {}", e);
        AppError::InternalServerError
    })?;

    let scheme = parsed_url.scheme();
    let host = parsed_url
        .host_str()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();

    // Only allow HTTPS requests to trusted GitHub hosts.
    // Prefer an explicit allowlist from config; fall back to public GitHub.
    let allowed_hosts: Vec<String> = std::env::var("GITHUB_ALLOWED_HOSTS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect()
        })
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| vec!["github.com".to_string(), "api.github.com".to_string()]);

    let expected_path = "/login/oauth/access_token";
    let has_userinfo = !parsed_url.username().is_empty() || parsed_url.password().is_some();

    if scheme != "https"
        || has_userinfo
        || parsed_url.path() != expected_path
        || !allowed_hosts.iter().any(|h| h == &host)
    {
        tracing::error!(
            "Blocked GitHub token exchange due to untrusted URL: scheme='{}', host='{}', path='{}'",
            scheme,
            host,
            parsed_url.path()
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
        ("code_verifier", request.code_verifier.as_str()),
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
        // Redact body in logs to avoid leaking sensitive data, log only status and length
        tracing::warn!(
            "GitHub token exchange failed: status={}, body_len={}",
            status,
            error_body.len()
        );
        return Err(AppError::GitHubError("Token exchange failed".to_string()));
    }

    let raw_response: GitHubRawTokenResponse = response.json().await.map_err(|e| {
        tracing::error!("Failed to parse GitHub response: {}", e);
        AppError::GitHubError("Invalid response from OAuth provider".to_string())
    })?;

    tracing::info!(
        "GitHub token exchange successful (state_len={})",
        request.state.len()
    );

    Ok(Json(GitHubTokenResponse {
        access_token: raw_response.access_token,
        refresh_token: raw_response.refresh_token,
        token_type: raw_response.token_type,
        expires_in: raw_response.expires_in,
        scope: raw_response.scope,
    }))
}
