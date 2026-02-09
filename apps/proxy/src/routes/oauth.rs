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
    // GITHUB_ALLOWED_HOSTS must be explicitly set for security.
    let allowed_hosts: Vec<String> = std::env::var("GITHUB_ALLOWED_HOSTS")
        .map_err(|_| {
            AppError::ConfigError(
                "GITHUB_ALLOWED_HOSTS environment variable is not set.".to_string(),
            )
        })?
        .split(',')
        .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();

    if allowed_hosts.is_empty() {
        return Err(AppError::ConfigError(
            "GITHUB_ALLOWED_HOSTS must not be empty.".to_string(),
        ));
    }

    let expected_path = "/login/oauth/access_token";
    let has_userinfo = !parsed_url.username().is_empty() || parsed_url.password().is_some();
    let has_query_or_fragment = parsed_url.query().is_some() || parsed_url.fragment().is_some();
    let port = parsed_url.port_or_known_default();

    if scheme != "https"
        || has_userinfo
        || has_query_or_fragment
        || port != Some(443)
        || parsed_url.path() != expected_path
        || !allowed_hosts.iter().any(|h| h == &host)
    {
        tracing::error!(
            "Blocked GitHub token exchange due to untrusted URL: scheme='{}', host='{}', port='{:?}', path='{}'",
            scheme,
            host,
            port,
            parsed_url.path()
        );
        return Err(AppError::GitHubError(
            "Untrusted OAuth provider URL".to_string(),
        ));
    }

    // Enforce trusted redirect URI to prevent open redirection
    let expected_redirect_uri =
        std::env::var("GITHUB_REDIRECT_URI").unwrap_or_else(|_| "aroeira://auth/callback".into());

    if request.redirect_uri != expected_redirect_uri {
        tracing::warn!(
            "Rejected GitHub token exchange due to unexpected redirect_uri: {}",
            request.redirect_uri
        );
        return Err(AppError::BadRequest(
            "Invalid request parameters".to_string(),
        ));
    }

    let params = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret),
        ("code", request.code.as_str()),
        ("redirect_uri", expected_redirect_uri.as_str()),
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
