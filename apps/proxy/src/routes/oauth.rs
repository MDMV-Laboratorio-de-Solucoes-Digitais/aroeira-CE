use crate::{
    error::AppError,
    models::{GitHubTokenRequest, GitHubTokenResponse},
    AppState,
};
use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use secrecy::ExposeSecret;
use validator::Validate;

#[axum::debug_handler]
pub async fn github_token_exchange(
    State(state): State<AppState>,
    Json(payload): Json<GitHubTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|_| AppError::BadRequest("Invalid OAuth request payload".to_string()))?;

    // 1. Validate the redirect_uri to prevent open redirect abuse or misuse
    validate_github_token_request(
        &payload,
        &state.config.github_redirect_uri,
        &state.config.github_token_url,
        &state.config.github_allowed_hosts,
    )
    .await?;

    // 2. Exchange code for token with GitHub
    let client = &state.http_client;

    let client_id = &state.config.github_client_id;
    let client_secret = state.config.github_client_secret.expose_secret();
    let code = &payload.code;
    let redirect_uri = &payload.redirect_uri;
    let code_verifier = &payload.code_verifier;

    let params = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_verifier", code_verifier.as_str()),
    ];

    let response = client
        .post(&state.config.github_token_url)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to send GitHub token request: {}", e);
            AppError::GitHubError("Failed to communicate with GitHub".to_string())
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::error!(
            "GitHub token exchange failed: status={}, body={}",
            status,
            body
        );
        return Err(AppError::GitHubError(
            "GitHub refused the token exchange".to_string(),
        ));
    }

    let token_response = response.json::<GitHubTokenResponse>().await.map_err(|e| {
        tracing::error!("Failed to parse GitHub token response: {}", e);
        AppError::GitHubError("Invalid response from GitHub".to_string())
    })?;

    if let Some(error) = &token_response.error {
        tracing::error!(
            "GitHub returned error in payload: {} - {}",
            error,
            token_response.error_description.as_deref().unwrap_or("")
        );
        return Err(AppError::GitHubError(
            token_response
                .error_description
                .clone()
                .unwrap_or_else(|| "GitHub OAuth error".to_string()),
        ));
    }

    Ok(Json(token_response))
}

async fn validate_github_token_request(
    request: &GitHubTokenRequest,
    expected_redirect_uri: &str,
    github_token_url: &str,
    allowed_hosts: &[String],
) -> Result<(), AppError> {
    // 1) Ensure the client cannot choose arbitrary redirect URIs
    if request.redirect_uri != expected_redirect_uri {
        tracing::error!("Blocked GitHub token exchange due to mismatched redirect_uri");
        return Err(AppError::BadRequest("Invalid redirect URI".to_string()));
    }

    let parsed_url = url::Url::parse(github_token_url)
        .map_err(|_| AppError::GitHubError("Invalid provider token URL format".to_string()))?;

    let scheme = parsed_url.scheme();
    let host = parsed_url
        .host_str()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();

    let expected_path = "/login/oauth/access_token";
    let has_userinfo = !parsed_url.username().is_empty() || parsed_url.password().is_some();
    let has_query_or_fragment = parsed_url.query().is_some() || parsed_url.fragment().is_some();
    let port = parsed_url.port_or_known_default();

    // Reject IP-literal hosts (defense-in-depth for SSRF / DNS rebinding)
    if matches!(
        parsed_url.host(),
        Some(url::Host::Ipv4(_) | url::Host::Ipv6(_))
    ) {
        tracing::error!("Blocked GitHub token exchange due to IP-literal host");
        return Err(AppError::GitHubError(
            "Untrusted OAuth provider URL".to_string(),
        ));
    }

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

    let addrs = tokio::net::lookup_host((host.as_str(), 443))
        .await
        .map_err(|e| {
            tracing::error!("DNS lookup failed for GitHub token host: {}", e);
            AppError::InternalServerError
        })?;

    let is_private = addrs.into_iter().any(|addr| match addr.ip() {
        std::net::IpAddr::V4(ipv4) => {
            ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local()
        }
        std::net::IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                || (ipv6.segments()[0] & 0xffc0) == 0xfe80
        }
    });

    if is_private {
        tracing::error!("Blocked GitHub token exchange due to non-public DNS resolution");
        return Err(AppError::GitHubError(
            "Untrusted OAuth provider URL".to_string(),
        ));
    }

    Ok(())
}
