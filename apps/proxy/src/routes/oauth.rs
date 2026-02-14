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
    // Bounded read to avoid DoS via huge error bodies.
    const MAX_ERROR_BODY_BYTES: usize = 8 * 1024; // enough for diagnostics

    payload
        .validate()
        .map_err(|_| AppError::BadRequest("Invalid OAuth request payload".to_string()))?;

    validate_redirect_uri(&payload, &state.config.github_redirect_uri)?;

    // 2. Resolve and validate the upstream token URL
    // We do this explicitly to return a trusted `Url` object and satisfy SSRF checks.
    let token_url = resolve_github_token_url(
        &state.config.github_token_url,
        &state.config.github_allowed_hosts,
    )?;

    // 3. Exchange code for token with GitHub
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

    // Configurable URL with strict validation (see resolve_github_token_url)
    // to support Enterprise/Proxy scenarios while preventing SSRF.
    let response = client
        .post(token_url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to send GitHub token request: {}", e);
            AppError::GitHubError("Failed to communicate with GitHub".to_string())
        })?;

    if !response.status().is_success() {
        let status = response.status();

        let mut body = Vec::new();
        let mut resp = response;
        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            tracing::error!("Failed reading GitHub error response body: {}", e);
            AppError::GitHubError("Failed to read response from GitHub".to_string())
        })? {
            if body.len().saturating_add(chunk.len()) > MAX_ERROR_BODY_BYTES {
                break;
            }
            body.extend_from_slice(&chunk);
        }

        // Avoid logging potentially sensitive payloads; keep a small bounded snippet.
        let body_str = String::from_utf8_lossy(&body);
        let snippet: String = body_str.chars().take(512).collect();

        tracing::error!(
            "GitHub token exchange failed: status={}, body_snippet={}",
            status,
            snippet
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
        // Do not log `error_description` (may contain sensitive/user-specific details).
        tracing::error!("GitHub returned error in payload: {}", error);
        return Err(AppError::GitHubError("GitHub OAuth error".to_string()));
    }

    if token_response.access_token.is_none()
        || token_response.token_type.is_none()
        || token_response.scope.is_none()
    {
        tracing::error!("GitHub token response missing required fields");
        return Err(AppError::GitHubError(
            "Invalid response from GitHub".to_string(),
        ));
    }

    Ok(Json(token_response))
}

fn validate_redirect_uri(
    request: &GitHubTokenRequest,
    expected_redirect_uri: &str,
) -> Result<(), AppError> {
    let req = url::Url::parse(&request.redirect_uri)
        .map_err(|_| AppError::BadRequest("Invalid redirect URI".to_string()))?;
    let expected = url::Url::parse(expected_redirect_uri)
        .map_err(|_| AppError::GitHubError("Server misconfiguration".to_string()))?;

    // Reject any authority tricks / dynamic parts
    let has_userinfo = !req.username().is_empty() || req.password().is_some();
    let has_query_or_fragment = req.query().is_some() || req.fragment().is_some();
    if has_userinfo || has_query_or_fragment {
        tracing::error!("Blocked GitHub token exchange due to unexpected redirect_uri components");
        return Err(AppError::BadRequest("Invalid redirect URI".to_string()));
    }

    // Compare normalized base (scheme/host/port/path), ignoring formatting differences.
    let same_base = req.scheme() == expected.scheme()
        && req.host_str() == expected.host_str()
        && req.port_or_known_default() == expected.port_or_known_default()
        && req.path() == expected.path();

    if !same_base {
        tracing::error!("Blocked GitHub token exchange due to mismatched redirect_uri");
        return Err(AppError::BadRequest("Invalid redirect URI".to_string()));
    }

    Ok(())
}

fn resolve_github_token_url(
    configured_url: &str,
    allowed_hosts: &[String],
) -> Result<url::Url, AppError> {
    // Defense-in-depth: If the configured URL matches the standard GitHub endpoint exactly,
    // return a fresh Url object constructed from a string literal.
    // This helps static analysis tools (like CodeQL) verify that the default path is safe/constant.
    const STANDARD_GITHUB_URL: &str = "https://github.com/login/oauth/access_token";
    if configured_url == STANDARD_GITHUB_URL {
        // Safe to unwrap because we know this string literal is a valid URL.
        #[allow(clippy::expect_used)]
        return Ok(url::Url::parse(STANDARD_GITHUB_URL).expect("Standard URL is valid"));
    }

    // Otherwise, parse and validate the custom URL against the allowlist.
    let parsed_url = url::Url::parse(configured_url)
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

    Ok(parsed_url)
}
