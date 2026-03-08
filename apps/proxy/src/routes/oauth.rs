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
use std::sync::LazyLock;
use validator::Validate;

const STANDARD_GITHUB_URL: &str = "https://github.com/login/oauth/access_token";
const MAX_ERROR_BODY_BYTES: usize = 8 * 1024;

static STANDARD_GITHUB_PARSED: LazyLock<url::Url> =
    LazyLock::new(|| match url::Url::parse(STANDARD_GITHUB_URL) {
        Ok(url) => url,
        Err(_parse_err) => {
            tracing::error!("STANDARD_GITHUB_URL is invalid");
            url::Url::parse("https://github.com").unwrap_or_else(|_fallback_err| {
                url::Url::parse("about:blank")
                    .unwrap_or_else(|_final_err| url::Url::parse("https://invalid").unwrap())
            })
        }
    });

#[axum::debug_handler]
pub async fn github_token_exchange(
    State(state): State<AppState>,
    Json(payload): Json<GitHubTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|_err| AppError::BadRequest("Invalid OAuth request payload".to_owned()))?;

    validate_redirect_uri(&payload, &state.config.github_redirect_uri)?;

    let token_url = resolve_github_token_url(
        &state.config.github_token_url,
        &state.config.github_allowed_hosts,
    )?;

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
        .post(token_url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await
        .map_err(|err| {
            tracing::error!("Failed to send GitHub token request: {}", err);
            AppError::GitHubError("Failed to communicate with GitHub".to_owned())
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let mut body = Vec::new();
        let mut resp = response;
        while let Some(chunk) = resp.chunk().await.map_err(|err| {
            tracing::error!("Failed reading GitHub error response body: {}", err);
            AppError::GitHubError("Failed to read response from GitHub".to_owned())
        })? {
            if body.len().saturating_add(chunk.len()) > MAX_ERROR_BODY_BYTES {
                break;
            }
            body.extend_from_slice(&chunk);
        }

        let error_code = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(|err_str| err_str.as_str())
                    .map(ToString::to_string)
            });

        if let Some(error_code_value) = error_code {
            tracing::error!(
                "GitHub token exchange failed: status={}, error_code={}",
                status,
                error_code_value
            );
        } else {
            tracing::error!("GitHub token exchange failed: status={}", status);
        }
        return Err(AppError::GitHubError(
            "GitHub refused the token exchange".to_owned(),
        ));
    }

    let token_response = response
        .json::<GitHubTokenResponse>()
        .await
        .map_err(|err| {
            tracing::error!("Failed to parse GitHub token response: {}", err);
            AppError::GitHubError("Invalid response from GitHub".to_owned())
        })?;

    if let Some(error) = &token_response.error {
        tracing::error!("GitHub returned error in payload: {}", error);
        return Err(AppError::GitHubError("GitHub OAuth error".to_owned()));
    }

    if token_response.access_token.is_none()
        || token_response.token_type.is_none()
        || token_response.scope.is_none()
    {
        tracing::error!("GitHub token response missing required fields");
        return Err(AppError::GitHubError(
            "Invalid response from GitHub".to_owned(),
        ));
    }

    Ok(Json(token_response))
}

fn validate_redirect_uri(
    request: &GitHubTokenRequest,
    expected_redirect_uri: &str,
) -> Result<(), AppError> {
    let req = url::Url::parse(&request.redirect_uri)
        .map_err(|_err| AppError::BadRequest("Invalid redirect URI".to_owned()))?;
    let expected = url::Url::parse(expected_redirect_uri)
        .map_err(|_err| AppError::GitHubError("Server misconfiguration".to_owned()))?;

    let has_userinfo = !req.username().is_empty() || req.password().is_some();
    let has_query_or_fragment = req.query().is_some() || req.fragment().is_some();
    if has_userinfo || has_query_or_fragment {
        tracing::error!("Blocked GitHub token exchange due to unexpected redirect_uri components");
        return Err(AppError::BadRequest("Invalid redirect URI".to_owned()));
    }

    let expected_has_userinfo = !expected.username().is_empty() || expected.password().is_some();
    let expected_has_query_or_fragment =
        expected.query().is_some() || expected.fragment().is_some();
    if expected_has_userinfo || expected_has_query_or_fragment {
        tracing::error!(
            "Server misconfiguration: expected redirect URI contains forbidden components"
        );
        return Err(AppError::GitHubError("Server misconfiguration".to_owned()));
    }
    let expected_scheme = expected.scheme();
    if expected_scheme != "http" && expected_scheme != "https" && expected_scheme != "aroeira" {
        tracing::error!("Server misconfiguration: expected redirect URI has unsupported scheme");
        return Err(AppError::GitHubError("Server misconfiguration".to_owned()));
    }

    let same_base = req.scheme() == expected.scheme()
        && req.host_str() == expected.host_str()
        && req.port_or_known_default() == expected.port_or_known_default()
        && req.path() == expected.path();

    if !same_base {
        tracing::error!("Blocked GitHub token exchange due to mismatched redirect_uri");
        return Err(AppError::BadRequest("Invalid redirect URI".to_owned()));
    }

    Ok(())
}

fn resolve_github_token_url(
    configured_url: &str,
    allowed_hosts: &[String],
) -> Result<url::Url, AppError> {
    if configured_url == STANDARD_GITHUB_URL {
        return Ok(STANDARD_GITHUB_PARSED.clone());
    }

    let parsed_url = url::Url::parse(configured_url)
        .map_err(|_err| AppError::GitHubError("Invalid provider token URL format".to_owned()))?;

    let scheme = parsed_url.scheme();
    let host = parsed_url
        .host_str()
        .ok_or_else(|| AppError::GitHubError("Untrusted OAuth provider URL".to_owned()))?
        .trim_end_matches('.')
        .to_ascii_lowercase();

    let expected_path = "/login/oauth/access_token";
    let has_userinfo = !parsed_url.username().is_empty() || parsed_url.password().is_some();
    let has_query_or_fragment = parsed_url.query().is_some() || parsed_url.fragment().is_some();
    let port = parsed_url.port_or_known_default();

    if matches!(
        parsed_url.host(),
        Some(url::Host::Ipv4(_) | url::Host::Ipv6(_))
    ) {
        tracing::error!("Blocked GitHub token exchange due to IP-literal host");
        return Err(AppError::GitHubError(
            "Untrusted OAuth provider URL".to_owned(),
        ));
    }

    if scheme != "https"
        || has_userinfo
        || has_query_or_fragment
        || port != Some(443)
        || parsed_url.path() != expected_path
        || !allowed_hosts
            .iter()
            .any(|allowed_host| allowed_host == &host)
    {
        tracing::error!(
            "Blocked GitHub token exchange due to untrusted URL: scheme='{}', host='{}', port='{:?}', path='{}'",
            scheme,
            host,
            port,
            parsed_url.path()
        );
        return Err(AppError::GitHubError(
            "Untrusted OAuth provider URL".to_owned(),
        ));
    }

    Ok(parsed_url)
}
