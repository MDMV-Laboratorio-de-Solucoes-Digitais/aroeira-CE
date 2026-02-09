use infra::constants::{OAUTH_CALLBACK_HOST, OAUTH_CALLBACK_PATH, OAUTH_CALLBACK_SCHEME};
use url::Url;

/// The path for "hostless" custom scheme URLs (e.g., aroeira:auth/callback)
pub const HOSTLESS_PATH: &str = "auth/callback";

/// Gets the development server port from environment or defaults to 1420.
#[must_use]
pub fn get_dev_port() -> u16 {
    std::env::var("AROEIRA_DEV_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(1420)
}

/// Validates the basic structure (scheme, host, path) of an OAuth callback URL.
///
/// This handles:
/// 1. Canonical production scheme: <aroeira://auth/callback>
/// 2. Hostless custom scheme: aroeira:auth/callback
/// 3. Localhost development: http://localhost:{port}/auth/callback (debug only)
///
/// # Errors
///
/// Returns an error string if the URL is invalid or not allowed.
pub fn validate_callback_url_base(url: &Url) -> Result<(), String> {
    const GENERIC_ERROR: &str = "Invalid authentication callback. Please try again.";

    let is_aroeira_protocol = url.scheme().eq_ignore_ascii_case(OAUTH_CALLBACK_SCHEME);
    let is_localhost_dev = cfg!(debug_assertions)
        && url.scheme() == "http"
        && url.host_str() == Some("localhost")
        && url.port() == Some(get_dev_port())
        && url.path() == "/auth/callback";

    if !is_aroeira_protocol && !is_localhost_dev {
        tracing::warn!(
            expected_scheme = OAUTH_CALLBACK_SCHEME,
            actual_scheme = url.scheme(),
            "OAuth callback: invalid scheme"
        );
        return Err(GENERIC_ERROR.to_string());
    }

    // For aroeira protocol, validate host/path
    if is_aroeira_protocol {
        let is_canonical =
            url.host_str() == Some(OAUTH_CALLBACK_HOST) && url.path() == OAUTH_CALLBACK_PATH;
        let is_hostless =
            url.host_str().is_none() && url.path().trim_start_matches('/') == HOSTLESS_PATH;

        if !is_canonical && !is_hostless {
            tracing::warn!(
                expected_host = OAUTH_CALLBACK_HOST,
                expected_path = OAUTH_CALLBACK_PATH,
                actual_host = ?url.host_str(),
                actual_path = url.path(),
                "OAuth callback: invalid host or path"
            );
            return Err(GENERIC_ERROR.to_string());
        }
    }

    Ok(())
}
