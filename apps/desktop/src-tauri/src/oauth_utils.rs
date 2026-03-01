use infra::constants::{OAUTH_CALLBACK_HOST, OAUTH_CALLBACK_PATH, OAUTH_CALLBACK_SCHEME};
use url::Url;

/// The path for "hostless" custom scheme URLs (e.g., aroeira:auth/callback)
pub const HOSTLESS_PATH: &str = "auth/callback";

/// Gets the development server port from environment or defaults to 1420.
#[must_use]
pub fn get_dev_port() -> u16 {
    std::env::var("AROEIRA_DEV_PORT")
        .or_else(|_| std::env::var("VITE_DEV_PORT"))
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
    const MAX_CALLBACK_URL_LEN: usize = 8192;

    if url.as_str().len() > MAX_CALLBACK_URL_LEN {
        tracing::warn!("OAuth callback: url too large");
        return Err(GENERIC_ERROR.to_string());
    }

    let is_aroeira_protocol = url.scheme().eq_ignore_ascii_case(OAUTH_CALLBACK_SCHEME);
    let host = url
        .host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase());
    let has_userinfo = !url.username().is_empty() || url.password().is_some();

    let is_localhost_dev = cfg!(debug_assertions)
        && url.scheme() == "http"
        && host.as_deref() == Some("localhost")
        && url.port() == Some(get_dev_port())
        && url.path() == "/auth/callback"
        && !has_userinfo;

    if !is_aroeira_protocol && !is_localhost_dev {
        tracing::warn!(
            expected_scheme = OAUTH_CALLBACK_SCHEME,
            actual_scheme = url.scheme(),
            "OAuth callback: invalid scheme"
        );
        return Err(GENERIC_ERROR.to_string());
    }

    // Reject URL fragments everywhere (OAuth response must not be in fragment for this app)
    if url.fragment().is_some() {
        tracing::warn!("OAuth callback: unexpected fragment");
        return Err(GENERIC_ERROR.to_string());
    }

    // For aroeira protocol, validate host/path and disallow userinfo/ports
    if is_aroeira_protocol {
        if !url.username().is_empty() || url.password().is_some() || url.port().is_some() {
            tracing::warn!("OAuth callback: unexpected authority components");
            return Err(GENERIC_ERROR.to_string());
        }
        let is_canonical =
            host.as_deref() == Some(OAUTH_CALLBACK_HOST) && url.path() == OAUTH_CALLBACK_PATH;
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

/// Helper to extract query parameters manually, preserving '+' signs.
///
/// # Errors
///
/// Returns an error if the query is malformed or exceeds size limits.
fn parse_query_preserving_plus(query: &str) -> Result<Vec<(String, String)>, String> {
    const GENERIC_ERROR: &str = "Invalid authentication callback. Please try again.";
    const MAX_QUERY_PAIRS: usize = 64;
    const MAX_KEY_LEN: usize = 64;
    const MAX_VALUE_LEN: usize = 4096;

    let mut query_pairs = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if query_pairs.len() >= MAX_QUERY_PAIRS {
            return Err(GENERIC_ERROR.to_string());
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));

        // Cheap pre-checks to avoid decoding obviously oversized inputs.
        if k.len() > MAX_KEY_LEN * 3 || v.len() > MAX_VALUE_LEN * 3 {
            return Err(GENERIC_ERROR.to_string());
        }

        let k = percent_encoding::percent_decode_str(k)
            .decode_utf8()
            .map_err(|_| GENERIC_ERROR.to_string())?
            .to_string();
        let v = percent_encoding::percent_decode_str(v)
            .decode_utf8()
            .map_err(|_| GENERIC_ERROR.to_string())?
            .to_string();

        if k.len() > MAX_KEY_LEN || v.len() > MAX_VALUE_LEN {
            return Err(GENERIC_ERROR.to_string());
        }

        query_pairs.push((k, v));
    }
    Ok(query_pairs)
}

/// Parses an OAuth callback URL to extract code and state.
///
/// # Errors
///
/// Returns a generic error if the URL is invalid or missing required parameters.
pub fn parse_oauth_callback_url(callback_url: &str) -> Result<(String, String), String> {
    // Generic error message for all validation failures
    const GENERIC_ERROR: &str = "Invalid authentication callback. Please try again.";

    let url = Url::parse(callback_url).map_err(|e| {
        tracing::warn!("OAuth callback URL parse error: {e}");
        GENERIC_ERROR.to_string()
    })?;

    validate_callback_url_base(&url)?;
    extract_and_validate_params(&url)
}

/// Extracts and performs security validation on the OAuth code and state parameters.
///
/// # Errors
///
/// Returns an error if parameters are missing, invalid, or exceed size limits.
fn extract_and_validate_params(url: &Url) -> Result<(String, String), String> {
    const GENERIC_ERROR: &str = "Invalid authentication callback. Please try again.";
    const MAX_CODE_LEN: usize = 4096;
    const MAX_STATE_LEN: usize = 512;

    // Security: Validate state charset to prevent injection/ambiguity.
    // Accept RFC3986 "unreserved" characters: ALPHA / DIGIT / "-" / "." / "_" / "~".
    fn is_unreserved(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
    }

    // Helper to extract query parameters.
    let query = url.query().unwrap_or("");
    let query_pairs = parse_query_preserving_plus(query)?;

    // Check for error response from OAuth provider
    if let Some((_, error_code)) = query_pairs.iter().find(|(k, _)| k == "error") {
        // Log only the error code (standard OAuth error codes like "access_denied")
        // Do NOT log error_description as it may contain sensitive user-specific details
        tracing::info!(
            error_code = %error_code,
            "OAuth provider returned error"
        );
        return Err("Authentication was denied or failed. Please try again.".to_string());
    }

    let get_unique_query_param = |key: &str| -> Result<String, String> {
        let mut values = query_pairs
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty());

        let first = values.next().ok_or_else(|| {
            tracing::warn!("OAuth callback: missing or empty {} parameter", key);
            GENERIC_ERROR.to_string()
        })?;

        if values.next().is_some() {
            tracing::warn!("OAuth callback: duplicate {} parameter", key);
            return Err(GENERIC_ERROR.to_string());
        }

        Ok(first)
    };

    let code = get_unique_query_param("code")?;
    let state = get_unique_query_param("state")?;

    if code.len() > MAX_CODE_LEN || state.len() > MAX_STATE_LEN {
        tracing::warn!(
            code_len = code.len(),
            state_len = state.len(),
            "OAuth callback: code/state too large"
        );
        return Err(GENERIC_ERROR.to_string());
    }

    if state.is_empty() || !state.as_bytes().iter().copied().all(is_unreserved) {
        tracing::warn!(
            target: "audit",
            outcome = "failure",
            reason = "invalid_state_charset",
            "OAuth callback: state contains invalid characters"
        );
        return Err(GENERIC_ERROR.to_string());
    }

    // Security: Validate code charset to prevent injection attacks or anomalies
    // Code should not contain control characters
    if code.chars().any(char::is_control) {
        tracing::warn!(
            target: "audit",
            outcome = "failure",
            reason = "invalid_code_charset",
            "OAuth callback: code contains control characters"
        );
        return Err(GENERIC_ERROR.to_string());
    }

    // Hash state for logging purposes (to avoid logging sensitive value)
    let state_hash_for_log = infra::utils::hash_string_sha256_hex(&state);
    tracing::info!(
        target: "oauth_debug",
        state_hash = %state_hash_for_log,
        "Callback parsed successfully"
    );

    Ok((code, state))
}

/// Validates the OAuth callback URL and extracts code and state.
///
/// # Errors
///
/// Returns an error if validation fails or parameters are invalid.
pub fn validate_and_parse_callback(
    callback_url: &str,
    request_id: &str,
) -> Result<(String, String), String> {
    const MAX_CALLBACK_LEN: usize = 8192;

    // Prevent DoS via excessive URL length
    if callback_url.len() > MAX_CALLBACK_LEN {
        tracing::warn!(
            target: "audit",
            request_id = %request_id,
            outcome = "failure",
            reason = "callback_too_long",
            "OAuth callback URL exceeded max length"
        );
        return Err("Invalid authentication request".to_string());
    }

    // Parse callback URL
    let (code, state_param) = parse_oauth_callback_url(callback_url).inspect_err(|e| {
        tracing::error!(
            target: "oauth_debug",
            request_id = %request_id,
            error = %e,
            "Failed to parse OAuth callback URL"
        );
        tracing::warn!(
            target: "audit",
            request_id = %request_id,
            outcome = "failure",
            reason = "invalid_callback",
            "OAuth authentication failed: invalid callback URL"
        );
    })?;

    let state_hash_for_log = infra::utils::hash_string_sha256_hex(&state_param);
    tracing::info!(
        target: "oauth_debug",
        request_id = %request_id,
        state_hash = %state_hash_for_log,
        "Callback parsed successfully"
    );

    Ok((code, state_param))
}
