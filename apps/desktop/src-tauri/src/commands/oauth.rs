//! `OAuth2` Tauri Commands - TDD GREEN PHASE
//!
//! This module provides Tauri commands for `OAuth2` authentication
//! with PKCE flow for Google and GitHub providers.
//!
//! # Security Notes
//!
//! - Uses PKCE (RFC 7636) for all flows - no client secrets
//! - State parameter provides CSRF protection
//! - Sessions expire after 10 minutes
//! - Tokens stored in OS secure storage (not in this module)

use crate::commands::auth::{get_device_id, handle_successful_login, hash_email_for_logging};
use crate::state::AppState;
use domain::modules::auth::oauth::{AuthProvider, OAuthPkceSession, OAuthService, OAuthUser};
use hex;
use infra::services::oauth::{OAuthConfig, OAuthServiceImpl};
use infra::utils::hash_password;
use parking_lot::Mutex;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::State;
use url::Url;
use uuid::Uuid;

/// OAuth state managed by Tauri.
///
/// This struct is registered as Tauri managed state to persist
/// OAuth sessions across command invocations.
pub struct OAuthState {
    /// Session store for pending OAuth flows
    pub session_store: OAuthSessionStore,
    /// OAuth service implementation
    pub oauth_service: Arc<OAuthServiceImpl>,
}

impl OAuthState {
    /// Creates new OAuth state with given configuration.
    #[must_use]
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            session_store: OAuthSessionStore::new(),
            oauth_service: Arc::new(OAuthServiceImpl::new(config)),
        }
    }
}

/// Response from `start_oauth_flow` command.
#[derive(Debug, Serialize, Deserialize)]
pub struct StartOAuthResponse {
    /// Authorization URL to open in browser
    pub auth_url: String,
    /// State parameter for CSRF verification
    pub state: String,
}

/// Response from `handle_oauth_callback` command.
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthCallbackResponse {
    /// Provider that authenticated the user
    pub provider: String,
    /// User's email from the provider
    pub email: String,
    /// User's display name (optional)
    pub name: Option<String>,
    /// User's avatar URL (optional)
    pub avatar_url: Option<String>,
}

/// Response from `get_oauth_availability` command.
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthAvailability {
    /// Whether Google provider is configured
    pub google: bool,
    /// Whether GitHub provider is configured
    pub github: bool,
}

impl From<OAuthUser> for OAuthCallbackResponse {
    fn from(user: OAuthUser) -> Self {
        Self {
            provider: user.provider.to_string().to_lowercase(),
            email: user.email,
            name: user.name,
            avatar_url: user.avatar_url,
        }
    }
}

/// Starts an OAuth authentication flow for the given provider.
///
/// This command:
/// 1. Generates a PKCE challenge and authorization URL
/// 2. Stores the PKCE session for later verification
/// 3. Returns the URL to open in the system browser
///
/// # Arguments
///
/// * `provider` - The OAuth provider (google or github)
///
/// # Returns
///
/// * `Ok(StartOAuthResponse)` - Authorization URL and state parameter
/// * `Err(String)` - If provider is not configured
///
/// # Errors
///
/// Returns an error string if:
/// - The provider is not configured (missing Client ID)
/// - URL generation fails
/// - Session storage fails
#[tauri::command]
pub async fn start_oauth_flow(
    provider: AuthProvider,
    oauth_state: State<'_, OAuthState>,
    state: State<'_, AppState>,
) -> Result<StartOAuthResponse, String> {
    let device_id = get_device_id().map_err(|e| {
        tracing::error!(
            target: "security",
            outcome = "failure",
            reason = "device_id_unavailable",
            error = %e,
            "OAuth flow aborted: device ID unavailable"
        );
        "Authentication failed. Please try again.".to_string()
    })?;

    // Hash device_id for privacy in logs
    let mut hasher = Sha256::new();
    hasher.update(device_id.as_bytes());
    let device_id_hash = hex::encode(hasher.finalize());

    // Generate authorization URL
    let (auth_url, session) = oauth_state
        .oauth_service
        .generate_authorization_url(provider)
        .await
        .map_err(|e| {
            tracing::error!(
                target: "audit",
                outcome = "failure",
                reason = "url_generation_failed",
                device_id = %device_id_hash,
                error = %e,
                "OAuth URL generation failed"
            );
            "Failed to start authentication. Please try again.".to_string()
        })?;

    tracing::info!(
        target: "audit",
        action = "oauth_start",
        provider = %provider,
        device_id = %device_id_hash,
        "Starting OAuth flow"
    );

    let state_param = session.state.clone();

    // Persist session for cold start recovery (deep link opens closed app)
    // One-time use: deleted after successful `take` on callback.
    // Use underscore separator instead of colon (secure_storage doesn't allow colons in keys)
    // Hash state with SHA256 to ensure it's safe for storage keys and doesn't leak CSRF token
    let state_hash = hex::encode(Sha256::digest(state_param.as_bytes()));
    let storage_key = format!("oauth_pkce_session_{state_hash}");
    let session_json = serde_json::to_string(&session).map_err(|e| {
        tracing::error!("Failed to serialize OAuth PKCE session: {e}");
        "Failed to start authentication. Please try again.".to_string()
    })?;
    state
        .secure_storage
        .save(&storage_key, &session_json)
        .await
        .map_err(|e| {
            tracing::error!("Failed to persist OAuth session: {e}");
            "Failed to start authentication. Please try again.".to_string()
        })?;

    // Store session for callback verification (warm start)
    // Store in memory ONLY after successful persistence to avoid leaks if persistence fails
    oauth_state.session_store.store(session.clone());

    Ok(StartOAuthResponse {
        auth_url,
        state: state_param,
    })
}

/// Handles an OAuth callback URL from deep linking.
///
/// This command:
/// 1. Parses the callback URL to extract code and state
/// 2. Verifies the state matches a pending session (CSRF protection)
/// 3. Exchanges the code for tokens and user info
/// 4. Creates/Updates local user record
/// 5. Establishes an authenticated session (JWT)
/// 6. Returns the authenticated user information
///
/// # Arguments
///
/// * `callback_url` - The full callback URL (e.g., `<aroeira://auth/callback?code=...&state=...>`)
///
/// # Returns
///
/// * `Ok(OAuthCallbackResponse)` - Authenticated user information
/// * `Err(String)` - If callback parsing fails, state mismatch, or exchange fails
///
/// # Errors
///
/// Returns an error string if:
/// - Callback URL is invalid
/// - Session is expired or invalid
/// - Token exchange fails
/// - User creation/retrieval fails
#[tauri::command]
pub async fn handle_oauth_callback(
    callback_url: String,
    oauth_state: State<'_, OAuthState>,
    state: State<'_, AppState>,
) -> Result<OAuthCallbackResponse, String> {
    const MAX_CALLBACK_LEN: usize = 8192;
    let device_id = get_device_id().map_err(|e| {
        tracing::error!(
            target: "security",
            outcome = "failure",
            reason = "device_id_unavailable",
            error = %e,
            "OAuth flow aborted: device ID unavailable"
        );
        "Authentication failed. Please try again.".to_string()
    })?;

    // Hash device_id for privacy in logs
    let mut hasher = Sha256::new();
    hasher.update(device_id.as_bytes());
    let device_id_hash = hex::encode(hasher.finalize());

    // Prevent DoS via excessive URL length
    if callback_url.len() > MAX_CALLBACK_LEN {
        tracing::warn!(
            target: "audit",
            outcome = "failure",
            reason = "callback_too_long",
            device_id = %device_id_hash,
            "OAuth callback URL exceeded max length"
        );
        return Err("Invalid authentication request".to_string());
    }

    // Parse callback URL
    let (code, state_param) = parse_oauth_callback_url(&callback_url).inspect_err(|_| {
        tracing::warn!(
            target: "audit",
            outcome = "failure",
            reason = "invalid_callback",
            device_id = %device_id_hash,
            "OAuth authentication failed: invalid callback URL"
        );
    })?;

    // Retrieve and consume session (CSRF protection)
    let session = retrieve_session(&state_param, oauth_state.inner(), state.inner())
        .await
        .inspect_err(|e| {
            tracing::warn!(
                target: "audit",
                outcome = "failure",
                reason = "session_retrieval_failed",
                device_id = %device_id_hash,
                error = %e,
                "OAuth session retrieval failed"
            );
        })?;

    // Exchange code for user info
    let user = match oauth_state
        .oauth_service
        .exchange_code(&session, code)
        .await
    {
        Ok(user) => user,
        Err(e) => {
            // Log failure with context - sanitize error to avoid leaking sensitive provider data
            tracing::warn!(
                target: "audit",
                outcome = "failure",
                reason = "code_exchange_failed",
                device_id = %device_id_hash,
                "OAuth authentication failed: code exchange error"
            );
            // Log only error type/category, not full details which may contain tokens/PII
            tracing::error!(
                error_type = std::any::type_name_of_val(&e),
                "OAuth code exchange failed for provider {:?}",
                session.provider
            );

            // Security: Do NOT restore session on failure.
            // OAuth2 state/code should be one-time use to prevent replay attacks.
            // Users must restart the flow if it fails.

            return Err("Authentication failed. Please try again.".to_string());
        }
    };

    // Application-Level Authentication
    let user_id = authenticate_or_create_user(&user, &session, &state).await?;

    // Get device ID for session binding
    // already have device_id from start of function

    // Generate email hash for consistent rate limit clearing
    let email_hash = hash_email_for_logging(
        &user.email.trim().to_ascii_lowercase(),
        state.rate_limit_key.expose_secret().as_bytes(),
    )
    .map_err(|_| "Internal security error".to_string())?;

    // Create session (JWT), store it, and clear rate limits
    handle_successful_login(user_id, &email_hash, &device_id, state.inner()).await?;

    // Log successful OAuth login (audit trail)
    log_oauth_success(user_id, &session, &user);

    Ok(OAuthCallbackResponse::from(user))
}

/// Checks which OAuth providers are available by querying the backend configuration.
///
/// This command:
/// 1. Checks if Google client ID is configured
/// 2. Checks if GitHub client ID is configured
///
/// # Arguments
///
/// * `oauth_state` - The OAuth managed state containing service configuration
///
/// # Returns
///
/// * `Ok(OAuthAvailability)` - Availability status for each provider
/// * `Err(String)` - If backend check fails
///
/// # Errors
///
/// Returns an error string if:
/// - Configuration check fails
#[tauri::command]
pub async fn get_oauth_availability(
    oauth_state: State<'_, OAuthState>,
) -> Result<OAuthAvailability, String> {
    Ok(OAuthAvailability {
        google: oauth_state.oauth_service.config.google_client_id.is_some(),
        github: oauth_state.oauth_service.config.github_client_id.is_some(),
    })
}

async fn retrieve_session(
    state_param: &str,
    oauth_state: &OAuthState,
    state: &AppState,
) -> Result<OAuthPkceSession, String> {
    // First try in-memory store (warm start), then fall back to secure storage (cold start)
    if let Some(session) = oauth_state.session_store.take(state_param) {
        // Warm start: session found in memory.

        // We should still clean up any persisted session that might exist (e.g. from start_oauth_flow)
        // to avoid leaving stale data in secure storage.
        let state_hash = hex::encode(Sha256::digest(state_param.as_bytes()));
        let storage_key = format!("oauth_pkce_session_{state_hash}");
        if let Err(e) = state.secure_storage.delete(&storage_key).await {
            tracing::warn!(
                target: "security",
                "Failed to delete persisted OAuth session from secure storage: {e}. \
                 Session will expire naturally but cleanup is incomplete."
            );
        }

        if session.state != state_param || !session.is_valid() || session.is_expired() {
            tracing::warn!(
                target: "audit",
                outcome = "failure",
                reason = "session_invalid_or_expired",
                "OAuth authentication failed: invalid or expired session"
            );
            return Err("Invalid or expired OAuth session. Please try again.".to_string());
        }

        Ok(session)
    } else {
        // Cold start: try to recover session from secure storage
        let state_hash = hex::encode(Sha256::digest(state_param.as_bytes()));
        let storage_key = format!("oauth_pkce_session_{state_hash}");
        let session_json = state
            .secure_storage
            .get(&storage_key)
            .await
            .map_err(|e| {
                tracing::error!("Failed to read persisted OAuth session: {e}");
                "Invalid or expired OAuth session. Please try again.".to_string()
            })?
            .ok_or_else(|| {
                tracing::warn!(
                    target: "audit",
                    outcome = "failure",
                    reason = "session_not_found",
                    "OAuth authentication failed: invalid or expired session"
                );
                "Invalid or expired OAuth session. Please try again.".to_string()
            })?;

        // Consume-once: delete regardless of parse outcome to prevent replay attempts.
        // Log failures but don't block auth flow - session expiry provides secondary protection.
        if let Err(e) = state.secure_storage.delete(&storage_key).await {
            tracing::warn!(
                target: "security",
                "Failed to delete persisted OAuth session from secure storage: {e}. \
                 Session will expire naturally but cleanup is incomplete."
            );
        }

        let recovered = serde_json::from_str::<OAuthPkceSession>(&session_json).map_err(|e| {
            tracing::error!("Failed to deserialize persisted OAuth session: {e}");
            "Invalid or expired OAuth session. Please try again.".to_string()
        })?;

        if recovered.state != state_param || !recovered.is_valid() || recovered.is_expired() {
            tracing::warn!(
                target: "audit",
                outcome = "failure",
                reason = "session_invalid_or_expired",
                "OAuth authentication failed: invalid or expired session"
            );
            return Err("Invalid or expired OAuth session. Please try again.".to_string());
        }

        Ok(recovered)
    }
}

async fn authenticate_or_create_user(
    user: &OAuthUser,
    session: &OAuthPkceSession,
    state: &AppState,
) -> Result<Uuid, String> {
    let normalized_email = user.email.trim().to_ascii_lowercase();

    // Fail closed: OAuth sign-in must only accept provider-verified emails.
    if !user.email_verified {
        tracing::warn!(
            target: "audit",
            outcome = "failure",
            reason = "oauth_email_not_verified",
            provider = %session.provider,
            email_domain = %user.email.rsplit_once('@').map_or("unknown", |(_, d)| d),
            "OAuth login rejected due to unverified email"
        );
        return Err("Authentication failed. Please use a verified email.".to_string());
    }

    match state.user_repo.find_by_email(&normalized_email).await {
        Ok(Some(mut u)) => {
            if !u.email_verified {
                // SECURITY CRITICAL: When verifying an existing unverified account via OAuth,
                // we MUST invalidate the old password to prevent account takeover.
                // Otherwise, an attacker who pre-registered the email could use the old password.
                let password_hash = generate_and_hash_oauth_password(session.provider).await?;

                u.email_verified = true;
                u.password_hash = password_hash; // Invalidate old password
                u.verification_token = None;
                u.verification_token_expires_at = None;

                state.user_repo.save(&u).await.map_err(|e| {
                    tracing::error!("Failed to update user verification from OAuth: {e}");
                    "Authentication failed".to_string()
                })?;
            }
            Ok(u.id)
        }
        Ok(None) => {
            // Create new user for OAuth

            // Generate a random high-entropy password that will never be shown to the user
            // This ensures the account cannot be accessed via password login unless explicitly reset
            let password_hash = generate_and_hash_oauth_password(session.provider).await?;

            let new_user = domain::modules::auth::User {
                id: Uuid::new_v4(),
                email: normalized_email.clone(),
                password_hash,
                email_verified: true, // We already verified this above
                verification_token: None,
                verification_token_expires_at: None,
            };

            match state.user_repo.save(&new_user).await {
                Ok(saved) => Ok(saved.id),
                Err(e) => {
                    // Concurrency safety: if another callback created the same email concurrently,
                    // re-fetch and proceed instead of failing the login.
                    tracing::warn!(
                        "User creation from OAuth failed (may be concurrent insert): {e}"
                    );
                    if let Ok(Some(existing)) =
                        state.user_repo.find_by_email(&normalized_email).await
                    {
                        Ok(existing.id)
                    } else {
                        tracing::error!("Failed to recover user after OAuth create conflict: {e}");
                        Err("Authentication failed".to_string())
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!("Database error finding user: {e}");
            Err("Authentication failed".to_string())
        }
    }
}

async fn generate_and_hash_oauth_password(provider: AuthProvider) -> Result<String, String> {
    // Generate a random high-entropy password that will never be shown to the user
    let oauth_random_password = format!("oauth:{}:{}", provider, Uuid::new_v4());

    // Use infra's hash_password which handles security config correctly
    // spawn_blocking is required because bcrypt is CPU-intensive and would block the async runtime
    tauri::async_runtime::spawn_blocking(move || hash_password(&oauth_random_password))
        .await
        .map_err(|e| {
            tracing::error!("Task join error during password hashing: {e}");
            "Authentication failed".to_string()
        })?
        .map_err(|e| {
            tracing::error!("Failed to hash generated OAuth password: {e}");
            "Authentication failed".to_string()
        })
}

fn log_oauth_success(user_id: Uuid, session: &OAuthPkceSession, user: &OAuthUser) {
    // Log successful OAuth login (audit trail) with essential context
    // Note: email and provider_user_id are hashed/redacted for privacy in logs
    let email_domain = user
        .email
        .rsplit_once('@')
        .map_or("unknown", |(_, domain)| domain);

    let mut hasher = Sha256::new();
    hasher.update(user.provider_user_id.as_bytes());
    let hashed_user_id = hex::encode(hasher.finalize());

    tracing::info!(
        target: "audit",
        user_id = %user_id,
        provider = %session.provider,
        provider_user_id_hash = %hashed_user_id,
        email_domain = %email_domain,
        outcome = "success",
        "OAuth authentication completed"
    );
}

/// Thread-safe storage for OAuth PKCE sessions.
///
/// Sessions are stored temporarily between:
/// 1. Generating the authorization URL
/// 2. Receiving the callback with authorization code
///
/// Sessions are automatically cleaned up when expired.
/// Uses `parking_lot::Mutex` for better async performance.
pub struct OAuthSessionStore {
    sessions: Mutex<HashMap<String, OAuthPkceSession>>,
}

impl OAuthSessionStore {
    /// Creates a new empty session store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Stores a session, keyed by its state value.
    ///
    /// Automatically cleans up expired sessions during this operation.
    pub fn store(&self, session: OAuthPkceSession) {
        const MAX_SESSIONS: usize = 512;
        let mut sessions = self.sessions.lock();

        // Clean up expired sessions
        sessions.retain(|_, s| !s.is_expired());

        // Enforce a hard cap to prevent memory growth (DoS prevention)
        if sessions.len() >= MAX_SESSIONS {
            tracing::warn!(
                target: "security",
                reason = "session_store_full",
                "OAuth session store reached max capacity ({MAX_SESSIONS}). Evicting oldest session."
            );
            // Remove oldest session directly
            if let Some(oldest_key) = sessions
                .iter()
                .min_by_key(|(_, s)| s.created_at)
                .map(|(k, _)| k.clone())
            {
                sessions.remove(&oldest_key);
            }
        }

        // Store new session
        sessions.insert(session.state.clone(), session);
    }

    /// Takes a session by its state value, removing it from storage.
    ///
    /// Returns `None` if:
    /// - Session doesn't exist
    /// - Session has expired
    #[must_use]
    pub fn take(&self, state: &str) -> Option<OAuthPkceSession> {
        let mut sessions = self.sessions.lock();

        // Proactively clean up expired sessions to prevent memory leaks
        sessions.retain(|_, s| !s.is_expired());

        if sessions.get(state).is_some_and(|s| !s.is_valid()) {
            sessions.remove(state);
            return None;
        }

        // Remove and return (expiration already checked by retain)
        sessions.remove(state)
    }
}

impl Default for OAuthSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses an OAuth callback URL to extract code and state.
///
/// # Arguments
///
/// * `callback_url` - The full callback URL (e.g., `<aroeira://auth/callback?code=...&state=...>`)
///
/// # Returns
///
/// * `Ok((code, state))` - The authorization code and state parameter
/// * `Err(String)` - Generic user-safe error message (details logged internally)
///
/// # Errors
///
/// Returns a generic error if:
/// - URL cannot be parsed
/// - URL scheme is not "aroeira"
/// - URL host is not "auth" or path is not "/callback"
/// - Code or state parameters are missing or empty
/// - Error parameter is present (OAuth error response)
///
/// # Security
///
/// This function returns generic error messages to prevent leaking internal
/// validation logic. Specific details are logged internally for debugging.
pub fn parse_oauth_callback_url(callback_url: &str) -> Result<(String, String), String> {
    use crate::constants::{OAUTH_CALLBACK_HOST, OAUTH_CALLBACK_PATH, OAUTH_CALLBACK_SCHEME};

    // Generic error message for all validation failures
    const GENERIC_ERROR: &str = "Invalid authentication callback. Please try again.";
    const MAX_CODE_LEN: usize = 4096;
    const MAX_STATE_LEN: usize = 512;

    let url = Url::parse(callback_url).map_err(|e| {
        tracing::warn!("OAuth callback URL parse error: {e}");
        GENERIC_ERROR.to_string()
    })?;

    // Enforce expected deep-link callback origin using constants
    if url.scheme() != OAUTH_CALLBACK_SCHEME {
        tracing::warn!(
            expected = OAUTH_CALLBACK_SCHEME,
            actual = url.scheme(),
            "OAuth callback: invalid scheme"
        );
        return Err(GENERIC_ERROR.to_string());
    }

    // Handle both canonical (with host) and hostless (deep link) formats
    // canonical: aroeira://auth/callback
    // hostless: aroeira:///auth/callback (appears as path "//auth/callback" with no host)
    let is_canonical =
        url.host_str() == Some(OAUTH_CALLBACK_HOST) && url.path() == OAUTH_CALLBACK_PATH;
    let is_hostless = url.host_str().is_none()
        && url.path().trim_start_matches('/')
            == format!(
                "{}/{}",
                OAUTH_CALLBACK_HOST,
                OAUTH_CALLBACK_PATH.trim_start_matches('/')
            );

    // Note: OAUTH_CALLBACK_HOST is "auth" and OAUTH_CALLBACK_PATH is "/callback"
    // So hostless path check is against "/auth/callback"

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

    // Check for error response from OAuth provider
    if let Some((_, error_code)) = url.query_pairs().find(|(k, _)| k == "error") {
        // Log only the error code (standard OAuth error codes like "access_denied")
        // Do NOT log error_description as it may contain sensitive user-specific details
        tracing::info!(
            error_code = %error_code,
            "OAuth provider returned error"
        );
        return Err("Authentication was denied or failed. Please try again.".to_string());
    }

    // Helper to extract query parameters
    let get_query_param = |key: &str| -> Result<String, String> {
        url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                tracing::warn!("OAuth callback: missing or empty {} parameter", key);
                GENERIC_ERROR.to_string()
            })
    };

    let code = get_query_param("code")?;
    let state = get_query_param("state")?;

    if code.len() > MAX_CODE_LEN || state.len() > MAX_STATE_LEN {
        tracing::warn!(
            code_len = code.len(),
            state_len = state.len(),
            "OAuth callback: code/state too large"
        );
        return Err(GENERIC_ERROR.to_string());
    }

    // Security: Validate state charset to prevent injection/ambiguity.
    // Accept only unreserved URI characters (RFC 3986): ALPHA / DIGIT / "-" / "." / "_" / "~".
    // Note: `Url::query_pairs()` decodes '+' as space, so disallow whitespace explicitly.
    if state.chars().any(char::is_whitespace)
        || !state
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
    {
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

    Ok((code, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::modules::auth::oauth::{AuthProvider, OAuthPkceSession};

    // ===========================================
    // OAuthSessionStore Tests
    // ===========================================

    #[test]
    fn session_store_returns_none_for_unknown_state() {
        let store = OAuthSessionStore::new();
        assert!(store.take("unknown-state").is_none());
    }

    #[test]
    fn session_store_returns_session_once_then_removes() {
        let store = OAuthSessionStore::new();
        let session = OAuthPkceSession::new(
            "test-state".to_string(),
            "a".repeat(43),
            AuthProvider::Google,
        );

        store.store(session);

        // First take succeeds
        let retrieved = store.take("test-state");
        assert!(retrieved.is_some());

        // Second take fails (session consumed)
        assert!(store.take("test-state").is_none());
    }

    #[test]
    fn session_store_handles_multiple_sessions() {
        let store = OAuthSessionStore::new();

        let session1 =
            OAuthPkceSession::new("state-1".to_string(), "a".repeat(43), AuthProvider::Google);
        let session2 =
            OAuthPkceSession::new("state-2".to_string(), "b".repeat(43), AuthProvider::GitHub);

        store.store(session1);
        store.store(session2);

        // Can retrieve both independently
        let s1 = store.take("state-1");
        assert!(s1.is_some());
        assert_eq!(s1.unwrap().provider, AuthProvider::Google);

        let s2 = store.take("state-2");
        assert!(s2.is_some());
        assert_eq!(s2.unwrap().provider, AuthProvider::GitHub);

        // Both consumed
        assert!(store.take("state-1").is_none());
        assert!(store.take("state-2").is_none());
    }

    #[test]
    fn session_store_cleans_expired_sessions_on_store() {
        use chrono::{Duration as ChronoDuration, Utc};

        let store = OAuthSessionStore::new();

        // Store an expired session
        let mut old_session = OAuthPkceSession::new(
            "old-state".to_string(),
            "a".repeat(43),
            AuthProvider::Google,
        );
        old_session.created_at = Utc::now() - ChronoDuration::minutes(15);
        store.store(old_session);

        // Store a new session (triggers cleanup)
        let new_session = OAuthPkceSession::new(
            "new-state".to_string(),
            "a".repeat(43),
            AuthProvider::GitHub,
        );
        store.store(new_session);

        // Old session should be gone (expired)
        assert!(store.take("old-state").is_none());
        // New session should exist
        assert!(store.take("new-state").is_some());
    }

    #[test]
    fn session_store_preserves_unexpired_sessions() {
        use chrono::{Duration as ChronoDuration, Utc};

        let store = OAuthSessionStore::new();

        // Store a session that's 5 minutes old (not expired - TTL is 10 min)
        let mut recent_session = OAuthPkceSession::new(
            "recent-state".to_string(),
            "a".repeat(43),
            AuthProvider::Google,
        );
        recent_session.created_at = Utc::now() - ChronoDuration::minutes(5);
        store.store(recent_session);

        // Store another session (triggers cleanup, but shouldn't remove the 5-min-old one)
        let new_session = OAuthPkceSession::new(
            "new-state".to_string(),
            "b".repeat(43),
            AuthProvider::GitHub,
        );
        store.store(new_session);

        // Both sessions should still exist
        assert!(store.take("recent-state").is_some());
        assert!(store.take("new-state").is_some());
    }

    // ===========================================
    // URL Parsing Tests
    // ===========================================

    #[test]
    fn parse_callback_url_extracts_code_and_state() {
        let url = "aroeira://auth/callback?code=abc123&state=xyz789";
        let (code, state) = parse_oauth_callback_url(url).expect("Should parse valid URL");

        assert_eq!(code, "abc123");
        assert_eq!(state, "xyz789");
    }

    #[test]
    fn parse_callback_url_fails_without_code() {
        let url = "aroeira://auth/callback?state=xyz789";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
    }

    #[test]
    fn parse_callback_url_fails_without_state() {
        let url = "aroeira://auth/callback?code=abc123";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
    }

    #[test]
    fn parse_callback_url_fails_on_invalid_url() {
        let url = "not a valid url";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
    }

    #[test]
    fn parse_callback_url_handles_url_encoded_values() {
        // state uses only allowed unreserved characters (RFC 3986)
        // code uses + which is allowed in code but not state (per our strict rule)
        // %2B encodes +
        let url = "aroeira://auth/callback?code=abc%2B123&state=xyz-789";
        let (code, state) = parse_oauth_callback_url(url).expect("Should parse URL-encoded values");

        assert_eq!(code, "abc+123");
        assert_eq!(state, "xyz-789");
    }

    #[test]
    fn parse_callback_url_handles_error_response() {
        let url = "aroeira://auth/callback?error=access_denied&error_description=User%20denied";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
        let err = result.unwrap_err();
        // Error should be generic, not expose provider details
        assert!(err.contains("denied") || err.contains("failed"));
    }

    #[test]
    fn parse_callback_url_rejects_wrong_scheme() {
        let url = "https://auth/callback?code=abc123&state=xyz789";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
        // Error should be generic, not exposing internal validation details
        assert!(
            result
                .unwrap_err()
                .contains("Invalid authentication callback")
        );
    }

    #[test]
    fn parse_callback_url_rejects_wrong_host() {
        let url = "aroeira://malicious/callback?code=abc123&state=xyz789";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
        // Error should be generic, not exposing internal validation details
        assert!(
            result
                .unwrap_err()
                .contains("Invalid authentication callback")
        );
    }

    #[test]
    fn parse_callback_url_rejects_wrong_path() {
        let url = "aroeira://auth/malicious?code=abc123&state=xyz789";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
        // Error should be generic, not exposing internal validation details
        assert!(
            result
                .unwrap_err()
                .contains("Invalid authentication callback")
        );
    }

    #[test]
    fn parse_callback_url_rejects_empty_code() {
        let url = "aroeira://auth/callback?code=&state=xyz789";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
        // Error should be generic, not exposing internal validation details
        assert!(
            result
                .unwrap_err()
                .contains("Invalid authentication callback")
        );
    }

    #[test]
    fn parse_callback_url_rejects_empty_state() {
        let url = "aroeira://auth/callback?code=abc123&state=";
        let result = parse_oauth_callback_url(url);

        assert!(result.is_err());
        // Error should be generic, not exposing internal validation details
        assert!(
            result
                .unwrap_err()
                .contains("Invalid authentication callback")
        );
    }
}
