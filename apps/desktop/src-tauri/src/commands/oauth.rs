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

use crate::commands::auth::{
    generate_request_id, get_device_id, handle_successful_login, hash_email_for_logging,
};
use crate::state::AppState;
use domain::modules::auth::AuthError;
use domain::modules::auth::oauth::{AuthProvider, OAuthPkceSession, OAuthService, OAuthUser};
use hex;
use infra::services::oauth::{OAuthConfig, OAuthServiceImpl, PkceSessionStorage};
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
    /// PKCE session storage using OS keyring
    pkce_storage: Arc<dyn PkceSessionStorage>,
}

impl OAuthState {
    /// Creates new OAuth state with given configuration.
    #[must_use]
    pub fn new(config: OAuthConfig) -> Self {
        let pkce_storage: Arc<dyn PkceSessionStorage> =
            Arc::new(infra::services::oauth::KeyringPkceStorage);
        Self {
            session_store: OAuthSessionStore::new(pkce_storage.clone()),
            oauth_service: Arc::new(OAuthServiceImpl::new(config)),
            pkce_storage,
        }
    }

    /// Creates new OAuth state with custom PKCE storage (for testing).
    #[cfg(test)]
    #[must_use]
    pub fn new_with_storage(
        config: OAuthConfig,
        pkce_storage: Arc<dyn PkceSessionStorage>,
    ) -> Self {
        Self {
            session_store: OAuthSessionStore::new(pkce_storage.clone()),
            oauth_service: Arc::new(OAuthServiceImpl::new(config)),
            pkce_storage,
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
    _state: State<'_, AppState>,
) -> Result<StartOAuthResponse, String> {
    let request_id = generate_request_id();
    let device_id = get_device_id().map_err(|e| {
        tracing::error!(
            target: "security",
            request_id = %request_id,
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
                request_id = %request_id,
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
        request_id = %request_id,
        action = "oauth_start",
        provider = %provider,
        device_id = %device_id_hash,
        "Starting OAuth flow"
    );

    let state_param = session.state.clone();

    // Persist session for cold start recovery (deep link opens closed app)
    // One-time use: deleted after successful `take` on callback.
    // Hash state with SHA256 to ensure it's safe for storage keys and doesn't leak CSRF token
    let state_hash = hex::encode(Sha256::digest(state_param.as_bytes()));
    let session_json = serde_json::to_string(&session).map_err(|e| {
        tracing::error!(
            target: "security",
            request_id = %request_id,
            outcome = "failure",
            reason = "session_serialization_failed",
            error = %e,
            "Failed to serialize OAuth PKCE session"
        );
        "Failed to start authentication. Please try again.".to_string()
    })?;

    // Store PKCE session in OS keyring for secure persistence (encryption at rest).
    // This protects the PKCE verifier from unauthorized access.
    let pkce_storage = oauth_state.pkce_storage.clone();
    let state_hash_clone = state_hash.clone();
    match tokio::task::spawn_blocking(move || {
        pkce_storage.save_session(&state_hash_clone, &session_json)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::error!(
                target: "security",
                request_id = %request_id,
                outcome = "failure",
                reason = "session_persistence_failed",
                error = %e,
                "Failed to persist OAuth session to keyring"
            );
            return Err("Failed to start authentication. Please try again.".to_string());
        }
        Err(e) => {
            tracing::error!(
                target: "security",
                request_id = %request_id,
                outcome = "failure",
                reason = "session_persistence_task_failed",
                error = %e,
                "Failed to persist OAuth session to keyring (task join error)"
            );
            return Err("Failed to start authentication. Please try again.".to_string());
        }
    }

    // Store session for callback verification (warm start)
    // Store in memory ONLY after successful persistence to avoid leaks if persistence fails
    oauth_state.session_store.store(session.clone());

    Ok(StartOAuthResponse {
        auth_url,
        state: state_param,
    })
}

/// Validates the OAuth callback URL and extracts code and state.
fn validate_and_parse_callback(
    callback_url: &str,
    request_id: &str,
    device_id_hash: &str,
) -> Result<(String, String), String> {
    const MAX_CALLBACK_LEN: usize = 8192;

    // Prevent DoS via excessive URL length
    if callback_url.len() > MAX_CALLBACK_LEN {
        tracing::warn!(
            target: "audit",
            request_id = %request_id,
            outcome = "failure",
            reason = "callback_too_long",
            device_id = %device_id_hash,
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
            device_id = %device_id_hash,
            "OAuth authentication failed: invalid callback URL"
        );
    })?;

    let state_hash_for_log = hex::encode(Sha256::digest(state_param.as_bytes()));
    tracing::info!(
        target: "oauth_debug",
        request_id = %request_id,
        state_hash = %state_hash_for_log,
        "Callback parsed successfully"
    );

    Ok((code, state_param))
}

/// Exchanges OAuth code for user info with logging.
async fn exchange_code_for_user(
    oauth_state: &OAuthState,
    session: &domain::modules::auth::oauth::OAuthPkceSession,
    code: String,
    request_id: &str,
    device_id_hash: &str,
) -> Result<OAuthUser, String> {
    match oauth_state.oauth_service.exchange_code(session, code).await {
        Ok(user) => Ok(user),
        Err(e) => {
            tracing::warn!(
                target: "audit",
                request_id = %request_id,
                outcome = "failure",
                reason = "code_exchange_failed",
                device_id = %device_id_hash,
                "OAuth authentication failed: code exchange error"
            );
            // Only log debug OAuth details when explicitly enabled
            if cfg!(debug_assertions) && std::env::var_os("AROEIRA_OAUTH_DEBUG").is_some() {
                tracing::debug!(
                        target: "oauth_debug",
                        request_id = %request_id,
                        error_details = %e,
                        "OAuth code exchange failed for provider {:?}",
                        session.provider
                );
            }
            Err("Authentication failed. Please try again.".to_string())
        }
    }
}

/// Finalizes OAuth login by creating user session and logging success.
async fn finalize_oauth_login(
    user: &OAuthUser,
    session: &domain::modules::auth::oauth::OAuthPkceSession,
    state: &AppState,
    device_id: &str,
    request_id: &str,
) -> Result<OAuthCallbackResponse, String> {
    let user_id = authenticate_or_create_user(user, session, state, request_id).await?;

    let email_hash = hash_email_for_logging(
        &user.email.trim().to_ascii_lowercase(),
        state.rate_limit_key.expose_secret().as_bytes(),
    )
    .map_err(|_| "Internal security error".to_string())?;

    handle_successful_login(user_id, &email_hash, device_id, state).await?;
    log_oauth_success(user_id, session, user, request_id);

    Ok(OAuthCallbackResponse::from(user.clone()))
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
    let request_id = generate_request_id();

    tracing::info!(
        target: "oauth_debug",
        request_id = %request_id,
        callback_path = "/auth/callback",
        "OAuth callback received"
    );

    let device_id = get_device_id().map_err(|e| {
        tracing::error!(
            target: "security",
            request_id = %request_id,
            outcome = "failure",
            reason = "device_id_unavailable",
            error = %e,
            "OAuth flow aborted: device ID unavailable"
        );
        "Authentication failed. Please try again.".to_string()
    })?;

    let mut hasher = Sha256::new();
    hasher.update(device_id.as_bytes());
    let device_id_hash = hex::encode(hasher.finalize());

    let (code, state_param) =
        validate_and_parse_callback(&callback_url, &request_id, &device_id_hash)?;

    let session = retrieve_session(&state_param, &oauth_state, &state, &request_id)
        .await
        .inspect_err(|e| {
            tracing::error!(
                target: "oauth_debug",
                request_id = %request_id,
                error = %e,
                "Session retrieval failed"
            );
            tracing::warn!(
                target: "audit",
                request_id = %request_id,
                outcome = "failure",
                reason = "session_retrieval_failed",
                device_id = %device_id_hash,
                error = %e,
                "OAuth session retrieval failed"
            );
        })?;

    let user =
        exchange_code_for_user(&oauth_state, &session, code, &request_id, &device_id_hash).await?;

    finalize_oauth_login(&user, &session, &state, &device_id, &request_id).await
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

/// Retrieves session from in-memory store (warm start).
async fn retrieve_warm_session(
    state_param: &str,
    oauth_state: &OAuthState,
    state_hash: &str,
    request_id: &str,
) -> Option<OAuthPkceSession> {
    let session = oauth_state
        .session_store
        .take_valid(state_param, request_id)?;

    // Session is valid - clean up persisted session from keyring.
    let pkce_storage = oauth_state.pkce_storage.clone();
    let state_hash_clone = state_hash.to_string();
    match tokio::task::spawn_blocking(move || pkce_storage.delete_session(&state_hash_clone)).await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::warn!(
                target: "security",
                request_id = %request_id,
                "Failed to delete persisted OAuth session from keyring: {e}. Session will be cleaned up separately."
            );
        }
        Err(e) => {
            tracing::warn!(
                target: "security",
                request_id = %request_id,
                "Failed to delete persisted OAuth session from keyring due to task failure: {e}. Session will be cleaned up separately."
            );
        }
    }

    Some(session)
}

/// Retrieves session from keyring (cold start).
async fn retrieve_cold_session(
    state_param: &str,
    oauth_state: &OAuthState,
    state_hash: &str,
    request_id: &str,
) -> Result<OAuthPkceSession, String> {
    const MAX_SESSION_JSON_BYTES: usize = 16 * 1024;

    let pkce_storage = oauth_state.pkce_storage.clone();
    let state_hash_clone = state_hash.to_string();
    let session_json =
        tokio::task::spawn_blocking(move || pkce_storage.get_session(&state_hash_clone))
            .await
            .map_err(|e| {
                tracing::error!(
                    target: "security",
                    request_id = %request_id,
                    outcome = "failure",
                    reason = "session_read_failed",
                    error = %e,
                    "Failed to read persisted OAuth session from keyring"
                );
                "Invalid or expired OAuth session. Please try again.".to_string()
            })?
            .map_err(|e| {
                tracing::error!(
                    target: "security",
                    request_id = %request_id,
                    outcome = "failure",
                    reason = "session_read_failed",
                    error = %e,
                    "Failed to read persisted OAuth session from keyring"
                );
                "Invalid or expired OAuth session. Please try again.".to_string()
            })?
            .ok_or_else(|| {
                tracing::warn!(
                    target: "audit",
                    request_id = %request_id,
                    outcome = "failure",
                    reason = "session_not_found",
                    "OAuth authentication failed: invalid or expired session"
                );
                "Invalid or expired OAuth session. Please try again.".to_string()
            })?;

    if session_json.len() > MAX_SESSION_JSON_BYTES {
        tracing::warn!(
            target: "security",
            request_id = %request_id,
            reason = "persisted_session_too_large",
            size = session_json.len(),
            "Persisted OAuth session exceeded max size"
        );
        return Err("Invalid or expired OAuth session. Please try again.".to_string());
    }

    let recovered = serde_json::from_str::<OAuthPkceSession>(&session_json).map_err(|e| {
        tracing::error!(
            target: "security",
            request_id = %request_id,
            outcome = "failure",
            reason = "session_deserialization_failed",
            error = %e,
            "Failed to deserialize persisted OAuth session"
        );
        "Invalid or expired OAuth session. Please try again.".to_string()
    })?;

    if recovered.state != state_param || !recovered.is_valid() || recovered.is_expired() {
        tracing::warn!(
            target: "audit",
            request_id = %request_id,
            outcome = "failure",
            reason = "session_invalid_or_expired",
            "OAuth authentication failed: invalid or expired session"
        );

        cleanup_invalid_persisted_session(oauth_state, state_hash, request_id).await;

        return Err("Invalid or expired OAuth session. Please try again.".to_string());
    }

    // Consume-once: delete from keyring only after successful validation.
    let pkce_storage = oauth_state.pkce_storage.clone();
    let state_hash_clone = state_hash.to_string();
    match tokio::task::spawn_blocking(move || pkce_storage.delete_session(&state_hash_clone)).await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::warn!(
                target: "security",
                request_id = %request_id,
                "Failed to delete persisted OAuth session from keyring: {e}. Session will expire naturally but cleanup is incomplete."
            );
        }
        Err(e) => {
            tracing::warn!(
                target: "security",
                request_id = %request_id,
                "Failed to delete persisted OAuth session from keyring due to task failure: {e}. Session will expire naturally but cleanup is incomplete."
            );
        }
    }

    Ok(recovered)
}

/// Helper to cleanup an invalid persisted session from keyring.
async fn cleanup_invalid_persisted_session(
    oauth_state: &OAuthState,
    state_hash: &str,
    request_id: &str,
) {
    let pkce_storage = oauth_state.pkce_storage.clone();
    let state_hash_clone = state_hash.to_string();
    match tokio::task::spawn_blocking(move || pkce_storage.delete_session(&state_hash_clone)).await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(
            target: "security",
            request_id = %request_id,
            "Failed to delete invalid persisted OAuth session from keyring: {e}"
        ),
        Err(e) => tracing::warn!(
            target: "security",
            request_id = %request_id,
            "Failed to delete invalid persisted OAuth session from keyring due to task failure: {e}"
        ),
    }
}

async fn retrieve_session(
    state_param: &str,
    oauth_state: &OAuthState,
    _state: &AppState,
    request_id: &str,
) -> Result<OAuthPkceSession, String> {
    let state_hash = hex::encode(Sha256::digest(state_param.as_bytes()));

    // Try warm start first, then cold start
    if let Some(session) =
        retrieve_warm_session(state_param, oauth_state, &state_hash, request_id).await
    {
        Ok(session)
    } else {
        retrieve_cold_session(state_param, oauth_state, &state_hash, request_id).await
    }
}

async fn authenticate_or_create_user(
    user: &OAuthUser,
    session: &OAuthPkceSession,
    state: &AppState,
    request_id: &str,
) -> Result<Uuid, String> {
    let normalized_email = user.email.trim().to_ascii_lowercase();

    // Fail closed: OAuth sign-in must only accept provider-verified emails.
    if !user.email_verified {
        tracing::warn!(
            target: "audit",
            request_id = %request_id,
            outcome = "failure",
            reason = "oauth_email_not_verified",
            provider = %session.provider,
            email_domain = %user.email.rsplit_once('@').map_or("unknown", |(_, d)| d),
            "OAuth login rejected due to unverified email"
        );
        return Err("Authentication failed. Please use a verified email.".to_string());
    }

    match state.user_repo.find_by_email(&normalized_email).await {
        Ok(Some(mut user)) => {
            if !user.email_verified {
                // SECURITY CRITICAL: When verifying an existing unverified account via OAuth,
                // we MUST invalidate the old password to prevent account takeover.
                // Otherwise, an attacker who pre-registered the email could use the old password.
                let password_hash = generate_and_hash_oauth_password(session.provider).await?;

                user.email_verified = true;
                user.password_hash = password_hash; // Invalidate old password
                user.verification_token = None;
                user.verification_token_expires_at = None;

                state.user_repo.save(&user).await.map_err(|e| {
                    tracing::error!(
                        request_id = %request_id,
                        "Failed to update user verification from OAuth: {e}"
                    );
                    "Authentication failed".to_string()
                })?;
            }
            Ok(user.id)
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
                Err(AuthError::EmailAlreadyExists) => {
                    // Concurrency safety: if another callback created the same email concurrently,
                    // re-fetch and proceed instead of failing the login.
                    tracing::warn!(
                        request_id = %request_id,
                        "User creation from OAuth failed due to concurrent insert (EmailAlreadyExists)"
                    );
                    if let Ok(Some(existing)) =
                        state.user_repo.find_by_email(&normalized_email).await
                    {
                        Ok(existing.id)
                    } else {
                        tracing::error!(
                            request_id = %request_id,
                            "Failed to recover user after OAuth create conflict"
                        );
                        Err("Authentication failed".to_string())
                    }
                }
                Err(e) => {
                    tracing::error!(
                        request_id = %request_id,
                        "Failed to save new OAuth user due to unexpected database error: {e}"
                    );
                    Err("Authentication failed".to_string())
                }
            }
        }
        Err(e) => {
            tracing::error!(
                request_id = %request_id,
                "Database error finding user: {e}"
            );
            Err("Authentication failed".to_string())
        }
    }
}

async fn generate_and_hash_oauth_password(_provider: AuthProvider) -> Result<String, String> {
    // Generate a random high-entropy password that will never be shown to the user
    let oauth_random_password = Uuid::new_v4().to_string();

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

fn log_oauth_success(
    user_id: Uuid,
    session: &OAuthPkceSession,
    user: &OAuthUser,
    request_id: &str,
) {
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
        request_id = %request_id,
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
///
/// # Security Note
///
/// When evicting sessions due to capacity limits, also deletes from
/// the persistent keyring storage to prevent stale data accumulation.
#[derive(Clone)]
pub struct OAuthSessionStore {
    sessions: Arc<Mutex<HashMap<String, OAuthPkceSession>>>,
    pkce_storage: Arc<dyn PkceSessionStorage>,
}

impl OAuthSessionStore {
    /// Creates a new empty session store with keyring storage.
    #[must_use]
    pub fn new(pkce_storage: Arc<dyn PkceSessionStorage>) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            pkce_storage,
        }
    }

    /// Takes a session by its state value, validating it before removal.
    ///
    /// Returns `None` if:
    /// - Session doesn't exist
    /// - Session state doesn't match
    /// - Session is invalid or has expired
    #[must_use]
    pub fn take_valid(&self, state: &str, request_id: &str) -> Option<OAuthPkceSession> {
        let mut sessions = self.sessions.lock();
        sessions.retain(|_, s| !s.is_expired());

        let is_valid = sessions
            .get(state)
            .is_some_and(|s| s.state == state && s.is_valid() && !s.is_expired());

        if !is_valid {
            tracing::warn!(
                target: "audit",
                request_id = %request_id,
                outcome = "failure",
                reason = "session_invalid_or_expired",
                "OAuth authentication failed: invalid or expired session"
            );
            // If present but invalid, remove it to prevent reuse.
            let removed = sessions.remove(state);

            // Best-effort cleanup of persisted session to avoid stale sensitive data.
            if removed.is_some() {
                let pkce_storage = self.pkce_storage.clone();
                let state_hash = hex::encode(Sha256::digest(state.as_bytes()));

                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.spawn(async move {
                        let _ = tokio::task::spawn_blocking(move || {
                            pkce_storage.delete_session(&state_hash)
                        })
                        .await;
                    });
                }
            }

            return None;
        }

        sessions.remove(state)
    }

    /// Stores a session, keyed by its state value.
    ///
    /// Automatically cleans up expired sessions during this operation.
    /// When evicting due to capacity limits, also deletes from keyring.
    pub fn store(&self, session: OAuthPkceSession) {
        const MAX_SESSIONS: usize = 512;

        let (evicted_state_hash, pkce_storage) = {
            let mut sessions = self.sessions.lock();

            // Clean up expired sessions
            sessions.retain(|_, s| !s.is_expired());

            // Enforce a hard cap to prevent memory growth (DoS prevention)
            // Find oldest first, then remove in separate step to avoid borrow checker issues
            let oldest_key = sessions
                .iter()
                .min_by_key(|(_, s)| s.created_at)
                .map(|(k, _)| k.clone());

            let evicted_state_hash = if sessions.len() >= MAX_SESSIONS {
                oldest_key.map(|key| {
                    let state_hash = hex::encode(Sha256::digest(key.as_bytes()));
                    tracing::warn!(
                        target: "security",
                        reason = "session_store_full",
                        evicted_state_hash = %state_hash,
                        "OAuth session store reached max capacity ({MAX_SESSIONS}). Evicting oldest session."
                    );
                    sessions.remove(&key);
                    state_hash
                })
            } else {
                None
            };

            // Store new session while still holding the lock to preserve the cap invariant.
            sessions.insert(session.state.clone(), session);

            (evicted_state_hash, self.pkce_storage.clone())
        };

        if let Some(state_hash) = evicted_state_hash {
            let state_hash_clone = state_hash.clone();

            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    match tokio::task::spawn_blocking(move || {
                        pkce_storage.delete_session(&state_hash_clone)
                    })
                    .await
                    {
                        Ok(Ok(())) => tracing::debug!(
                            target: "security",
                            state_hash = %state_hash,
                            "Evicted session deleted from keyring"
                        ),
                        Ok(Err(e)) => tracing::warn!(
                            target: "security",
                            state_hash = %state_hash,
                            "Failed to delete evicted session from keyring: {e}"
                        ),
                        Err(e) => tracing::warn!(
                            target: "security",
                            state_hash = %state_hash,
                            "Task failed when deleting evicted session from keyring: {e}"
                        ),
                    }
                });
            } else {
                tracing::warn!(
                    target: "security",
                    state_hash = %state_hash_clone,
                    "No Tokio runtime found to clean up evicted session from keyring. It will be left to expire."
                );
            }
        }
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
    /// Performs a background cleanup of stale sessions from the keyring.
    ///
    /// This should be called on application startup to ensure that any
    /// sessions left over from crashes or forceful terminations are removed.
    pub fn cleanup_stale_sessions(&self) {
        // This is a placeholder for future implementation.
        // Currently, the keyring API doesn't support listing entries, so we can't
        // easily sweep for stale sessions without maintaining a separate index.
        // For now, we rely on the "consume-once" and "evict-on-full" policies
        // to keep the keyring usage bounded.
        tracing::debug!("OAuth session cleanup initiated (placeholder)");
    }
}

impl Default for OAuthSessionStore {
    fn default() -> Self {
        let pkce_storage: Arc<dyn PkceSessionStorage> =
            Arc::new(infra::services::oauth::KeyringPkceStorage);
        Self::new(pkce_storage)
    }
}

/// Helper to extract query parameters manually, preserving '+' signs.
///
/// `Url::query_pairs()` treats '+' as space (application/x-www-form-urlencoded).
/// OAuth codes (and potentially state) are often base64-like and may contain '+'.
/// We use `percent_encoding` directly to decode '%XX' but leave '+' as is.
fn parse_query_preserving_plus(query: &str) -> Result<Vec<(String, String)>, String> {
    const GENERIC_ERROR: &str = "Invalid authentication callback. Please try again.";

    let mut query_pairs = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));

        let k = percent_encoding::percent_decode_str(k)
            .decode_utf8()
            .map_err(|_| GENERIC_ERROR.to_string())?
            .to_string();
        let v = percent_encoding::percent_decode_str(v)
            .decode_utf8()
            .map_err(|_| GENERIC_ERROR.to_string())?
            .to_string();
        query_pairs.push((k, v));
    }
    Ok(query_pairs)
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
    // Generic error message for all validation failures
    const GENERIC_ERROR: &str = "Invalid authentication callback. Please try again.";

    let url = Url::parse(callback_url).map_err(|e| {
        tracing::warn!("OAuth callback URL parse error: {e}");
        GENERIC_ERROR.to_string()
    })?;

    validate_callback_url_base(&url)?;
    extract_and_validate_params(&url)
}

/// Validates the basic structure (scheme, host, path) of the callback URL.
fn validate_callback_url_base(url: &Url) -> Result<(), String> {
    use crate::constants::{OAUTH_CALLBACK_HOST, OAUTH_CALLBACK_PATH, OAUTH_CALLBACK_SCHEME};
    const GENERIC_ERROR: &str = "Invalid authentication callback. Please try again.";
    const HOSTLESS_PATH: &str = "auth/callback";

    // Handle both production (aroeira://) and dev mode (http://localhost) callbacks
    let dev_port: u16 = std::env::var("AROEIRA_DEV_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(1420);

    let is_aroeira_protocol = url.scheme() == OAUTH_CALLBACK_SCHEME;
    let is_localhost_dev = cfg!(debug_assertions)
        && url.scheme() == "http"
        && url.host_str() == Some("localhost")
        && url.port() == Some(dev_port)
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

/// Extracts and performs security validation on the OAuth code and state parameters.
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

    Ok((code, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::modules::auth::oauth::{AuthProvider, OAuthPkceSession};

    /// Mock PKCE storage for testing that does nothing (no-op).
    struct MockPkceStorage;
    impl PkceSessionStorage for MockPkceStorage {
        fn save_session(&self, _state_hash: &str, _session: &str) -> Result<(), String> {
            Ok(())
        }
        fn get_session(&self, _state_hash: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn delete_session(&self, _state_hash: &str) -> Result<(), String> {
            Ok(())
        }
    }

    fn create_mock_store() -> OAuthSessionStore {
        OAuthSessionStore::new(Arc::new(MockPkceStorage))
    }

    // ===========================================
    // OAuthSessionStore Tests
    // ===========================================

    #[test]
    fn session_store_returns_none_for_unknown_state() {
        let store = create_mock_store();
        assert!(store.take("unknown-state").is_none());
    }

    #[test]
    fn session_store_returns_session_once_then_removes() {
        let store = create_mock_store();
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
        let store = create_mock_store();

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

        let store = create_mock_store();

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

        let store = create_mock_store();

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
