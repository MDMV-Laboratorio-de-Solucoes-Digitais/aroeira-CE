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
use crate::oauth::session_store::OAuthSessionStore;
use crate::oauth_utils::validate_and_parse_callback;
use crate::state::AppState;
use domain::modules::auth::AuthError;
use domain::modules::auth::oauth::{AuthProvider, OAuthPkceSession, OAuthService, OAuthUser};
use hex;
use infra::services::oauth::{OAuthConfig, OAuthServiceImpl, PkceSessionStorage};
use infra::utils::hash_password;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tauri::State;
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
/// # Errors
/// Returns an error if the OAuth flow cannot be started (e.g., device ID unavailable,
/// provider not configured, or session persistence fails).
#[tauri::command]
pub async fn start_oauth_flow(
    provider: AuthProvider,
    oauth_state: State<'_, OAuthState>,
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
            "Authentication failed. Please try again.".to_string()
        })?;

    tracing::info!(
        target: "audit",
        request_id = %request_id,
        action = "oauth_start",
        provider = %provider,
        device_id = %device_id_hash,
        outcome = "started",
        "Starting OAuth flow"
    );

    let state_param = session.state.clone();

    if !session.is_valid() || session.is_expired() {
        tracing::error!(
            target: "security",
            request_id = %request_id,
            outcome = "failure",
            reason = "generated_session_invalid",
            "OAuth service produced an invalid/expired PKCE session"
        );
        return Err("Authentication failed. Please try again.".to_string());
    }

    persist_oauth_session(&oauth_state, &session, &request_id).await?;

    Ok(StartOAuthResponse {
        auth_url,
        state: state_param,
    })
}

fn state_hash(state: &str) -> String {
    hex::encode(Sha256::digest(state.as_bytes()))
}

async fn persist_oauth_session(
    oauth_state: &OAuthState,
    session: &OAuthPkceSession,
    request_id: &str,
) -> Result<(), String> {
    const MAX_SESSION_JSON_BYTES: usize = 16 * 1024;

    let state_hash = state_hash(&session.state);

    let session_json = serde_json::to_string(session).map_err(|e| {
        tracing::error!(
            target: "security",
            request_id = %request_id,
            outcome = "failure",
            reason = "session_serialization_failed",
            error = %e,
            "Failed to serialize OAuth PKCE session"
        );
        "Authentication failed. Please try again.".to_string()
    })?;
    if session_json.len() > MAX_SESSION_JSON_BYTES {
        tracing::warn!(
            target: "security",
            request_id = %request_id,
            reason = "session_serialized_too_large",
            size = session_json.len(),
            "Refusing to persist oversized OAuth PKCE session"
        );

        // Best-effort cleanup in case an entry already exists for this state hash.
        let _ = tokio::task::spawn_blocking({
            let pkce_storage = oauth_state.pkce_storage.clone();
            let state_hash = state_hash.clone();
            move || pkce_storage.delete_session(&state_hash)
        })
        .await;

        return Err("Authentication failed. Please try again.".to_string());
    }

    // Store PKCE session in OS keyring for secure persistence (encryption at rest).
    // This protects the PKCE verifier from unauthorized access.
    store_session_in_keyring(
        oauth_state.pkce_storage.clone(),
        state_hash,
        session_json,
        request_id,
    )
    .await?;

    // Store session for callback verification (warm start)
    // Store in memory ONLY after successful persistence to avoid leaks if persistence fails
    oauth_state.session_store.store(session.clone());

    Ok(())
}

async fn store_session_in_keyring(
    pkce_storage: Arc<dyn PkceSessionStorage>,
    state_hash: String,
    session_json: String,
    request_id: &str,
) -> Result<(), String> {
    let write_future =
        tokio::task::spawn_blocking(move || pkce_storage.save_session(&state_hash, &session_json));

    match tokio::time::timeout(std::time::Duration::from_secs(5), write_future).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(e))) => {
            tracing::error!(
                target: "security",
                request_id = %request_id,
                outcome = "failure",
                reason = "session_persistence_failed",
                error = %e,
                "Failed to persist OAuth session to keyring"
            );
            Err("Authentication failed. Please try again.".to_string())
        }
        Ok(Err(e)) => {
            tracing::error!(
                target: "security",
                request_id = %request_id,
                outcome = "failure",
                reason = "session_persistence_task_failed",
                error = %e,
                "Failed to persist OAuth session to keyring (task join error)"
            );
            Err("Authentication failed. Please try again.".to_string())
        }
        Err(_) => {
            tracing::error!(
                target: "security",
                request_id = %request_id,
                outcome = "failure",
                reason = "session_persistence_timed_out",
                "Timed out persisting OAuth session to keyring"
            );
            Err("Authentication failed. Please try again.".to_string())
        }
    }
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
                    error_message = %e.to_string(),
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
    oauth_state: &OAuthState,
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

    // Clean up persisted session now that login is successful
    let state_hash = state_hash(&session.state);
    let pkce_storage = oauth_state.pkce_storage.clone();
    let request_id_clone = request_id.to_string();

    tokio::spawn(async move {
        match tokio::task::spawn_blocking(move || pkce_storage.delete_session(&state_hash)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(
                target: "security",
                request_id = %request_id_clone,
                "Failed to delete persisted OAuth session after success: {e}"
            ),
            Err(e) => tracing::warn!(
                target: "security",
                request_id = %request_id_clone,
                "Failed to delete persisted OAuth session after success (task join error): {e}"
            ),
        }
    });

    Ok(OAuthCallbackResponse::from(user.clone()))
}

/// Handles an OAuth callback URL from deep linking.
///
/// # Errors
/// Returns an error if the callback URL is invalid, the session cannot be retrieved,
/// the code exchange fails, or the user cannot be authenticated/created.
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

    let session = retrieve_session(&state_param, &oauth_state, &request_id)
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
                "OAuth session retrieval failed"
            );
        })?;

    let state_hash = state_hash(&state_param);

    let user =
        match exchange_code_for_user(&oauth_state, &session, code, &request_id, &device_id_hash)
            .await
        {
            Ok(user) => user,
            Err(e) => {
                // Avoid leaving stale PKCE sessions persisted on terminal failure paths.
                cleanup_invalid_persisted_session(&oauth_state, &state_hash, &request_id).await;

                // Also ensure any warm session is removed to prevent inconsistent retries.
                let _ = oauth_state
                    .session_store
                    .take_valid(&state_param, &request_id);

                return Err(e);
            }
        };

    let finalize_result = finalize_oauth_login(
        &user,
        &session,
        &oauth_state,
        &state,
        &device_id,
        &request_id,
    )
    .await;

    if finalize_result.is_err() {
        // Best-effort cleanup: after a successful code exchange the PKCE verifier is no longer needed.
        cleanup_invalid_persisted_session(&oauth_state, &state_hash, &request_id).await;
        let _ = oauth_state
            .session_store
            .take_valid(&state_param, &request_id);
    }

    finalize_result
}

/// Checks which OAuth providers are available by querying the backend configuration.
///
/// # Errors
/// This function currently does not return errors, but returns a `Result` for API consistency.
#[tauri::command]
pub async fn get_oauth_availability(
    oauth_state: State<'_, OAuthState>,
) -> Result<OAuthAvailability, String> {
    let google = oauth_state
        .oauth_service
        .is_provider_available(AuthProvider::Google);
    let github = oauth_state
        .oauth_service
        .is_provider_available(AuthProvider::GitHub);

    Ok(OAuthAvailability { google, github })
}

/// Retrieves session from in-memory store (warm start).
fn retrieve_warm_session(
    state_param: &str,
    oauth_state: &OAuthState,
    request_id: &str,
) -> Option<OAuthPkceSession> {
    let session = oauth_state
        .session_store
        .take_valid(state_param, request_id)?;

    // NOTE: Do not delete the persisted session here.
    // Delete only after a successful code exchange/login to allow retry on transient failures.

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
    let read_task =
        tokio::task::spawn_blocking(move || pkce_storage.get_session(&state_hash_clone));

    let session_json = tokio::time::timeout(std::time::Duration::from_secs(5), read_task)
        .await
        .map_err(|_| {
            tracing::error!(
                target: "security",
                request_id = %request_id,
                outcome = "failure",
                reason = "session_read_timed_out",
                "Timed out reading persisted OAuth session from keyring"
            );
            "Authentication failed. Please try again.".to_string()
        })?
        .map_err(|e| {
            tracing::error!(
                target: "security",
                request_id = %request_id,
                outcome = "failure",
                reason = "session_read_task_failed",
                error = %e,
                "Failed to read persisted OAuth session: task join error"
            );
            "Authentication failed. Please try again.".to_string()
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
            "Authentication failed. Please try again.".to_string()
        })?
        .ok_or_else(|| {
            tracing::warn!(
                target: "audit",
                request_id = %request_id,
                outcome = "failure",
                reason = "session_not_found",
                "OAuth authentication failed: invalid or expired session"
            );
            "Authentication failed. Please try again.".to_string()
        })?;

    if session_json.len() > MAX_SESSION_JSON_BYTES {
        tracing::warn!(
            target: "security",
            request_id = %request_id,
            reason = "persisted_session_too_large",
            size = session_json.len(),
            "Persisted OAuth session exceeded max size"
        );

        cleanup_invalid_persisted_session(oauth_state, state_hash, request_id).await;

        return Err("Authentication failed. Please try again.".to_string());
    }

    let recovered = match serde_json::from_str::<OAuthPkceSession>(&session_json) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                target: "security",
                request_id = %request_id,
                outcome = "failure",
                reason = "session_deserialization_failed",
                error = %e,
                "Failed to deserialize persisted OAuth session"
            );

            cleanup_invalid_persisted_session(oauth_state, state_hash, request_id).await;

            return Err("Authentication failed. Please try again.".to_string());
        }
    };

    validate_session_and_log(&recovered, state_param, request_id, oauth_state, state_hash).await?;

    // Retention Policy: We deliberately keep the persisted session in the keyring here.
    // It will be deleted only after a successful token exchange and login (in `finalize_oauth_login`)
    // to allow for retries in case of transient network failures during the exchange.

    Ok(recovered)
}

async fn validate_session_and_log(
    session: &OAuthPkceSession,
    state_param: &str,
    request_id: &str,
    oauth_state: &OAuthState,
    state_hash: &str,
) -> Result<(), String> {
    // Validate state match (CSRF protection)
    if session.state != state_param {
        tracing::warn!(
            target: "audit",
            request_id = %request_id,
            outcome = "failure",
            reason = "state_mismatch_csrf",
            "OAuth authentication failed: invalid or expired session"
        );
        cleanup_invalid_persisted_session(oauth_state, state_hash, request_id).await;
        return Err("Authentication failed. Please try again.".to_string());
    }

    // Security: Validate session integrity (expiry/validity) for recovered sessions.
    // This ensures that even if a session exists in the store, it meets current security policies.
    if !session.is_valid() || session.is_expired() {
        tracing::warn!(
            target: "audit",
            request_id = %request_id,
            outcome = "failure",
            reason = "session_invalid_or_expired",
            "OAuth authentication failed: invalid or expired session"
        );
        cleanup_invalid_persisted_session(oauth_state, state_hash, request_id).await;
        return Err("Authentication failed. Please try again.".to_string());
    }

    Ok(())
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
    request_id: &str,
) -> Result<OAuthPkceSession, String> {
    let state_hash = state_hash(state_param);

    // Try warm start first, then cold start
    if let Some(session) = retrieve_warm_session(state_param, oauth_state, request_id) {
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
    validate_oauth_user(user, session, request_id)?;

    let normalized_email = user.email.trim().to_ascii_lowercase();
    find_or_create_local_user(&normalized_email, state, request_id).await
}

/// Validates that the user data from the OAuth provider meets security requirements.
fn validate_oauth_user(
    user: &OAuthUser,
    session: &OAuthPkceSession,
    request_id: &str,
) -> Result<(), String> {
    let normalized_email = user.email.trim().to_ascii_lowercase();

    // Fail closed: must have a plausible, non-empty email before any lookup/logging.
    if normalized_email.is_empty() || !normalized_email.contains('@') {
        tracing::warn!(
            target: "audit",
            request_id = %request_id,
            outcome = "failure",
            reason = "oauth_email_invalid",
            provider = %session.provider,
            "OAuth login rejected due to invalid email"
        );
        return Err("Authentication failed. Please try again.".to_string());
    }

    // Fail closed: OAuth sign-in must only accept provider-verified emails.
    if !user.email_verified {
        tracing::warn!(
            target: "audit",
            request_id = %request_id,
            outcome = "failure",
            reason = "oauth_email_not_verified",
            provider = %session.provider,
            "OAuth login rejected due to unverified email"
        );
        return Err("Authentication failed. Please use a verified email.".to_string());
    }

    Ok(())
}

/// Finds a user by email or creates a new one if they don't exist.
/// Also handles hardening of existing unverified accounts.
async fn find_or_create_local_user(
    normalized_email: &str,
    state: &AppState,
    request_id: &str,
) -> Result<Uuid, String> {
    match state.user_repo.find_by_email(normalized_email).await {
        Ok(Some(mut user)) => {
            if !user.email_verified {
                harden_unverified_user(&mut user, state, request_id).await?;
            }
            Ok(user.id)
        }
        Ok(None) => {
            // Create new user for OAuth
            create_oauth_user(normalized_email, state, request_id).await
        }
        Err(e) => {
            tracing::error!(
                request_id = %request_id,
                "Database error finding user: {e}"
            );
            Err("Authentication failed. Please try again.".to_string())
        }
    }
}

/// Hardens an existing, unverified user account during an OAuth flow
/// by generating a new secure password and marking the email as verified.
async fn harden_unverified_user(
    user: &mut domain::modules::auth::User,
    state: &AppState,
    request_id: &str,
) -> Result<(), String> {
    // SECURITY CRITICAL: When verifying an existing unverified account via OAuth,
    // we MUST invalidate the old password to prevent account takeover.
    let password_hash = generate_and_hash_oauth_password().await?;

    user.email_verified = true;
    user.password_hash = password_hash; // Invalidate old password
    user.verification_token = None;
    user.verification_token_expires_at = None;

    state.user_repo.save(user).await.map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            "Failed to update user verification from OAuth: {e}"
        );
        "Authentication failed. Please try again.".to_string()
    })?;

    Ok(())
}

/// Creates a new user record for an authenticated OAuth account.
///
/// Handles concurrency conflicts (e.g. two simultaneous callbacks for the same new user)
/// by falling back to the existing record and applying hardening if needed.
async fn create_oauth_user(
    email: &str,
    state: &AppState,
    request_id: &str,
) -> Result<Uuid, String> {
    // Generate a random high-entropy password that will never be shown to the user
    // This ensures the account cannot be accessed via password login unless explicitly reset
    let password_hash = generate_and_hash_oauth_password().await?;

    let new_user = domain::modules::auth::User {
        id: Uuid::new_v4(),
        email: email.to_string(),
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
            if let Ok(Some(mut existing)) = state.user_repo.find_by_email(email).await {
                if !existing.email_verified {
                    harden_unverified_user(&mut existing, state, request_id).await?;
                }
                Ok(existing.id)
            } else {
                tracing::error!(
                    request_id = %request_id,
                    "Failed to recover user after OAuth create conflict"
                );
                Err("Authentication failed. Please try again.".to_string())
            }
        }
        Err(e) => {
            tracing::error!(
                request_id = %request_id,
                "Failed to save new OAuth user due to unexpected database error: {e}"
            );
            Err("Authentication failed. Please try again.".to_string())
        }
    }
}

async fn generate_and_hash_oauth_password() -> Result<String, String> {
    // Generate a high-entropy password that will never be shown to the user.
    // Use a cryptographically secure random number generator.
    let random_bytes = tauri::async_runtime::spawn_blocking(|| {
        let mut bytes = [0u8; 32]; // 256 bits of entropy
        getrandom::getrandom(&mut bytes).inspect_err(|e| {
            tracing::error!("Failed to generate random bytes for OAuth password: {e}");
        })?;
        Ok::<_, getrandom::Error>(bytes)
    })
    .await
    .map_err(|e| {
        tracing::error!("Task join error during random byte generation: {e}");
        "Authentication failed".to_string()
    })?
    .map_err(|e| {
        tracing::error!("Failed to generate random bytes for OAuth password: {e}");
        "Authentication failed".to_string()
    })?;

    let oauth_random_password = hex::encode(random_bytes);

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
    let mut hasher = Sha256::new();
    hasher.update(user.provider_user_id.as_bytes());
    let hashed_user_id = hex::encode(hasher.finalize());

    tracing::info!(
        target: "audit",
        request_id = %request_id,
        user_id = %user_id,
        provider = %session.provider,
        provider_user_id_hash = %hashed_user_id,
        outcome = "success",
        "OAuth authentication completed"
    );
}
