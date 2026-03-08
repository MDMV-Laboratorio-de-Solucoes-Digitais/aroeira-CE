use crate::error_codes::{ErrorCode, ErrorResponse};
use crate::services::secure_storage::{AUTH_TOKEN_KEY, SecureStorage};
use tauri::State;
use tracing::{debug, error, info};

/// Helper function to set auth token
///
/// # Errors
///
/// Returns an error if the token save fails.
#[tauri::command]
pub async fn set_auth_token(
    state: State<'_, crate::state::AppState>,
    token: String,
) -> Result<(), String> {
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(String::from(ErrorResponse::new(
            ErrorCode::InvalidToken,
            "Auth token cannot be empty",
        )));
    }

    state
        .secure_storage
        .save(AUTH_TOKEN_KEY, &token)
        .await
        .map_err(|e| {
            debug!(action = "set_auth_token", outcome = "failure", error = %e);
            String::from(ErrorResponse::from_code(ErrorCode::SecureStorageError))
        })?;

    info!(action = "set_auth_token", outcome = "success");
    Ok(())
}

/// Helper function to get auth token
///
/// # Errors
///
/// Returns an error if the token retrieval fails.
#[tauri::command]
pub async fn get_auth_token(
    state: State<'_, crate::state::AppState>,
) -> Result<Option<String>, String> {
    const MAX_TOKEN_LENGTH: usize = 4096;

    let token = state
        .secure_storage
        .get(AUTH_TOKEN_KEY)
        .await
        .map_err(|e| {
            debug!(action = "get_auth_token", outcome = "failure", error = %e);
            String::from(ErrorResponse::from_code(ErrorCode::SecureStorageError))
        })?;

    if let Some(ref t) = token {
        let trimmed = t.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_TOKEN_LENGTH || trimmed.split('.').count() != 3
        {
            debug!(
                action = "get_auth_token",
                outcome = "clearing_invalid_token",
                reason = "invalid_format_or_length",
                token_len = trimmed.len()
            );
            state.secure_storage.delete(AUTH_TOKEN_KEY).await.ok();
            return Ok(None);
        }
    }

    info!(action = "get_auth_token", outcome = "success");
    Ok(token)
}

/// Helper function to clear auth token
///
/// # Errors
///
/// Returns an error if the token deletion fails.
pub async fn clear_auth_token(state: State<'_, crate::state::AppState>) -> Result<(), String> {
    state
        .secure_storage
        .delete(AUTH_TOKEN_KEY)
        .await
        .map_err(|e| {
            debug!(action = "clear_auth_token", outcome = "failure", error = %e);
            String::from(ErrorResponse::from_code(ErrorCode::SecureStorageError))
        })?;

    info!(action = "clear_auth_token", outcome = "success");
    Ok(())
}

#[tauri::command]
/// Helper function to check if auth token exists
///
/// # Errors
///
/// Returns an error if the check fails.
pub async fn has_auth_token(state: State<'_, crate::state::AppState>) -> Result<bool, String> {
    let Some(token) = get_auth_token(state.clone()).await? else {
        return Ok(false);
    };

    if crate::auth_utils::get_user_id(&state, &token).is_err() {
        let _ = clear_auth_token(state).await;
        return Ok(false);
    }

    Ok(true)
}

#[tauri::command]
/// Helper function to get user id from token
///
/// # Errors
///
/// Returns an error if the token retrieval or user ID extraction fails.
pub async fn get_user_id_from_token(
    state: State<'_, crate::state::AppState>,
) -> Result<Option<String>, String> {
    let Some(token) = get_auth_token(state.clone()).await? else {
        return Ok(None);
    };

    if token.split('.').count() != 3 {
        let _ = clear_auth_token(state).await;
        return Ok(None);
    }

    match crate::auth_utils::get_user_id(&state, &token) {
        Ok(user_id) => Ok(Some(user_id.to_string())),
        Err(e) => {
            error!(
                action = "get_user_id_from_token",
                outcome = "failure",
                reason = "extraction_failed",
                error = %e
            );
            let _ = clear_auth_token(state).await;
            Ok(None)
        }
    }
}
