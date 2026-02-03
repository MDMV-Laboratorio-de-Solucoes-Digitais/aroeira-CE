use crate::state::AppState;
use infra::services::auth::verify_jwt;
use secrecy::ExposeSecret;
use tauri::State;
use tracing::warn;
use uuid::Uuid;

/// Extracts the user ID from a JWT token (pure logic)
///
/// # Errors
///
/// This function will return an error if:
/// - The token is invalid or expired
/// - The token format is incorrect
/// - The JWT verification fails
pub fn extract_user_id(
    token: &str,
    secret: &str,
    issuer: &str,
    audience: &str,
) -> Result<Uuid, String> {
    const MAX_TOKEN_LENGTH: usize = 4096;

    let token = token.trim();
    if token.is_empty() || token.len() > MAX_TOKEN_LENGTH {
        return Err("Invalid or expired token".to_string());
    }

    let actual_token = if token.len() >= 7 && token[..7].eq_ignore_ascii_case("bearer ") {
        let mut parts = token.split_whitespace();
        let _bearer = parts.next();
        let some_token = parts.next();
        let extra = parts.next();

        match (some_token, extra) {
            (Some(t), None) => t,
            _ => return Err("Invalid or expired token".to_string()),
        }
    } else {
        token
    };

    if actual_token.split('.').count() != 3 {
        return Err("Invalid or expired token".to_string());
    }

    verify_jwt(actual_token, secret, issuer, audience).map_err(|e| {
        warn!(error = %e, "Invalid or expired token");
        "Invalid or expired token".to_string()
    })
}

/// Extracts the user ID from a JWT token using `AppState`
///
/// # Errors
///
/// This function will return an error if:
/// - The token is invalid or expired
/// - The token format is incorrect
/// - The JWT verification fails
pub fn get_user_id(state: &State<'_, AppState>, token: &str) -> Result<Uuid, String> {
    extract_user_id(
        token,
        state.jwt_secret.expose_secret(),
        &state.jwt_issuer,
        &state.jwt_audience,
    )
}

#[cfg(test)]
#[path = "auth_utils_tests.rs"]
mod tests;
