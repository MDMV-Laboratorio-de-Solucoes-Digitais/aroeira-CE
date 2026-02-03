use anyhow::Result;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub exp: u64,    // expiration
    pub iat: u64,    // issued-at
    pub iss: String, // Issuer
    pub aud: String, // Audience
}

/// Creates a JWT token for a user
///
/// # Errors
///
/// This function will return an error if:
/// - The expiration hours value is too large causing overflow
/// - The JWT expiration timestamp overflows u64
/// - The JWT encoding fails
pub fn create_jwt(
    user_id: Uuid,
    secret: &str,
    expiration_hours: u64,
    issuer: &str,
    audience: &str,
) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let expiration_seconds = expiration_hours.checked_mul(3600).ok_or_else(|| {
        anyhow::anyhow!(
            "JWT expiration hours value {expiration_hours} is too large (max: {})",
            u64::MAX / 3600
        )
    })?;
    let expiration = now.checked_add(expiration_seconds).ok_or_else(|| {
        anyhow::anyhow!(
            "JWT expiration timestamp overflows u64: now={now}, expiration_seconds={expiration_seconds}"
        )
    })?;

    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiration,
        iat: now, // issued-at timestamp
        iss: issuer.to_string(),
        aud: audience.to_string(),
    };

    let header = Header::new(Algorithm::HS256);

    Ok(encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )?)
}

/// Verifies a JWT token and extracts the user ID
///
/// # Errors
///
/// This function will return an error if:
/// - The token is invalid or malformed
/// - The token has expired
/// - The token issuer or audience doesn't match
/// - The token's subject (user ID) is not a valid UUID
pub fn verify_jwt(token: &str, secret: &str, issuer: &str, audience: &str) -> Result<Uuid> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )?;

    Ok(Uuid::parse_str(&token_data.claims.sub)?)
}
