use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct GitHubTokenRequest {
    #[validate(length(min = 1, max = 2048, message = "Invalid authorization code"))]
    pub code: String,

    #[validate(length(min = 10, max = 255, message = "Invalid state"))]
    pub state: String,

    #[validate(url(message = "Invalid redirect URI"))]
    pub redirect_uri: String,

    #[validate(length(min = 43, max = 128, message = "Invalid code verifier"))]
    pub code_verifier: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubTokenResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct GitHubRawTokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<i64>,
    pub scope: String,
}
