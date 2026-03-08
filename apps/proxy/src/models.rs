use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Clone, Debug, Deserialize, Serialize, Validate)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GitHubTokenResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}
