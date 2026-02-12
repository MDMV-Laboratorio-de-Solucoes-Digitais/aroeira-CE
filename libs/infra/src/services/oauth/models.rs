use serde::Deserialize;

/// Google userinfo response structure
#[derive(Deserialize)]
pub struct GoogleUserInfo {
    /// Unique user identifier
    pub sub: String,
    /// User's email
    pub email: String,
    /// User's full name
    pub name: Option<String>,
    /// Profile picture URL
    pub picture: Option<String>,
    /// Whether email is verified
    pub email_verified: bool,
}

/// GitHub user API response structure
#[derive(Deserialize)]
pub struct GitHubUserInfo {
    /// Unique user identifier
    pub id: u64,
    /// User's email (may be null if not public)
    pub _email: Option<String>,
    /// User's name
    pub name: Option<String>,
    /// Avatar URL
    pub avatar_url: Option<String>,
}

/// GitHub email API response structure
#[derive(Deserialize)]
pub struct GitHubEmail {
    /// Email address
    pub email: String,
    /// Whether this is the primary email
    pub primary: bool,
    /// Whether the email is verified
    pub verified: bool,
}
