//! OAuth2 Service Implementation - TDD GREEN PHASE
//!
//! This module implements the `OAuthService` trait from the domain layer
//! using the `oauth2` crate for PKCE-based authentication flows.
//!
//! # Security Notes
//!
//! - Uses PKCE (RFC 7636) for all flows - no client secrets
//! - State parameter provides CSRF protection
//! - Tokens are not stored here - caller is responsible for secure storage

use async_trait::async_trait;
use domain::modules::auth::oauth::{
    AuthProvider, OAuthError, OAuthPkceSession, OAuthService, OAuthUser,
};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use tracing::{debug, error, warn};

/// Configuration for OAuth2 providers.
///
/// Client IDs are loaded from environment variables.
/// No client secrets are used (public client with PKCE).
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Google OAuth2 client ID (optional)
    pub google_client_id: Option<String>,
    /// GitHub OAuth2 client ID (optional)
    pub github_client_id: Option<String>,
    /// Redirect URI for OAuth callbacks (e.g., "aroeira://auth/callback")
    pub redirect_uri: String,
}

impl OAuthConfig {
    /// Creates config from environment variables.
    ///
    /// Looks for:
    /// - `GOOGLE_CLIENT_ID`
    /// - `GITHUB_CLIENT_ID`
    #[must_use]
    pub fn from_env(redirect_uri: String) -> Self {
        Self {
            google_client_id: std::env::var("GOOGLE_CLIENT_ID").ok(),
            github_client_id: std::env::var("GITHUB_CLIENT_ID").ok(),
            redirect_uri,
        }
    }
}

/// OAuth2 service implementation using PKCE flow.
///
/// This implementation:
/// - Generates authorization URLs with PKCE challenges
/// - Exchanges authorization codes for tokens
/// - Fetches user info from provider APIs
pub struct OAuthServiceImpl {
    config: OAuthConfig,
}

impl OAuthServiceImpl {
    /// Google OAuth2 authorization endpoint
    const GOOGLE_AUTH_URL: &'static str = "https://accounts.google.com/o/oauth2/v2/auth";
    /// Google OAuth2 token endpoint
    const GOOGLE_TOKEN_URL: &'static str = "https://oauth2.googleapis.com/token";
    /// Google userinfo endpoint
    const GOOGLE_USERINFO_URL: &'static str = "https://openidconnect.googleapis.com/v1/userinfo";

    /// GitHub OAuth2 authorization endpoint
    const GITHUB_AUTH_URL: &'static str = "https://github.com/login/oauth/authorize";
    /// GitHub OAuth2 token endpoint
    const GITHUB_TOKEN_URL: &'static str = "https://github.com/login/oauth/access_token";
    /// GitHub user API endpoint
    const GITHUB_USER_URL: &'static str = "https://api.github.com/user";
    /// GitHub user emails API endpoint
    const GITHUB_EMAILS_URL: &'static str = "https://api.github.com/user/emails";

    /// Creates a new OAuth service with the given configuration.
    #[must_use]
    pub fn new(config: OAuthConfig) -> Self {
        Self { config }
    }

    /// Gets client ID and URLs for a provider.
    fn get_provider_config(
        &self,
        provider: AuthProvider,
    ) -> Result<(&str, &'static str, &'static str), OAuthError> {
        match provider {
            AuthProvider::Google => {
                let client_id = self
                    .config
                    .google_client_id
                    .as_ref()
                    .ok_or_else(|| OAuthError::ProviderNotConfigured("Google".to_string()))?;
                Ok((
                    client_id.as_str(),
                    Self::GOOGLE_AUTH_URL,
                    Self::GOOGLE_TOKEN_URL,
                ))
            }
            AuthProvider::GitHub => {
                let client_id = self
                    .config
                    .github_client_id
                    .as_ref()
                    .ok_or_else(|| OAuthError::ProviderNotConfigured("GitHub".to_string()))?;
                Ok((
                    client_id.as_str(),
                    Self::GITHUB_AUTH_URL,
                    Self::GITHUB_TOKEN_URL,
                ))
            }
        }
    }

    /// Returns the scopes required for each provider.
    fn get_scopes(provider: AuthProvider) -> Vec<Scope> {
        match provider {
            AuthProvider::Google => vec![
                Scope::new("openid".to_string()),
                Scope::new("email".to_string()),
                Scope::new("profile".to_string()),
            ],
            AuthProvider::GitHub => vec![
                Scope::new("read:user".to_string()),
                Scope::new("user:email".to_string()),
            ],
        }
    }

    /// Fetches user info from Google's userinfo endpoint.
    async fn fetch_google_user(&self, access_token: &str) -> Result<OAuthUser, OAuthError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;
            
        let response = client
            .get(Self::GOOGLE_USERINFO_URL)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OAuthError::UserInfoFailed(format!(
                "Google userinfo returned status {}",
                response.status()
            )));
        }

        let user_info: GoogleUserInfo = response
            .json()
            .await
            .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

        Ok(OAuthUser {
            provider: AuthProvider::Google,
            provider_user_id: user_info.sub,
            email: user_info.email,
            name: user_info.name,
            avatar_url: user_info.picture,
        })
    }

    /// Fetches user info from GitHub's API.
    async fn fetch_github_user(&self, access_token: &str) -> Result<OAuthUser, OAuthError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

        // Fetch user profile
        let user_response = client
            .get(Self::GITHUB_USER_URL)
            .header("User-Agent", "Aroeira-Desktop")
            .header("Accept", "application/vnd.github+json")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

        if !user_response.status().is_success() {
            return Err(OAuthError::UserInfoFailed(format!(
                "GitHub user API returned status {}",
                user_response.status()
            )));
        }

        let user_info: GitHubUserInfo = user_response
            .json()
            .await
            .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

        // If email is not public, fetch from emails endpoint
        let email = if let Some(email) = user_info.email {
            email
        } else {
            self.fetch_github_primary_email(access_token).await?
        };

        Ok(OAuthUser {
            provider: AuthProvider::GitHub,
            provider_user_id: user_info.id.to_string(),
            email,
            name: user_info.name,
            avatar_url: user_info.avatar_url,
        })
    }

    /// Fetches primary email from GitHub's emails endpoint.
    async fn fetch_github_primary_email(&self, access_token: &str) -> Result<String, OAuthError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;
            
        let response = client
            .get(Self::GITHUB_EMAILS_URL)
            .header("User-Agent", "Aroeira-Desktop")
            .header("Accept", "application/vnd.github+json")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OAuthError::UserInfoFailed(format!(
                "GitHub emails API returned status {}",
                response.status()
            )));
        }

        let emails: Vec<GitHubEmail> = response
            .json()
            .await
            .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

        // Find primary email, or first verified email, or first email
        emails
            .iter()
            .find(|e| e.primary && e.verified)
            .or_else(|| emails.iter().find(|e| e.verified))
            .or_else(|| emails.first())
            .map(|e| e.email.clone())
            .ok_or_else(|| OAuthError::UserInfoFailed("No email found".to_string()))
    }
}

#[async_trait]
impl OAuthService for OAuthServiceImpl {
    async fn generate_authorization_url(
        &self,
        provider: AuthProvider,
    ) -> Result<(String, OAuthPkceSession), OAuthError> {
        debug!("Generating authorization URL for {:?}", provider);

        let (client_id, auth_url_str, token_url_str) = self.get_provider_config(provider)?;

        // Parse URLs
        let auth_url = AuthUrl::new(auth_url_str.to_string())
            .map_err(|e| OAuthError::CodeExchangeFailed(e.to_string()))?;
        let token_url = TokenUrl::new(token_url_str.to_string())
            .map_err(|e| OAuthError::CodeExchangeFailed(e.to_string()))?;
        let redirect_url = RedirectUrl::new(self.config.redirect_uri.clone())
            .map_err(|e| OAuthError::CodeExchangeFailed(e.to_string()))?;

        // Create OAuth2 client
        let client = oauth2::basic::BasicClient::new(ClientId::new(client_id.to_string()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(redirect_url);

        // Generate PKCE challenge
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Build authorization URL with scopes and PKCE
        let mut auth_request = client.authorize_url(CsrfToken::new_random);
        for scope in Self::get_scopes(provider) {
            auth_request = auth_request.add_scope(scope);
        }
        let (auth_url, csrf_state) = auth_request.set_pkce_challenge(pkce_challenge).url();

        // Create session
        let session = OAuthPkceSession::new(
            csrf_state.secret().clone(),
            pkce_verifier.secret().clone(),
            provider,
        );

        debug!("Generated auth URL for {:?}", provider);

        Ok((auth_url.to_string(), session))
    }

    async fn exchange_code(
        &self,
        session: &OAuthPkceSession,
        code: String,
    ) -> Result<OAuthUser, OAuthError> {
        debug!("Exchanging code for {:?}", session.provider);

        // Validate session
        if !session.is_valid() {
            warn!("Invalid session: state or verifier failed validation");
            return Err(OAuthError::SessionNotFound);
        }

        if session.is_expired() {
            warn!("Session expired");
            return Err(OAuthError::SessionNotFound);
        }

        let (client_id, auth_url_str, token_url_str) =
            self.get_provider_config(session.provider)?;

        // Parse URLs
        let auth_url = AuthUrl::new(auth_url_str.to_string())
            .map_err(|e| OAuthError::CodeExchangeFailed(e.to_string()))?;
        let token_url = TokenUrl::new(token_url_str.to_string())
            .map_err(|e| OAuthError::CodeExchangeFailed(e.to_string()))?;
        let redirect_url = RedirectUrl::new(self.config.redirect_uri.clone())
            .map_err(|e| OAuthError::CodeExchangeFailed(e.to_string()))?;

        // Create OAuth2 client
        let client = oauth2::basic::BasicClient::new(ClientId::new(client_id.to_string()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(redirect_url);

        // Create PKCE verifier from session
        let pkce_verifier = PkceCodeVerifier::new(session.pkce_verifier.clone());

        // Prepare token exchange request
        let token_request = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier);

        // Perform token exchange with timeout and provider-specific adjustments
        let exchange_future = async {
            match session.provider {
                AuthProvider::GitHub => {
                    // GitHub requires Accept: application/json
                    token_request
                        .request_async(&|mut req: oauth2::HttpRequest| async move {
                            if let Ok(header_val) = "application/json".parse() {
                                // "accept" implements IntoHeaderName
                                req.headers_mut().insert("accept", header_val);
                            }
                            async_http_client(req).await
                        })
                        .await
                }
                // Other providers (Google) work with default client
                _ => {
                    token_request
                        .request_async(&async_http_client)
                        .await
                }
            }
        };

        // Execute with timeout
        let token_result = tokio::time::timeout(std::time::Duration::from_secs(30), exchange_future)
            .await
            .map_err(|_| OAuthError::TokenRequestFailed("Token exchange timed out".to_string()))?
            .map_err(|_e| {
                // Sanitize error logging: avoid logging full error which might contain sensitive data
                // Just log that it failed and the provider
                error!("Token exchange failed for provider {:?}", session.provider);
                
                // Return a generic error description, or specific if safe (e.g. "access_denied")
                // For now, keep it generic to be safe
                OAuthError::TokenRequestFailed("Provider rejected token request".to_string())
            })?;

        let access_token = token_result.access_token().secret();

        // Fetch user info based on provider
        match session.provider {
            AuthProvider::Google => self.fetch_google_user(access_token).await,
            AuthProvider::GitHub => self.fetch_github_user(access_token).await,
        }
    }
}

/// Google userinfo response structure
#[derive(serde::Deserialize)]
struct GoogleUserInfo {
    /// Unique user identifier
    sub: String,
    /// User's email
    email: String,
    /// User's full name
    name: Option<String>,
    /// Profile picture URL
    picture: Option<String>,
}

/// GitHub user API response structure
#[derive(serde::Deserialize)]
struct GitHubUserInfo {
    /// Unique user identifier
    id: u64,
    /// User's email (may be null if not public)
    email: Option<String>,
    /// User's name
    name: Option<String>,
    /// Avatar URL
    avatar_url: Option<String>,
}

/// GitHub email API response structure
#[derive(serde::Deserialize)]
struct GitHubEmail {
    /// Email address
    email: String,
    /// Whether this is the primary email
    primary: bool,
    /// Whether the email is verified
    verified: bool,
}

/// Custom async HTTP client for oauth2 crate with timeout and proper configuration.
///
/// This replaces `oauth2::reqwest::async_http_client` which doesn't have a timeout by default.
async fn async_http_client(
    request: oauth2::HttpRequest,
) -> Result<oauth2::HttpResponse, reqwest::Error> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let mut request_builder = client
        .request(request.method().clone(), request.uri().to_string())
        .body(request.body().clone());

    for (name, value) in request.headers() {
        request_builder = request_builder.header(name, value);
    }

    let response = request_builder
        .send()
        .await?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await?
        .to_vec();

    let mut resp = oauth2::HttpResponse::new(body);
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    Ok(resp)
}

#[cfg(test)]
mod tests;
