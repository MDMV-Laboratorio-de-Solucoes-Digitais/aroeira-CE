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
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use tracing::{debug, error, warn};

// Static HTTP client for async_http_client callback (connection pooling)
static ASYNC_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|e| {
            warn!("Failed to build static reqwest client: {e}; falling back to default client");
            reqwest::Client::new()
        })
});

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

    // Test overrides
    pub google_auth_url: Option<String>,
    pub google_token_url: Option<String>,
    pub google_userinfo_url: Option<String>,

    pub github_auth_url: Option<String>,
    pub github_token_url: Option<String>,
    pub github_user_url: Option<String>,
    pub github_emails_url: Option<String>,
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
            google_auth_url: None,
            google_token_url: None,
            google_userinfo_url: None,
            github_auth_url: None,
            github_token_url: None,
            github_user_url: None,
            github_emails_url: None,
        }
    }
}

/// Trait for securely storing OAuth tokens.
pub trait TokenStorage: Send + Sync {
    fn store(&self, service: &str, user_key: &str, secret: &str) -> Result<(), String>;
}

/// Default implementation using OS keyring.
pub struct KeyringTokenStorage;

impl TokenStorage for KeyringTokenStorage {
    fn store(&self, service: &str, user_key: &str, secret: &str) -> Result<(), String> {
        #[cfg(not(test))]
        {
            let entry = keyring::Entry::new(service, user_key).map_err(|e| e.to_string())?;
            entry.set_password(secret).map_err(|e| e.to_string())?;
            Ok(())
        }
        #[cfg(test)]
        {
            // In tests, just return Ok or store in memory if needed (for now no-op is fine for default)
            // But ideally we use a mock in tests.
            let _ = (service, user_key, secret);
            Ok(())
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
    token_storage: Box<dyn TokenStorage>,
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
        Self {
            config,
            token_storage: Box::new(KeyringTokenStorage),
        }
    }

    /// Creates a new OAuth service with injected storage (for testing).
    #[cfg(test)]
    pub fn new_with_storage(config: OAuthConfig, storage: Box<dyn TokenStorage>) -> Self {
        Self {
            config,
            token_storage: storage,
        }
    }

    /// Gets client ID and URLs for a provider.
    fn get_provider_config(
        &self,
        provider: AuthProvider,
    ) -> Result<(&str, &str, &str), OAuthError> {
        match provider {
            AuthProvider::Google => {
                let client_id = self
                    .config
                    .google_client_id
                    .as_ref()
                    .ok_or_else(|| OAuthError::ProviderNotConfigured("Google".to_string()))?;
                Ok((
                    client_id.as_str(),
                    self.config
                        .google_auth_url
                        .as_deref()
                        .unwrap_or(Self::GOOGLE_AUTH_URL),
                    self.config
                        .google_token_url
                        .as_deref()
                        .unwrap_or(Self::GOOGLE_TOKEN_URL),
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
                    self.config
                        .github_auth_url
                        .as_deref()
                        .unwrap_or(Self::GITHUB_AUTH_URL),
                    self.config
                        .github_token_url
                        .as_deref()
                        .unwrap_or(Self::GITHUB_TOKEN_URL),
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
        let url = self
            .config
            .google_userinfo_url
            .as_deref()
            .unwrap_or(Self::GOOGLE_USERINFO_URL);
        let response = ASYNC_HTTP_CLIENT
            .get(url)
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

        // Security Critical: Ensure email is verified by Google
        if !user_info.email_verified {
            return Err(OAuthError::UserInfoFailed(
                "Google email not verified".to_string(),
            ));
        }

        Ok(OAuthUser {
            provider: AuthProvider::Google,
            provider_user_id: user_info.sub,
            email: user_info.email,
            name: user_info.name,
            avatar_url: user_info.picture,
            email_verified: user_info.email_verified,
        })
    }

    /// Fetches user info from GitHub's API.
    async fn fetch_github_user(&self, access_token: &str) -> Result<OAuthUser, OAuthError> {
        // Fetch user profile
        let url = self
            .config
            .github_user_url
            .as_deref()
            .unwrap_or(Self::GITHUB_USER_URL);
        let user_response = ASYNC_HTTP_CLIENT
            .get(url)
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

        // Always fetch verified email from emails endpoint for security
        let (email, email_verified) = self.fetch_github_primary_email(access_token).await?;

        Ok(OAuthUser {
            provider: AuthProvider::GitHub,
            provider_user_id: user_info.id.to_string(),
            email,
            name: user_info.name,
            avatar_url: user_info.avatar_url,
            email_verified,
        })
    }

    /// Fetches primary email from GitHub's emails endpoint.
    async fn fetch_github_primary_email(
        &self,
        access_token: &str,
    ) -> Result<(String, bool), OAuthError> {
        let url = self
            .config
            .github_emails_url
            .as_deref()
            .unwrap_or(Self::GITHUB_EMAILS_URL);
        let response = ASYNC_HTTP_CLIENT
            .get(url)
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

        // Security Critical: Only accept verified emails
        let email_obj = emails
            .iter()
            .find(|e| e.primary && e.verified)
            .or_else(|| emails.iter().find(|e| e.verified))
            .ok_or_else(|| OAuthError::UserInfoFailed("No verified email found".to_string()))?;

        Ok((email_obj.email.clone(), email_obj.verified))
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
        let auth_url = AuthUrl::new(auth_url_str.to_string()).map_err(|e| {
            OAuthError::ProviderNotConfigured(format!("Invalid authorization URL: {e}"))
        })?;
        let token_url = TokenUrl::new(token_url_str.to_string())
            .map_err(|e| OAuthError::ProviderNotConfigured(format!("Invalid token URL: {e}")))?;
        let redirect_url = RedirectUrl::new(self.config.redirect_uri.clone())
            .map_err(|e| OAuthError::ProviderNotConfigured(format!("Invalid redirect URI: {e}")))?;

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
            warn!("Invalid PKCE session (failed validation)");
            return Err(OAuthError::CodeExchangeFailed(
                "Invalid PKCE session".to_string(),
            ));
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

        // Perform token exchange with timeout and provider-specific adjustments
        // Rebuild request inside match arms to avoid ownership issues (ExchangeCode consumes self)
        let exchange_future = async {
            match session.provider {
                AuthProvider::GitHub => {
                    // GitHub requires Accept: application/json
                    let verifier = PkceCodeVerifier::new(session.pkce_verifier.clone());
                    client
                        .exchange_code(AuthorizationCode::new(code.clone()))
                        .set_pkce_verifier(verifier)
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
                    let verifier = PkceCodeVerifier::new(session.pkce_verifier.clone());
                    client
                        .exchange_code(AuthorizationCode::new(code.clone()))
                        .set_pkce_verifier(verifier)
                        .request_async(&async_http_client)
                        .await
                }
            }
        };

        // Execute with timeout
        let token_result =
            tokio::time::timeout(std::time::Duration::from_secs(30), exchange_future)
                .await
                .map_err(|_| {
                    OAuthError::TokenRequestFailed("Token exchange timed out".to_string())
                })?
                .map_err(|e| {
                    // The `oauth2` crate's error types are designed not to leak secrets.
                    // Logging the error at a debug level provides valuable diagnostic information.
                    debug!(
                        "Token exchange failed for provider {:?}: {:?}",
                        session.provider, e
                    );
                    error!("Token exchange failed for provider {:?}", session.provider);
                    // Return a generic error to the client.
                    OAuthError::TokenRequestFailed("Provider rejected token request".to_string())
                })?;

        let access_token = token_result.access_token().secret();

        // Fetch user info based on provider
        let user = match session.provider {
            AuthProvider::Google => self.fetch_google_user(access_token).await,
            AuthProvider::GitHub => self.fetch_github_user(access_token).await,
        }?;

        // Securely store the token in the OS keyring (best effort).
        // NOTE: The app session (JWT) is stored via tauri secure storage; provider token storage
        // should not hard-fail the entire login on platforms where keyring is unavailable.
        {
            let service_name = "aroeira-oauth";
            let user_key = format!("{}:{}", user.provider, user.provider_user_id);

            // Hash user key for logging and storage to avoid PII leak in OS store/logs
            let mut hasher = Sha256::new();
            hasher.update(user_key.as_bytes());
            let user_key_hash = hex::encode(hasher.finalize());

            // Create token payload containing both access and refresh tokens
            let token_payload = serde_json::json!({
                "access_token": access_token,
                "refresh_token": token_result.refresh_token().map(|t| t.secret()),
            });

            match self
                .token_storage
                .store(service_name, &user_key_hash, &token_payload.to_string())
            {
                Ok(()) => debug!("Securely stored OAuth token for {}", user_key_hash),
                Err(e) => {
                    warn!(
                        "OAuth token not stored in OS keyring (continuing without it): {}",
                        e
                    );
                }
            }
        }

        Ok(user)
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
    /// Whether email is verified
    email_verified: bool,
}

/// GitHub user API response structure
#[derive(serde::Deserialize)]
struct GitHubUserInfo {
    /// Unique user identifier
    id: u64,
    /// User's email (may be null if not public)
    _email: Option<String>,
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
    // Use static client for connection pooling
    let client = &*ASYNC_HTTP_CLIENT;

    let mut request_builder = client
        .request(request.method().clone(), request.uri().to_string())
        .body(request.body().clone());

    for (name, value) in request.headers() {
        // Skip Content-Length as reqwest calculates it automatically from the body.
        // Forwarding it can cause mismatches (e.g. if compression is involved) or errors.
        if name.as_str().eq_ignore_ascii_case("content-length") {
            continue;
        }
        request_builder = request_builder.header(name, value);
    }

    let response = request_builder.send().await?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await?.to_vec();

    let mut resp = oauth2::HttpResponse::new(body);
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    Ok(resp)
}

#[cfg(test)]
mod tests;
