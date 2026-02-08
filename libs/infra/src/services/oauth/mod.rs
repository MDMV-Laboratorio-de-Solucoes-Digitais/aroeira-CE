//! `OAuth2` Service Implementation - TDD GREEN PHASE
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
use hex;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use tracing::{debug, error, warn};
use uuid::Uuid;

// Static HTTP client for async_http_client callback (connection pooling)
static ASYNC_HTTP_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build reqwest client for OAuth")
});

/// Maximum allowed size for OAuth HTTP response bodies (1 MB).
/// Prevents `DoS` attacks via unbounded memory allocation.
/// Configuration for `OAuth2` providers.
///
/// Client IDs are loaded from environment variables.
/// GitHub requires a client secret even for PKCE flows.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Google `OAuth2` client ID (optional)
    pub google_client_id: Option<String>,
    /// GitHub `OAuth2` client ID (optional)
    pub github_client_id: Option<String>,
    /// GitHub `OAuth2` client secret (required for token exchange)
    pub github_client_secret: Option<secrecy::SecretString>,
    /// Redirect URI for OAuth callbacks (e.g., `<aroeira://auth/callback>`)
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
    /// - `GITHUB_CLIENT_SECRET` (required for GitHub token exchange)
    #[must_use]
    pub fn from_env(redirect_uri: String) -> Self {
        let get_optional_env = |key: &str| -> Option<String> {
            std::env::var(key)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };

        Self {
            google_client_id: get_optional_env("GOOGLE_CLIENT_ID"),
            github_client_id: get_optional_env("GITHUB_CLIENT_ID"),
            github_client_secret: get_optional_env("GITHUB_CLIENT_SECRET")
                .map(secrecy::SecretString::from),
            redirect_uri,
            google_auth_url: None,
            google_token_url: None,
            google_userinfo_url: None,
            github_auth_url: None,
            github_token_url: get_optional_env("GITHUB_TOKEN_URL"),
            github_user_url: None,
            github_emails_url: None,
        }
    }
}

/// Trait for securely storing OAuth tokens.
pub trait TokenStorage: Send + Sync {
    /// Stores a token secret securely.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails (e.g. keyring unavailable).
    fn store(&self, service: &str, user_key: &str, secret: &str) -> Result<(), String>;
}

/// Trait for securely storing PKCE OAuth sessions.
///
/// PKCE sessions contain sensitive data (PKCE verifier, state) that must be
/// stored in OS secure storage (keyring) rather than plaintext files.
pub trait PkceSessionStorage: Send + Sync {
    /// Saves a PKCE session securely.
    ///
    /// # Arguments
    ///
    /// * `state_hash` - The hashed state parameter (used as key)
    /// * `session_json` - The serialized session data
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails (e.g. keyring unavailable).
    fn save_session(&self, state_hash: &str, session_json: &str) -> Result<(), String>;

    /// Retrieves a PKCE session from secure storage.
    ///
    /// # Arguments
    ///
    /// * `state_hash` - The hashed state parameter (used as key)
    ///
    /// # Returns
    ///
    /// * `Ok(Some(session_json))` - The session data if found
    /// * `Ok(None)` - If session not found
    /// * `Err(...)` - If retrieval fails
    ///
    /// # Errors
    ///
    /// Returns an error if the keyring is unavailable or access fails.
    fn get_session(&self, state_hash: &str) -> Result<Option<String>, String>;

    /// Deletes a PKCE session from secure storage.
    ///
    /// # Arguments
    ///
    /// * `state_hash` - The hashed state parameter (used as key)
    ///
    /// # Errors
    ///
    /// Returns an error if deletion fails.
    fn delete_session(&self, state_hash: &str) -> Result<(), String>;
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
            let _ = (service, user_key, secret);
            Ok(())
        }
    }
}

/// Default implementation of `PkceSessionStorage` using OS keyring.
pub struct KeyringPkceStorage;

impl PkceSessionStorage for KeyringPkceStorage {
    fn save_session(&self, state_hash: &str, session_json: &str) -> Result<(), String> {
        #[cfg(not(test))]
        {
            let entry =
                keyring::Entry::new("aroeira-oauth-pkce", state_hash).map_err(|e| e.to_string())?;
            entry
                .set_password(session_json)
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        #[cfg(test)]
        {
            let _ = (state_hash, session_json);
            Ok(())
        }
    }

    fn get_session(&self, state_hash: &str) -> Result<Option<String>, String> {
        #[cfg(not(test))]
        {
            let entry =
                keyring::Entry::new("aroeira-oauth-pkce", state_hash).map_err(|e| e.to_string())?;
            match entry.get_password() {
                Ok(password) => Ok(Some(password)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        }
        #[cfg(test)]
        {
            let _ = state_hash;
            Ok(None)
        }
    }

    fn delete_session(&self, state_hash: &str) -> Result<(), String> {
        #[cfg(not(test))]
        {
            let entry =
                keyring::Entry::new("aroeira-oauth-pkce", state_hash).map_err(|e| e.to_string())?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        #[cfg(test)]
        {
            let _ = state_hash;
            Ok(())
        }
    }
}

/// `OAuth2` service implementation using PKCE flow.
///
/// This implementation:
/// - Generates authorization URLs with PKCE challenges
/// - Exchanges authorization codes for tokens
/// - Fetches user info from provider APIs
pub struct OAuthServiceImpl {
    pub config: OAuthConfig,
    token_storage: std::sync::Arc<dyn TokenStorage>,
}

impl OAuthServiceImpl {
    /// Google `OAuth2` authorization endpoint
    const GOOGLE_AUTH_URL: &'static str = "https://accounts.google.com/o/oauth2/v2/auth";
    /// Google `OAuth2` token endpoint
    const GOOGLE_TOKEN_URL: &'static str = "https://oauth2.googleapis.com/token";
    /// Google userinfo endpoint
    const GOOGLE_USERINFO_URL: &'static str = "https://openidconnect.googleapis.com/v1/userinfo";

    /// GitHub `OAuth2` authorization endpoint
    const GITHUB_AUTH_URL: &'static str = "https://github.com/login/oauth/authorize";
    /// GitHub `OAuth2` token endpoint
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
            token_storage: std::sync::Arc::new(KeyringTokenStorage),
        }
    }

    /// Creates a new OAuth service with injected storage (for testing).
    #[cfg(test)]
    #[must_use]
    pub fn new_with_storage(
        config: OAuthConfig,
        storage: std::sync::Arc<dyn TokenStorage>,
    ) -> Self {
        Self {
            config,
            token_storage: storage,
        }
    }

    /// Gets client ID, secret (for GitHub), and URLs for a provider.
    fn get_provider_config(
        &self,
        provider: AuthProvider,
    ) -> Result<(&str, Option<&str>, &str, &str), OAuthError> {
        match provider {
            AuthProvider::Google => {
                let client_id = self
                    .config
                    .google_client_id
                    .as_ref()
                    .ok_or_else(|| OAuthError::ProviderNotConfigured("Google".to_string()))?;
                Ok((
                    client_id.as_str(),
                    None, // Google uses PKCE without client secret
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

                // Client secret is optional (e.g. when using BFF proxy or if GitHub App is public)
                let client_secret = self
                    .config
                    .github_client_secret
                    .as_ref()
                    .filter(|s| !s.expose_secret().is_empty())
                    .map(secrecy::ExposeSecret::expose_secret);

                if client_secret.is_none() {
                    debug!(
                        "GitHub OAuth is configured without a client secret (Public Client / Proxy mode)"
                    );
                }

                Ok((
                    client_id.as_str(),
                    client_secret,
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

        let body =
            read_response_body_with_limit(response, MAX_OAUTH_HTTP_BODY_BYTES, "Google userinfo")
                .await
                .map_err(OAuthError::UserInfoFailed)?;

        let user_info: GoogleUserInfo =
            serde_json::from_slice(&body).map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

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

        let body =
            read_response_body_with_limit(user_response, MAX_OAUTH_HTTP_BODY_BYTES, "GitHub user")
                .await
                .map_err(OAuthError::UserInfoFailed)?;

        let user_info: GitHubUserInfo =
            serde_json::from_slice(&body).map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

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

        let body =
            read_response_body_with_limit(response, MAX_OAUTH_HTTP_BODY_BYTES, "GitHub emails")
                .await
                .map_err(OAuthError::UserInfoFailed)?;

        let emails: Vec<GitHubEmail> =
            serde_json::from_slice(&body).map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

        // Security Critical: Only accept primary verified email
        // This removes the fallback to any verified email and prevents potential account confusion
        // (users can have multiple verified emails; picking a non-primary one can map to wrong account)
        let email_obj = emails
            .iter()
            .find(|e| e.primary && e.verified)
            .ok_or_else(|| {
                OAuthError::UserInfoFailed("No primary verified email found".to_string())
            })?;

        // Security Critical: Enforce primary verified email flag to true
        // This provides clearer intent and avoids ambiguity
        Ok((email_obj.email.clone(), true))
    }
}

#[async_trait]
impl OAuthService for OAuthServiceImpl {
    async fn generate_authorization_url(
        &self,
        provider: AuthProvider,
    ) -> Result<(String, OAuthPkceSession), OAuthError> {
        debug!("Generating authorization URL for {:?}", provider);

        let (client_id, _client_secret, auth_url_str, token_url_str) =
            self.get_provider_config(provider)?;

        // Parse URLs
        let auth_url = AuthUrl::new(auth_url_str.to_string()).map_err(|e| {
            OAuthError::ProviderNotConfigured(format!("Invalid authorization URL: {e}"))
        })?;
        let token_url = TokenUrl::new(token_url_str.to_string())
            .map_err(|e| OAuthError::ProviderNotConfigured(format!("Invalid token URL: {e}")))?;

        // Fail-closed allowlist for redirect URI to prevent token/code exfiltration via misconfig.
        let ru = self.config.redirect_uri.as_str();
        let is_prod = ru == "aroeira://auth/callback";
        let dev_port: u16 = std::env::var("AROEIRA_DEV_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(1420);
        let is_dev =
            cfg!(debug_assertions) && ru == format!("http://localhost:{dev_port}/auth/callback");
        if !is_prod && !is_dev {
            return Err(OAuthError::ProviderNotConfigured(
                "Invalid redirect URI: not allowlisted".to_string(),
            ));
        }

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
        let state = hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()));
        let mut auth_request = client.authorize_url(|| CsrfToken::new(state.clone()));
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

        validate_session(session)?;

        let (client_id, client_secret, auth_url_str, token_url_str) =
            self.get_provider_config(session.provider)?;

        // Parse URLs
        let auth_url = AuthUrl::new(auth_url_str.to_string())
            .map_err(|e| OAuthError::CodeExchangeFailed(e.to_string()))?;
        let token_url = TokenUrl::new(token_url_str.to_string())
            .map_err(|e| OAuthError::CodeExchangeFailed(e.to_string()))?;
        let redirect_url = RedirectUrl::new(self.config.redirect_uri.clone())
            .map_err(|e| OAuthError::CodeExchangeFailed(e.to_string()))?;

        let client_id = ClientId::new(client_id.to_string());

        let token_result = perform_token_exchange(
            client_id,
            client_secret,
            auth_url,
            token_url,
            redirect_url,
            session,
            code,
        )
        .await?;

        let access_token = token_result.access_token().secret();

        // Fetch user info based on provider
        let user = match session.provider {
            AuthProvider::Google => self.fetch_google_user(access_token).await,
            AuthProvider::GitHub => self.fetch_github_user(access_token).await,
        }?;

        store_tokens(&self.token_storage, &user, &token_result).await?;

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

/// Custom error type for OAuth HTTP client to handle both reqwest and IO errors
#[derive(Debug, thiserror::Error)]
pub enum OAuthHttpClientError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

const MAX_OAUTH_HTTP_BODY_BYTES: usize = 1_048_576; // 1 MiB

/// Helper to read response body with a size limit to prevent `DoS`.
async fn read_response_body_with_limit(
    mut response: reqwest::Response,
    limit: usize,
    error_context: &str,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|len| len > limit as u64)
    {
        return Err(format!("{error_context} response too large"));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(format!("{error_context} response too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Custom async HTTP client for oauth2 crate with timeout and proper configuration.
///
/// This replaces `oauth2::reqwest::async_http_client` which doesn't have a timeout by default.
async fn async_http_client(
    request: oauth2::HttpRequest,
) -> Result<oauth2::HttpResponse, OAuthHttpClientError> {
    // Use static client for connection pooling
    let client = &*ASYNC_HTTP_CLIENT;

    let mut request_builder = client.request(request.method().clone(), request.uri().to_string());
    // Only set body for methods that typically have one (POST, PUT, PATCH)
    // GET requests should not have a body per HTTP/1.1 spec
    if *request.method() != oauth2::http::Method::GET && !request.body().is_empty() {
        request_builder = request_builder.body(request.body().clone());
    }

    let mut has_content_type = false;
    for (name, value) in request.headers() {
        if name.as_str().eq_ignore_ascii_case("content-length") {
            continue;
        }
        if name.as_str().eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
        request_builder = request_builder.header(name, value);
    }

    if !has_content_type
        && *request.method() != oauth2::http::Method::GET
        && !request.body().is_empty()
    {
        request_builder = request_builder.header(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
    }

    let response = request_builder.send().await?;

    let status = response.status();
    let headers = response.headers().clone();

    let body = read_response_body_with_limit(response, MAX_OAUTH_HTTP_BODY_BYTES, "OAuth HTTP")
        .await
        .map_err(|e| {
            if e.contains("too large") {
                error!("OAuth HTTP response body exceeded maximum allowed size");
                OAuthHttpClientError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            } else {
                OAuthHttpClientError::Io(std::io::Error::other(e))
            }
        })?;

    let mut resp = oauth2::HttpResponse::new(body);
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    Ok(resp)
}

fn validate_session(session: &OAuthPkceSession) -> Result<(), OAuthError> {
    if !session.is_valid() {
        // Check if it's expired (now included in is_valid)
        if session.is_expired() {
            warn!("Session expired");
            return Err(OAuthError::SessionNotFound);
        }
        warn!("Invalid PKCE session (failed validation)");
        return Err(OAuthError::CodeExchangeFailed(
            "Invalid PKCE session".to_string(),
        ));
    }

    Ok(())
}

async fn perform_token_exchange(
    client_id: ClientId,
    client_secret: Option<&str>,
    auth_url: AuthUrl,
    token_url: TokenUrl,
    redirect_url: RedirectUrl,
    session: &OAuthPkceSession,
    code: String,
) -> Result<
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    OAuthError,
> {
    // Create OAuth2 client
    let client = oauth2::basic::BasicClient::new(client_id)
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);

    // Perform token exchange with timeout and provider-specific adjustments
    let exchange_future = async {
        if session.provider == AuthProvider::GitHub {
            // GitHub requires client secret even with PKCE
            let client = if let Some(secret) = client_secret {
                client.set_client_secret(oauth2::ClientSecret::new(secret.to_string()))
            } else {
                client
            };
            let verifier = PkceCodeVerifier::new(session.pkce_verifier.clone());
            let token_request = client
                .exchange_code(AuthorizationCode::new(code.clone()))
                .set_pkce_verifier(verifier);

            // GitHub requires Accept: application/json and commonly expects a User-Agent
            token_request
                .request_async(&|mut req: oauth2::HttpRequest| async move {
                    req.headers_mut().insert(
                        reqwest::header::ACCEPT,
                        reqwest::header::HeaderValue::from_static("application/json"),
                    );
                    req.headers_mut().insert(
                        reqwest::header::USER_AGENT,
                        reqwest::header::HeaderValue::from_static("Aroeira-Desktop"),
                    );
                    async_http_client(req).await
                })
                .await
                .map_err(|e| OAuthError::TokenRequestFailed(e.to_string()))
        } else {
            let verifier = PkceCodeVerifier::new(session.pkce_verifier.clone());
            let token_request = client
                .exchange_code(AuthorizationCode::new(code.clone()))
                .set_pkce_verifier(verifier);

            // Other providers (Google) work with default client
            token_request
                .request_async(&async_http_client)
                .await
                .map_err(|e| OAuthError::TokenRequestFailed(e.to_string()))
        }
    };

    // Execute with timeout
    tokio::time::timeout(std::time::Duration::from_secs(30), exchange_future)
        .await
        .map_err(|_| OAuthError::TokenRequestFailed("Token exchange timed out".to_string()))?
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
        })
}

async fn store_tokens(
    storage: &std::sync::Arc<dyn TokenStorage>,
    user: &OAuthUser,
    token_result: &oauth2::StandardTokenResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
) -> Result<(), OAuthError> {
    let user_key = format!("{}:{}", user.provider, user.provider_user_id);

    // Hash user key for logging and storage to avoid PII leak in OS store/logs
    let mut hasher = Sha256::new();
    hasher.update(user_key.as_bytes());
    let user_key_hash = hex::encode(hasher.finalize());

    // Create token payload. Include refresh token for long-lived sessions if available.
    // Validate tokens before creating payload
    let access_token = token_result.access_token().secret().clone();
    if access_token.trim().is_empty() {
        return Err(OAuthError::TokenRequestFailed(
            "Provider returned an empty access token".to_string(),
        ));
    }

    let refresh_token = token_result
        .refresh_token()
        .map(|t| t.secret().clone())
        .filter(|t| !t.trim().is_empty());

    let token_payload = serde_json::json!({
        "access_token": access_token,
        "refresh_token": refresh_token,
    });

    // Prevent blocking async runtime with synchronous keyring operations
    let storage = storage.clone();
    let token_payload_str = token_payload.to_string();
    let user_key_hash_for_store = user_key_hash.clone();

    let store_result = tokio::task::spawn_blocking(move || {
        let service_name = "aroeira-oauth".to_string();
        storage.store(&service_name, &user_key_hash_for_store, &token_payload_str)
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))
    .and_then(|r| r);

    if let Err(e) = store_result {
        warn!(
            "OAuth token not stored in OS keyring (failing login): {}",
            e
        );
        return Err(OAuthError::TokenRequestFailed(
            "Failed to persist session securely".to_string(),
        ));
    }
    debug!("Securely stored OAuth token for {}", user_key_hash);
    Ok(())
}

#[cfg(test)]
mod tests;
