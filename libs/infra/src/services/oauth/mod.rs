//! `OAuth2` Service Implementation - TDD GREEN PHASE

mod client;
mod models;
mod storage;

#[cfg(test)]
mod tests;

pub use client::{OAuthHttpClientError, async_http_client, read_response_body_with_limit};
pub use models::{GitHubEmail, GitHubUserInfo, GoogleUserInfo};
pub use storage::{
    KeyringPkceStorage, KeyringTokenStorage, MockPkceStorage, MockTokenStorage, PkceSessionStorage,
    PkceSessionStorageEnum, TokenStorage, TokenStorageEnum,
};

use crate::utils::encode_hex;
use domain::modules::auth::oauth::{
    AuthProvider, OAuthError, OAuthPkceSession, OAuthService, OAuthUser,
};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};
use uuid::Uuid;

// Constants for keyring service names to prevent typo-based fragmentation
pub const PKCE_SESSION_KEYRING_SERVICE: &str = "aroeira-oauth-pkce";
pub const TOKEN_KEYRING_SERVICE: &str = "aroeira-oauth";

const OAUTH_CALLBACK_HOST: &str = "auth";
const OAUTH_CALLBACK_PATH: &str = "/callback";

/// Configuration for `OAuth2` providers.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub google_client_id: Option<String>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<secrecy::SecretString>,
    pub redirect_uri: String,

    pub google_auth_url: Option<String>,
    pub google_token_url: Option<String>,
    pub google_userinfo_url: Option<String>,

    pub github_auth_url: Option<String>,
    pub github_token_url: Option<String>,
    pub github_user_url: Option<String>,
    pub github_emails_url: Option<String>,
}

impl OAuthConfig {
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

pub struct OAuthServiceImpl {
    pub config: OAuthConfig,
    token_storage: TokenStorageEnum,
}

impl OAuthServiceImpl {
    const GOOGLE_AUTH_URL: &'static str = "https://accounts.google.com/o/oauth2/v2/auth";
    const GOOGLE_TOKEN_URL: &'static str = "https://oauth2.googleapis.com/token";
    const GOOGLE_USERINFO_URL: &'static str = "https://openidconnect.googleapis.com/v1/userinfo";

    pub const GITHUB_AUTH_URL: &'static str = "https://github.com/login/oauth/authorize";
    pub const GITHUB_TOKEN_URL: &'static str = "https://github.com/login/oauth/access_token";
    pub const GITHUB_USER_URL: &'static str = "https://api.github.com/user";
    pub const GITHUB_EMAILS_URL: &'static str = "https://api.github.com/user/emails";

    #[must_use]
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            config,
            token_storage: TokenStorageEnum::new_keyring(),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn new_with_storage(config: OAuthConfig, storage: TokenStorageEnum) -> Self {
        Self {
            config,
            token_storage: storage,
        }
    }

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
                    None,
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

                let client_secret = self
                    .config
                    .github_client_secret
                    .as_ref()
                    .filter(|s| !s.expose_secret().trim().is_empty())
                    .map(secrecy::ExposeSecret::expose_secret);

                let token_url = self
                    .config
                    .github_token_url
                    .as_deref()
                    .unwrap_or(Self::GITHUB_TOKEN_URL);

                if token_url == Self::GITHUB_TOKEN_URL && client_secret.is_none() {
                    return Err(OAuthError::ProviderNotConfigured(
                        "GitHub client secret is required for the default token endpoint"
                            .to_string(),
                    ));
                }

                Ok((
                    client_id.as_str(),
                    client_secret,
                    self.config
                        .github_auth_url
                        .as_deref()
                        .unwrap_or(Self::GITHUB_AUTH_URL),
                    token_url,
                ))
            }
        }
    }

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

    async fn fetch_google_user(&self, access_token: &str) -> Result<OAuthUser, OAuthError> {
        let url = self
            .config
            .google_userinfo_url
            .as_deref()
            .unwrap_or(Self::GOOGLE_USERINFO_URL);
        let response = client::ASYNC_HTTP_CLIENT
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

        let body = read_response_body_with_limit(
            response,
            client::MAX_OAUTH_HTTP_BODY_BYTES,
            "Google userinfo",
        )
        .await
        .map_err(OAuthError::UserInfoFailed)?;

        let user_info: GoogleUserInfo =
            serde_json::from_slice(&body).map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

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

    async fn fetch_github_user(&self, access_token: &str) -> Result<OAuthUser, OAuthError> {
        let url = self
            .config
            .github_user_url
            .as_deref()
            .unwrap_or(Self::GITHUB_USER_URL);
        let user_response = client::ASYNC_HTTP_CLIENT
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

        let body = read_response_body_with_limit(
            user_response,
            client::MAX_OAUTH_HTTP_BODY_BYTES,
            "GitHub user",
        )
        .await
        .map_err(OAuthError::UserInfoFailed)?;

        let user_info: GitHubUserInfo =
            serde_json::from_slice(&body).map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

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

    async fn fetch_github_primary_email(
        &self,
        access_token: &str,
    ) -> Result<(String, bool), OAuthError> {
        let url = self
            .config
            .github_emails_url
            .as_deref()
            .unwrap_or(Self::GITHUB_EMAILS_URL);
        let response = client::ASYNC_HTTP_CLIENT
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

        let body = read_response_body_with_limit(
            response,
            client::MAX_OAUTH_HTTP_BODY_BYTES,
            "GitHub emails",
        )
        .await
        .map_err(OAuthError::UserInfoFailed)?;

        let emails: Vec<GitHubEmail> =
            serde_json::from_slice(&body).map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

        let email_obj = emails
            .iter()
            .find(|e| e.primary && e.verified)
            .ok_or_else(|| {
                OAuthError::UserInfoFailed("No primary verified email found".to_string())
            })?;

        Ok((email_obj.email.clone(), true))
    }

    /// Validates and constructs the redirect URL for the configured provider.
    fn validate_and_get_redirect_url(&self) -> Result<RedirectUrl, OAuthError> {
        let ru_url = url::Url::parse(self.config.redirect_uri.as_str())
            .map_err(|e| OAuthError::ProviderNotConfigured(format!("Invalid redirect URI: {e}")))?;

        // Extra hardening: disallow userinfo, fragments, and unexpected query strings.
        if !ru_url.username().is_empty()
            || ru_url.password().is_some()
            || ru_url.fragment().is_some()
            || ru_url.query().is_some()
        {
            return Err(OAuthError::ProviderNotConfigured(
                "Invalid redirect URI: contains disallowed components".to_string(),
            ));
        }

        let is_allowed_prod_scheme = matches!(ru_url.scheme(), "com.aroeira.app" | "aroeira");
        let is_prod = is_allowed_prod_scheme
            && ru_url.host_str() == Some(OAUTH_CALLBACK_HOST)
            && ru_url.path() == OAUTH_CALLBACK_PATH;

        let dev_port: u16 = std::env::var("AROEIRA_DEV_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(1420);

        let allow_dev_redirect = cfg!(debug_assertions)
            && std::env::var("AROEIRA_ALLOW_DEV_REDIRECT")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

        let is_dev = allow_dev_redirect
            && ru_url.scheme() == "http"
            && ru_url.host_str() == Some("localhost")
            && ru_url.port() == Some(dev_port)
            && ru_url.path() == OAUTH_CALLBACK_PATH
            && ru_url.query().is_none()
            && ru_url.fragment().is_none();

        if !is_prod && !is_dev {
            return Err(OAuthError::ProviderNotConfigured(
                "Invalid redirect URI: not allowlisted".to_string(),
            ));
        }

        RedirectUrl::new(self.config.redirect_uri.clone())
            .map_err(|e| OAuthError::ProviderNotConfigured(format!("Invalid redirect URI: {e}")))
    }

    fn validate_secure_url(url_str: &str, context: &str) -> Result<(), OAuthError> {
        let u = url::Url::parse(url_str).map_err(|e| {
            OAuthError::ProviderNotConfigured(format!("Invalid {context} URL format: {e}"))
        })?;

        // Extra hardening: disallow credentials and fragments in provider endpoints.
        if !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
            return Err(OAuthError::ProviderNotConfigured(format!(
                "Invalid {context} URL: contains disallowed components"
            )));
        }

        if u.scheme() != "https" {
            let is_local = u
                .host_str()
                .is_some_and(|h| h == "localhost" || h == "127.0.0.1");

            // In debug builds, require explicit opt-in via environment variable
            // to allow non-HTTPS URLs for local development.
            let allow_insecure_local = cfg!(debug_assertions)
                && std::env::var("AROEIRA_ALLOW_INSECURE_OAUTH_URLS")
                    .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

            if !is_local || !allow_insecure_local {
                return Err(OAuthError::ProviderNotConfigured(format!(
                    "{context} URL must be HTTPS (or set AROEIRA_ALLOW_INSECURE_OAUTH_URLS=1 for local dev)"
                )));
            }
        }
        Ok(())
    }

    /// Checks if a given OAuth provider is configured and available for use.
    #[must_use]
    pub fn is_provider_available(&self, provider: AuthProvider) -> bool {
        match provider {
            AuthProvider::Google => self
                .config
                .google_client_id
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty()),
            AuthProvider::GitHub => {
                let has_client_id = self
                    .config
                    .github_client_id
                    .as_ref()
                    .is_some_and(|s| !s.trim().is_empty());
                if !has_client_id {
                    return false;
                }

                let token_url = self
                    .config
                    .github_token_url
                    .as_deref()
                    .unwrap_or(Self::GITHUB_TOKEN_URL);
                let has_secret = self
                    .config
                    .github_client_secret
                    .as_ref()
                    .is_some_and(|s| !s.expose_secret().trim().is_empty());

                let is_direct_mode_ok = token_url == Self::GITHUB_TOKEN_URL && has_secret;
                let is_proxy_mode_ok = token_url != Self::GITHUB_TOKEN_URL;

                is_direct_mode_ok || is_proxy_mode_ok
            }
        }
    }
}

impl OAuthService for OAuthServiceImpl {
    async fn generate_authorization_url(
        &self,
        provider: AuthProvider,
    ) -> Result<(String, OAuthPkceSession), OAuthError> {
        debug!("Generating authorization URL for {:?}", provider);

        let (client_id, _client_secret, auth_url_str, token_url_str) =
            self.get_provider_config(provider)?;

        Self::validate_secure_url(auth_url_str, "authorization")?;
        Self::validate_secure_url(token_url_str, "token")?;

        let auth_url = AuthUrl::new(auth_url_str.to_string()).map_err(|e| {
            OAuthError::ProviderNotConfigured(format!("Invalid authorization URL: {e}"))
        })?;
        let token_url = TokenUrl::new(token_url_str.to_string())
            .map_err(|e| OAuthError::ProviderNotConfigured(format!("Invalid token URL: {e}")))?;

        let redirect_url = self.validate_and_get_redirect_url()?;

        let client = oauth2::basic::BasicClient::new(ClientId::new(client_id.to_string()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(redirect_url);

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let state = encode_hex(Sha256::digest(Uuid::new_v4().as_bytes()));
        let mut auth_request = client.authorize_url(|| CsrfToken::new(state.clone()));
        for scope in Self::get_scopes(provider) {
            auth_request = auth_request.add_scope(scope);
        }
        let (auth_url, csrf_state) = auth_request.set_pkce_challenge(pkce_challenge).url();

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

        Self::validate_secure_url(auth_url_str, "authorization")?;
        Self::validate_secure_url(token_url_str, "token")?;

        let auth_url = AuthUrl::new(auth_url_str.to_string())
            .map_err(|e| OAuthError::CodeExchangeFailed(e.to_string()))?;
        let token_url = TokenUrl::new(token_url_str.to_string())
            .map_err(|e| OAuthError::CodeExchangeFailed(e.to_string()))?;
        let redirect_url = self.validate_and_get_redirect_url()?;

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
        if access_token.trim().is_empty() {
            return Err(OAuthError::TokenRequestFailed(
                "Provider returned an empty access token".to_string(),
            ));
        }

        let user = match session.provider {
            AuthProvider::Google => self.fetch_google_user(access_token).await,
            AuthProvider::GitHub => self.fetch_github_user(access_token).await,
        }?;

        store_tokens(&self.token_storage, &user, &token_result).await?;

        Ok(user)
    }
}

fn validate_session(session: &OAuthPkceSession) -> Result<(), OAuthError> {
    if !session.is_valid() {
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
    let client = oauth2::basic::BasicClient::new(client_id)
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);

    let exchange_future = async {
        if session.provider == AuthProvider::GitHub {
            let client = if let Some(secret) = client_secret {
                client.set_client_secret(oauth2::ClientSecret::new(secret.to_string()))
            } else {
                client
            };
            let verifier = PkceCodeVerifier::new(session.pkce_verifier.clone());
            let token_request = client
                .exchange_code(AuthorizationCode::new(code.clone()))
                .set_pkce_verifier(verifier);

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

            token_request
                .request_async(&async_http_client)
                .await
                .map_err(|e| OAuthError::TokenRequestFailed(e.to_string()))
        }
    };

    tokio::time::timeout(std::time::Duration::from_secs(30), exchange_future)
        .await
        .map_err(|_| OAuthError::TokenRequestFailed("Token exchange timed out".to_string()))?
}

const MAX_TOKEN_PAYLOAD_BYTES: usize = 16 * 1024;
const MAX_TOKEN_LENGTH: usize = 8 * 1024;

async fn store_tokens(
    storage: &TokenStorageEnum,
    user: &OAuthUser,
    token_result: &oauth2::StandardTokenResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
) -> Result<(), OAuthError> {
    let provider_key = match user.provider {
        AuthProvider::Google => "google",
        AuthProvider::GitHub => "github",
    };
    let user_key = format!("{provider_key}:{}", user.provider_user_id);

    let mut hasher = Sha256::new();

    hasher.update(user_key.as_bytes());
    let user_key_hash = encode_hex(hasher.finalize());

    let access_token = token_result.access_token().secret().clone();
    if access_token.trim().is_empty() || access_token.len() > MAX_TOKEN_LENGTH {
        return Err(OAuthError::TokenRequestFailed(
            "Provider returned an invalid access token".to_string(),
        ));
    }

    let refresh_token = token_result
        .refresh_token()
        .map(|t| t.secret().clone())
        .filter(|t| !t.trim().is_empty() && t.len() <= MAX_TOKEN_LENGTH);

    let mut token_payload = serde_json::json!({
        "access_token": access_token,
    });
    if let Some(rt) = refresh_token {
        token_payload["refresh_token"] = serde_json::Value::String(rt);
    }

    let token_payload_str = token_payload.to_string();
    if token_payload_str.len() > MAX_TOKEN_PAYLOAD_BYTES {
        return Err(OAuthError::TokenRequestFailed(
            "Provider returned an unexpectedly large token payload".to_string(),
        ));
    }

    let user_key_hash_for_store = user_key_hash.clone();
    let storage_clone = storage.clone();

    let store_result = tokio::task::spawn_blocking(move || {
        let service_name = TOKEN_KEYRING_SERVICE.to_string();
        storage_clone.store(&service_name, &user_key_hash_for_store, &token_payload_str)
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
