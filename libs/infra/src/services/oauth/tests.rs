//! TDD RED PHASE: Integration tests for OAuth service.
//! Tests written BEFORE implementation exists.

#[cfg(test)]
use super::*;
use domain::modules::auth::oauth::{AuthProvider, OAuthService};

// ===========================================
// Authorization URL Generation Tests
// ===========================================

#[tokio::test]
async fn generate_url_for_google_includes_required_params() {
    let service = OAuthServiceImpl::new(OAuthConfig {
        google_client_id: Some("test-google-client-id".to_string()),
        github_client_id: None,
        github_client_secret: None,
        redirect_uri: "aroeira://auth/callback".to_string(),
        google_auth_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_auth_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    });

    let (url, session) = service
        .generate_authorization_url(AuthProvider::Google)
        .await
        .expect("Should generate URL for Google");

    // URL must contain required OAuth2 params
    assert!(
        url.contains("client_id=test-google-client-id"),
        "URL should contain client_id"
    );
    assert!(
        url.contains("response_type=code"),
        "URL should contain response_type=code"
    );
    assert!(
        url.contains("redirect_uri="),
        "URL should contain redirect_uri"
    );
    assert!(
        url.contains("code_challenge="),
        "URL should contain PKCE code_challenge"
    );
    assert!(
        url.contains("code_challenge_method=S256"),
        "URL should use S256 challenge method"
    );
    assert!(
        url.contains("state="),
        "URL should contain state for CSRF protection"
    );

    // Required scopes for Google OpenID Connect
    assert!(url.contains("scope="), "URL should contain scope parameter");
    assert!(
        url.contains("openid"),
        "URL should request openid scope for Google"
    );
    assert!(
        url.contains("email"),
        "URL should request email scope for Google"
    );

    // Session should be valid
    assert!(session.is_valid(), "Session should be valid");
    assert_eq!(session.provider, AuthProvider::Google);
}

#[tokio::test]
async fn generate_url_for_github_includes_required_params() {
    let service = OAuthServiceImpl::new(OAuthConfig {
        google_client_id: None,
        github_client_id: Some("test-github-client-id".to_string()),
        github_client_secret: Some(secrecy::SecretString::from(
            "test-github-client-secret".to_string(),
        )),
        redirect_uri: "aroeira://auth/callback".to_string(),
        google_auth_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_auth_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    });

    let (url, session) = service
        .generate_authorization_url(AuthProvider::GitHub)
        .await
        .expect("Should generate URL for GitHub");

    assert!(
        url.contains("client_id=test-github-client-id"),
        "URL should contain client_id"
    );
    assert!(url.contains("github.com"), "URL should be for github.com");
    assert!(
        url.contains("state="),
        "URL should contain state for CSRF protection"
    );

    // GitHub scopes
    assert!(url.contains("scope="), "URL should contain scope parameter");
    assert!(
        url.contains("read:user") || url.contains("user"),
        "URL should request user scope for GitHub"
    );

    assert!(session.is_valid(), "Session should be valid");
    assert_eq!(session.provider, AuthProvider::GitHub);
}

#[tokio::test]
async fn generate_url_fails_when_google_not_configured() {
    let service = OAuthServiceImpl::new(OAuthConfig {
        google_client_id: None, // Google not configured!
        github_client_id: None,
        github_client_secret: None,
        redirect_uri: "aroeira://auth/callback".to_string(),
        google_auth_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_auth_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    });

    let result = service
        .generate_authorization_url(AuthProvider::Google)
        .await;

    assert!(result.is_err(), "Should fail when Google not configured");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Google") || err.contains("not configured"),
        "Error should mention provider or configuration issue"
    );
}

#[tokio::test]
async fn generate_url_fails_when_github_not_configured() {
    let service = OAuthServiceImpl::new(OAuthConfig {
        google_client_id: None,
        github_client_id: None, // GitHub not configured!
        github_client_secret: None,
        redirect_uri: "aroeira://auth/callback".to_string(),
        google_auth_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_auth_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    });

    let result = service
        .generate_authorization_url(AuthProvider::GitHub)
        .await;

    assert!(result.is_err(), "Should fail when GitHub not configured");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("GitHub") || err.contains("not configured"),
        "Error should mention provider or configuration issue"
    );
}

#[tokio::test]
async fn session_state_matches_url_state_param() {
    let service = OAuthServiceImpl::new(OAuthConfig {
        google_client_id: Some("client-id".to_string()),
        github_client_id: None,
        github_client_secret: None,
        redirect_uri: "aroeira://auth/callback".to_string(),
        google_auth_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_auth_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    });

    let (url, session) = service
        .generate_authorization_url(AuthProvider::Google)
        .await
        .expect("Should generate URL");

    // The state in URL must match session.state
    assert!(
        url.contains(&format!("state={}", session.state)),
        "URL state param must match session state"
    );
}

#[tokio::test]
async fn pkce_verifier_in_session_is_valid_length() {
    let service = OAuthServiceImpl::new(OAuthConfig {
        google_client_id: Some("client-id".to_string()),
        github_client_id: None,
        github_client_secret: None,
        redirect_uri: "aroeira://auth/callback".to_string(),
        google_auth_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_auth_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    });

    let (_, session) = service
        .generate_authorization_url(AuthProvider::Google)
        .await
        .expect("Should generate URL");

    // PKCE verifier must be 43-128 chars (RFC 7636)
    assert!(
        session.pkce_verifier.len() >= 43,
        "PKCE verifier must be at least 43 chars"
    );
    assert!(
        session.pkce_verifier.len() <= 128,
        "PKCE verifier must be at most 128 chars"
    );
    assert!(session.is_valid(), "Session should be valid");
}

#[tokio::test]
async fn each_url_generation_produces_unique_state() {
    let service = OAuthServiceImpl::new(OAuthConfig {
        google_client_id: Some("client-id".to_string()),
        github_client_id: None,
        github_client_secret: None,
        redirect_uri: "aroeira://auth/callback".to_string(),
        google_auth_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_auth_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    });

    let (_, session1) = service
        .generate_authorization_url(AuthProvider::Google)
        .await
        .expect("Should generate first URL");

    let (_, session2) = service
        .generate_authorization_url(AuthProvider::Google)
        .await
        .expect("Should generate second URL");

    assert_ne!(
        session1.state, session2.state,
        "Each generation should produce unique state"
    );
    assert_ne!(
        session1.pkce_verifier, session2.pkce_verifier,
        "Each generation should produce unique PKCE verifier"
    );
}

#[tokio::test]
async fn redirect_uri_is_properly_encoded_in_url() {
    let service = OAuthServiceImpl::new(OAuthConfig {
        google_client_id: Some("client-id".to_string()),
        github_client_id: None,
        github_client_secret: None,
        redirect_uri: "aroeira://auth/callback".to_string(),
        google_auth_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_auth_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    });

    let (url, _) = service
        .generate_authorization_url(AuthProvider::Google)
        .await
        .expect("Should generate URL");

    // redirect_uri should be URL-encoded
    // "aroeira://auth/callback" -> "aroeira%3A%2F%2Fauth%2Fcallback" or similar
    assert!(
        url.contains("redirect_uri="),
        "URL should contain redirect_uri"
    );
    // The colon and slashes should be percent-encoded or the full URI present
    assert!(
        url.contains("aroeira") && url.contains("callback"),
        "Redirect URI parts should be in URL"
    );
}

// ===========================================
// Code Exchange Tests (will need HTTP mocking)
// ===========================================

#[tokio::test]
async fn exchange_code_fails_on_expired_session() {
    use chrono::{Duration, Utc};
    use domain::modules::auth::oauth::OAuthPkceSession;

    let service = OAuthServiceImpl::new(OAuthConfig {
        google_client_id: Some("client-id".to_string()),
        github_client_id: None,
        github_client_secret: None,
        redirect_uri: "aroeira://auth/callback".to_string(),
        google_auth_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_auth_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    });

    // Create an expired session
    let mut session = OAuthPkceSession::new(
        "test-state".to_string(),
        "a".repeat(43),
        AuthProvider::Google,
    );
    session.created_at = Utc::now() - Duration::minutes(15); // 15 min old

    let result = service
        .exchange_code(&session, "some-code".to_string())
        .await;

    assert!(result.is_err(), "Should fail on expired session");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("expired") || err.contains("Session not found"),
        "Error should mention expiration"
    );
}

#[tokio::test]
async fn exchange_code_fails_on_invalid_session() {
    use domain::modules::auth::oauth::OAuthPkceSession;

    let service = OAuthServiceImpl::new(OAuthConfig {
        google_client_id: Some("client-id".to_string()),
        github_client_id: None,
        github_client_secret: None,
        redirect_uri: "aroeira://auth/callback".to_string(),
        google_auth_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_auth_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    });

    // Create an invalid session (verifier too short)
    let session = OAuthPkceSession::new(
        "test-state".to_string(),
        "short".to_string(), // Invalid - too short
        AuthProvider::Google,
    );

    let result = service
        .exchange_code(&session, "some-code".to_string())
        .await;

    assert!(result.is_err(), "Should fail on invalid session");
}

#[tokio::test]
async fn exchange_code_success_google() {
    use domain::modules::auth::oauth::OAuthPkceSession;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Start mock server
    let mock_server = MockServer::start().await;

    // Config with mock URLs
    let config = OAuthConfig {
        google_client_id: Some("client-id".to_string()),
        github_client_id: None,
        github_client_secret: None,
        redirect_uri: "aroeira://auth/callback".to_string(),
        google_auth_url: Some(format!("{}/auth", mock_server.uri())),
        google_token_url: Some(format!("{}/token", mock_server.uri())),
        google_userinfo_url: Some(format!("{}/userinfo", mock_server.uri())),
        github_auth_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    };

    let service = OAuthServiceImpl::new(config);

    // Mock Token Endpoint
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock-access-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&mock_server)
        .await;

    // Mock UserInfo Endpoint
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "google-user-123",
            "email": "test@example.com",
            "name": "Test User",
            "picture": "https://example.com/avatar.jpg",
            "email_verified": true
        })))
        .mount(&mock_server)
        .await;

    // Create valid session
    let session = OAuthPkceSession::new(
        "test-state".to_string(),
        "a".repeat(43),
        AuthProvider::Google,
    );

    // Execute exchange
    let user = service
        .exchange_code(&session, "auth-code".to_string())
        .await
        .expect("Should exchange code successfully");

    assert_eq!(user.provider, AuthProvider::Google);
    assert_eq!(user.provider_user_id, "google-user-123");
    assert_eq!(user.email, "test@example.com");
    assert!(user.email_verified);
}

#[tokio::test]
async fn exchange_code_success_github() {
    use domain::modules::auth::oauth::OAuthPkceSession;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Start mock server
    let mock_server = MockServer::start().await;

    // Config with mock URLs
    let config = OAuthConfig {
        google_client_id: None,
        github_client_id: Some("client-id".to_string()),
        github_client_secret: Some(secrecy::SecretString::from("client-secret".to_string())),
        redirect_uri: "aroeira://auth/callback".to_string(),
        google_auth_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_auth_url: Some(format!("{}/auth", mock_server.uri())),
        github_token_url: Some(format!("{}/token", mock_server.uri())),
        github_user_url: Some(format!("{}/user", mock_server.uri())),
        github_emails_url: Some(format!("{}/user/emails", mock_server.uri())),
    };

    let service = OAuthServiceImpl::new(config);

    // Mock Token Endpoint
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock-access-token",
            "token_type": "bearer",
            "scope": "read:user,user:email"
        })))
        .mount(&mock_server)
        .await;

    // Mock User Profile
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 12345,
            "login": "github-user",
            "name": "GitHub User",
            "avatar_url": "https://example.com/avatar.jpg"
        })))
        .mount(&mock_server)
        .await;

    // Mock User Emails
    Mock::given(method("GET"))
        .and(path("/user/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "email": "old@example.com",
                "primary": false,
                "verified": true,
                "visibility": "public"
            },
            {
                "email": "test@example.com",
                "primary": true,
                "verified": true,
                "visibility": "public"
            }
        ])))
        .mount(&mock_server)
        .await;

    // Create valid session
    let session = OAuthPkceSession::new(
        "test-state".to_string(),
        "a".repeat(43),
        AuthProvider::GitHub,
    );

    // Execute exchange
    let user = service
        .exchange_code(&session, "auth-code".to_string())
        .await
        .expect("Should exchange code successfully");

    assert_eq!(user.provider, AuthProvider::GitHub);
    assert_eq!(user.provider_user_id, "12345");
    assert_eq!(user.email, "test@example.com");
    assert!(user.email_verified);
}
