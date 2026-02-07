use secrecy::SecretString;
use std::env;

pub struct Config {
    pub server_bind_address: String,
    pub github_client_id: String,
    pub github_client_secret: SecretString,
    pub github_token_url: String,
    pub allowed_origins: Vec<String>,
    pub rate_limit_requests: u32,
    pub rate_limit_window_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let server_bind_address =
            env::var("SERVER_BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

        let github_client_id = env::var("GITHUB_CLIENT_ID")
            .map_err(|_| config::ConfigError::NotFound("GITHUB_CLIENT_ID".into()))?;

        let github_client_secret = env::var("GITHUB_CLIENT_SECRET")
            .map_err(|_| config::ConfigError::NotFound("GITHUB_CLIENT_SECRET".into()))?;

        let github_token_url = env::var("GITHUB_TOKEN_URL")
            .unwrap_or_else(|_| "https://github.com/login/oauth/access_token".to_string());

        let allowed_origins = env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:1420,https://*.aroeira.app".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        let rate_limit_requests = env::var("RATE_LIMIT_REQUESTS")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .unwrap_or(5);

        let rate_limit_window_secs = env::var("RATE_LIMIT_WINDOW_SECS")
            .unwrap_or_else(|_| "60".to_string())
            .parse()
            .unwrap_or(60);

        Ok(Self {
            server_bind_address,
            github_client_id,
            github_client_secret: SecretString::new(github_client_secret.into()),
            github_token_url,
            allowed_origins,
            rate_limit_requests,
            rate_limit_window_secs,
        })
    }
}
