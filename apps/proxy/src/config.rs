use secrecy::SecretString;
use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub server_bind_address: String,
    pub github_client_id: String,
    pub github_client_secret: SecretString,
    pub github_token_url: String,
    pub github_allowed_hosts: Vec<String>,
    pub github_redirect_uri: String,
    pub allowed_origins: Vec<String>,
    pub rate_limit_requests: u32,
    pub rate_limit_window_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let server_bind_address =
            env::var("SERVER_BIND_ADDRESS").unwrap_or_else(|_err| "0.0.0.0:3000".to_owned());

        let github_client_id = env::var("GITHUB_CLIENT_ID")
            .map_err(|_err| "GITHUB_CLIENT_ID environment variable is not set.")?;

        let github_client_secret = env::var("GITHUB_CLIENT_SECRET")
            .map_err(|_err| "GITHUB_CLIENT_SECRET environment variable is not set.")?;

        let github_token_url = env::var("GITHUB_TOKEN_URL")
            .unwrap_or_else(|_err| "https://github.com/login/oauth/access_token".to_owned());

        let github_allowed_hosts = env::var("GITHUB_ALLOWED_HOSTS")
            .map_err(|_err| "GITHUB_ALLOWED_HOSTS environment variable is not set.")?
            .split(',')
            .map(|host| host.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect::<Vec<_>>();

        if github_allowed_hosts.is_empty() {
            return Err("GITHUB_ALLOWED_HOSTS must not be empty.".into());
        }

        let github_redirect_uri = env::var("GITHUB_REDIRECT_URI")
            .map_err(|_err| "GITHUB_REDIRECT_URI environment variable is not set.")?;

        let allowed_origins = env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_err| "http://localhost:1420,https://*.aroeira.app".to_owned())
            .split(',')
            .map(|origin| origin.trim().to_owned())
            .collect();

        let rate_limit_requests = env::var("RATE_LIMIT_REQUESTS")
            .unwrap_or_else(|_err| "5".to_owned())
            .parse()
            .unwrap_or(5);

        let rate_limit_window_secs = env::var("RATE_LIMIT_WINDOW_SECS")
            .unwrap_or_else(|_err| "60".to_owned())
            .parse()
            .unwrap_or(60);

        Ok(Self {
            server_bind_address,
            github_client_id,
            github_client_secret: SecretString::new(github_client_secret.into()),
            github_token_url,
            github_allowed_hosts,
            github_redirect_uri,
            allowed_origins,
            rate_limit_requests,
            rate_limit_window_secs,
        })
    }
}
