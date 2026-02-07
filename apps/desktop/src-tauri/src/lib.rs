use crate::state::AppState;
use domain::modules::auth::UserRepository;
use domain::modules::notes::NoteRepository;
use infra::database::establish_connection;
use infra::database::repositories::{note_repo::NoteRepositoryImpl, user_repo::UserRepositoryImpl};
use infra::security::{PathValidator, SecureFileCreator};
use secrecy::SecretBox;
use std::collections::HashMap;
use std::sync::Arc;
use tauri::{Emitter, Manager, Runtime};
use tracing::{error, info, warn};

pub mod auth_utils;
pub mod commands;
pub mod constants;
pub mod error_codes;
#[cfg(test)]
mod security_tests;
pub mod services;
pub mod state;
pub mod validation;

// Configuration struct to hold all application settings
#[derive(Clone)]
pub struct AppConfig {
    pub db_url: String,
    pub jwt_secret: String,
    pub password_min_length: usize,
    pub jwt_expiration_hours: u64,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub rate_limit_key: String,
    pub password_security_level: PasswordSecurityLevel,
    /// Google `OAuth2` client ID (optional)
    pub google_client_id: Option<String>,
    /// GitHub `OAuth2` client ID (optional)
    pub github_client_id: Option<String>,
    /// GitHub `OAuth2` client secret (required for token exchange)
    pub github_client_secret: Option<secrecy::SecretString>,
}

impl AppConfig {
    /// Creates a new `AppConfig` by reading values from environment variables
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - Required environment variables are not set
    /// - Environment variable values are invalid
    /// - Secrets don't meet security requirements
    pub fn from_env(app_handle: &tauri::AppHandle) -> Result<Self, Box<dyn std::error::Error>> {
        let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            if let Ok(mut path) = app_handle.path().app_local_data_dir() {
                if !path.exists()
                    && let Err(e) = std::fs::create_dir_all(&path) {
                    tracing::warn!("Failed to create app local data directory. Falling back to default. Error: {e}");
                    return crate::constants::DEFAULT_SQLITE_DB_URL.to_string();
                }
                path.push("Aroeira_local.db");
                if let Some(s) = path.to_str() {
                    use infra::database::SQLITE_PATH_ENCODE_SET;
                    use percent_encoding::utf8_percent_encode;
                    let encoded_path = utf8_percent_encode(s, SQLITE_PATH_ENCODE_SET).to_string();
                    return format!("sqlite:{encoded_path}?mode=rwc");
                }
            }
            crate::constants::DEFAULT_SQLITE_DB_URL.to_string()
        });

        let jwt_secret = get_or_create_secret_sync(app_handle, "jwt_secret", "JWT_SECRET")?;
        Self::validate_secret(&jwt_secret, "JWT_SECRET")?;

        let password_min_length =
            parse_env_var_with_default("PASSWORD_MIN_LENGTH", 8, str::parse::<usize>).clamp(8, 128);

        let jwt_expiration_hours =
            parse_env_var_with_default("JWT_EXPIRATION_HOURS", 24, str::parse::<u64>)
                .clamp(1, 24 * 365); // Clamp between 1 hour and 1 year

        let jwt_issuer = std::env::var("JWT_ISSUER").unwrap_or_else(|_| "Aroeira_app".to_string());
        let jwt_audience =
            std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "Aroeira_user".to_string());

        // Load rate limiting key from secure storage
        let rate_limit_key =
            get_or_create_secret_sync(app_handle, "rate_limit_key", "RATE_LIMIT_KEY")?;
        Self::validate_secret(&rate_limit_key, "RATE_LIMIT_KEY")?;

        // Load OAuth client IDs from environment (optional)
        let get_optional_env = |key: &str| -> Option<String> {
            std::env::var(key)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let google_client_id = get_optional_env("GOOGLE_CLIENT_ID");
        let mut github_client_id = get_optional_env("GITHUB_CLIENT_ID");
        let github_client_secret = get_optional_env("GITHUB_CLIENT_SECRET").map(Into::into);

        if google_client_id.is_none() && github_client_id.is_none() {
            info!(
                "No OAuth providers configured. Set GOOGLE_CLIENT_ID or GITHUB_CLIENT_ID to enable OAuth."
            );
        }

        // Log OAuth configuration status (without exposing secrets)
        // If GitHub client secret is missing, disable GitHub OAuth to prevent broken flows
        if github_client_id.is_some() && github_client_secret.is_some() {
            info!("GitHub OAuth configured with client secret");
        } else if github_client_id.is_some() {
            warn!(
                "GitHub OAuth client ID configured but GITHUB_CLIENT_SECRET is missing; disabling GitHub OAuth."
            );
            github_client_id = None;
        }

        Ok(Self {
            db_url,
            jwt_secret,
            password_min_length,
            jwt_expiration_hours,
            jwt_issuer,
            jwt_audience,
            rate_limit_key,
            password_security_level: parse_env_var_with_default(
                "PASSWORD_SECURITY_LEVEL",
                PasswordSecurityLevel::Secure,
                str::parse,
            ),
            google_client_id,
            github_client_id,
            github_client_secret,
        })
    }

    fn validate_secret(secret: &str, _name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if secret.is_empty() || secret.chars().any(char::is_whitespace) {
            error!("CRITICAL: Invalid secret configuration detected");
            return Err("Startup failed: Invalid secret configuration".into());
        }

        // Use byte length instead of char length for security validation
        // This ensures the secret meets the minimum byte requirement regardless of UTF-8 encoding
        if secret.len() < 32 {
            error!("CRITICAL: Secret does not meet minimum length requirements");
            return Err("Startup failed: Invalid secret configuration".into());
        }

        Ok(())
    }
}

/// Generates a cryptographically secure random secret of specified length
fn generate_secure_secret(length: usize) -> String {
    // Keep this whitespace-free to satisfy `validate_secret` and prevent startup failure.
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789)(*&^%$#@!~";

    use rand::RngCore;

    let mut rng = rand::rng();
    let mut out = String::with_capacity(length);

    // Rejection-sample to avoid modulo bias.
    while out.len() < length {
        let mut b = [0u8; 1];
        rng.fill_bytes(&mut b);
        let v = b[0] as usize;

        // Largest multiple of CHARSET.len() that fits in 0..=255
        let limit = (u8::MAX as usize + 1) / CHARSET.len() * CHARSET.len();
        if v < limit {
            out.push(CHARSET[v % CHARSET.len()] as char);
        }
    }

    out
}

/// Gets the storage path for a secret key
fn get_secret_storage_path<R: Runtime>(
    app_handle: &tauri::AppHandle<R>,
    key: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    if key.is_empty() || key.contains(['/', '\\']) || key.contains("..") {
        return Err("Invalid secret key name".into());
    }

    let mut storage_path = if let Ok(config_dir) = app_handle.path().app_config_dir() {
        config_dir
    } else if let Ok(data_dir) = app_handle.path().app_local_data_dir() {
        tracing::warn!(
            "app_config_dir unavailable; falling back to app_local_data_dir for secret storage"
        );
        data_dir
    } else {
        return Err("No suitable directory available for secret storage".into());
    };
    storage_path.push("secrets");
    storage_path.push(key);
    Ok(storage_path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PasswordSecurityLevel {
    None,
    Minimum,
    #[default]
    Secure,
    Strict,
    Paranoid,
}

impl std::str::FromStr for PasswordSecurityLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "minimum" => Ok(Self::Minimum),
            "secure" => Ok(Self::Secure),
            "strict" => Ok(Self::Strict),
            "paranoid" => Ok(Self::Paranoid),
            _ => Err(format!("Invalid password security level: {s}")),
        }
    }
}

impl PasswordSecurityLevel {
    /// Returns the minimum password length required for this security level
    #[must_use]
    pub const fn min_length(self) -> usize {
        match self {
            Self::None => 1,
            Self::Minimum | Self::Secure => 8,
            Self::Strict => 12,
            Self::Paranoid => 16,
        }
    }
}

/// Persists a secret from an environment variable to secure storage
fn persist_env_secret(storage_path: &std::path::Path, env_secret: &str, env_var_name: &str) {
    tracing::warn!(
        "Using {} from environment variable. This should be migrated to secure storage.",
        env_var_name
    );

    let env_secret = env_secret.trim();
    if env_secret.is_empty() {
        tracing::warn!(
            "Refusing to persist empty {} after trimming whitespace",
            env_var_name
        );
        return;
    }

    // Best-effort: persist for future runs so secrets don't unexpectedly rotate.
    // If persisting fails, still proceed using the env var.
    let _ = (|| -> Result<(), Box<dyn std::error::Error>> {
        // Validate path using PathValidator to prevent symlink attacks
        let validator = PathValidator::new();
        validator.validate(storage_path)?;

        // Use SecureFileCreator to write secret atomically
        let creator = SecureFileCreator::new();
        creator.write_string(storage_path, env_secret)?;

        Ok(())
    })();
}

/// Retrieves a secret from secure storage, generating and storing it if it doesn't exist (synchronous version)
fn get_or_create_secret_sync<R: Runtime>(
    app_handle: &tauri::AppHandle<R>,
    key: &str,
    env_var_name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let storage_path = get_secret_storage_path(app_handle, key)?;

    // Check if environment variable is set for migration purposes
    if let Ok(env_secret) = std::env::var(env_var_name) {
        let env_secret = env_secret.trim().to_string();
        if env_secret.is_empty() || env_secret.chars().any(char::is_whitespace) {
            return Err(format!("{env_var_name} is invalid (empty or contains whitespace)").into());
        }

        persist_env_secret(&storage_path, &env_secret, env_var_name);
        return Ok(env_secret);
    }

    // Validate path using PathValidator to prevent symlink attacks
    let validator = PathValidator::new();
    validator.validate(&storage_path)?;

    // Try to read existing secret from storage
    if storage_path.exists()
        && let Ok(stored_secret_bytes) = std::fs::read(&storage_path)
        && let Ok(stored_secret) = String::from_utf8(stored_secret_bytes)
    {
        let stored_secret = stored_secret.trim().to_string();

        // If the secret is empty or contains only whitespace, treat it as corrupted
        // and regenerate it instead of failing. This makes the system self-healing.
        if stored_secret.is_empty() || stored_secret.chars().any(char::is_whitespace) {
            tracing::warn!(
                secret_key = key,
                "Secret storage file contains invalid whitespace/empty secret. Regenerating...",
            );

            // Remove the corrupted file so we can regenerate it
            if let Err(e) = std::fs::remove_file(&storage_path) {
                tracing::error!(
                    secret_key = key,
                    error = %e,
                    "Failed to remove corrupted secret file"
                );
                // Return generic message - internal details are logged above
                return Err("Failed to process secret storage file".into());
            }

            // Fall through to generate a new secret below
        } else {
            // Secret is valid, self-heal common "newline at EOF" issues to avoid future startup failures.
            let config = infra::security::FileCreationConfig {
                fail_if_exists: false, // Allow overwriting the file.
                ..Default::default()
            };
            let creator = infra::security::SecureFileCreator::with_config(config);
            if let Err(e) = creator.write_string(&storage_path, &stored_secret) {
                tracing::warn!("Failed to self-heal secret file: {}", e);
            }

            return Ok(stored_secret);
        }
    }

    // If we couldn't read a valid secret but file already exists, fail hard instead of
    // attempting `create_new(true)` (which will error with AlreadyExists).
    if storage_path.exists() {
        return Err("Secret storage file exists but could not be read/decoded".into());
    }

    // Secret doesn't exist, generate a new one
    let new_secret = generate_secure_secret(32); // 32 bytes minimum

    // Use SecureFileCreator to write secret atomically
    let creator = SecureFileCreator::new();
    creator.write_string(&storage_path, &new_secret)?;

    Ok(new_secret)
}

// Helper function to parse environment variables with default values and warnings
fn parse_env_var_with_default<T, F, E>(var_name: &str, default_value: T, parser: F) -> T
where
    F: FnOnce(&str) -> std::result::Result<T, E>,
    E: std::fmt::Display,
{
    match std::env::var(var_name) {
        Ok(val) => match parser(&val) {
            Ok(parsed_val) => parsed_val,
            Err(e) => {
                tracing::warn!(
                    env_var = var_name,
                    error = %e,
                    "Invalid environment variable value. Using default."
                );
                default_value
            }
        },
        Err(_) => default_value,
    }
}

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {name}! You've been greeted from Rust!")
}

#[cfg(target_os = "linux")]
fn register_deep_links_for_linux(app: &mut tauri::App) {
    use tauri_plugin_deep_link::DeepLinkExt;
    match app.deep_link().register_all() {
        Ok(()) => tracing::info!("Deep links registered for Linux development"),
        Err(e) => tracing::warn!("Deep link registration failed: {}", e),
    }
}

#[cfg(not(target_os = "linux"))]
fn register_deep_links_for_linux(_app: &mut tauri::App) {}

async fn setup_app(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use migration::{Migrator, MigratorTrait};

    info!("Starting Aroeira Application setup...");

    let config = AppConfig::from_env(app.handle())?;

    let db = establish_connection(&config.db_url).await?;

    // Run database migrations
    // Fail fast on migration error to prevent inconsistent state.
    if let Err(e) = Migrator::up(&db, None).await {
        error!(
            error_message = %e.to_string(),
            "Database migration failed"
        );
        return Err(e.into());
    }

    // Wrap connection in Arc for sharing
    let db = Arc::new(db);

    let user_repo: Arc<dyn UserRepository + Send + Sync> =
        Arc::new(UserRepositoryImpl::new(db.clone()));
    let note_repo: Arc<dyn NoteRepository + Send + Sync> = Arc::new(NoteRepositoryImpl::new(db));
    let email_service: Arc<dyn domain::modules::auth::EmailService + Send + Sync> =
        if cfg!(debug_assertions) {
            info!("Using MockEmailService for development (verification disabled in mock mode)");
            Arc::new(infra::MockEmailService::new())
        } else {
            info!("Using SmtpEmailService for production");
            Arc::new(infra::SmtpEmailService::new())
        };

    let secure_storage = Arc::new(crate::services::secure_storage::TauriSecureStorage::new(
        app.handle().clone(),
    ));

    // Set up OAuth state first to consume config fields without cloning.
    // Use the deep-link scheme in both dev and release; opening the flow in the system browser
    // requires a custom-scheme callback (or an explicit loopback HTTP listener).
    let redirect_uri = crate::constants::OAUTH_REDIRECT_URI.to_string();
    let oauth_config = infra::services::oauth::OAuthConfig {
        google_client_id: config.google_client_id.clone(),
        github_client_id: config.github_client_id.clone(),
        github_client_secret: config.github_client_secret.clone(),
        redirect_uri,
        google_auth_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_auth_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    };
    app.manage(crate::commands::oauth::OAuthState::new(oauth_config));

    app.manage(AppState {
        user_repo,
        note_repo,
        email_service,
        secure_storage,
        jwt_secret: SecretBox::from(config.jwt_secret.into_boxed_str()),
        password_min_length: config.password_min_length,
        jwt_expiration_hours: config.jwt_expiration_hours,
        jwt_issuer: config.jwt_issuer,
        jwt_audience: config.jwt_audience,
        rate_limit_key: SecretBox::from(config.rate_limit_key.into_boxed_str()),
        login_attempts: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        register_attempts: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        global_login_attempts: Arc::new(tokio::sync::Mutex::new(
            crate::state::RateLimitEntry::new(),
        )),
        global_register_attempts: Arc::new(tokio::sync::Mutex::new(
            crate::state::RateLimitEntry::new(),
        )),
        device_login_attempts: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        device_register_attempts: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        password_security_level: config.password_security_level,
    });

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize tracing subscriber with structured JSON logging
    if let Err(e) = tracing_subscriber::fmt()
        .json()
        .with_ansi(false) // Disable ANSI colors for cleaner structured logs
        .try_init()
    {
        eprintln!("WARNING: tracing subscriber init failed: {e}");
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_secure_storage::init())
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            // Handle deep link when a second instance is launched
            if let Some(url) = argv.iter().find(|arg| arg.starts_with("aroeira://")) {
                // Defensive bounds to avoid forwarding huge/untrusted argv payloads
                if url.len() > 8192 {
                    tracing::warn!("Ignoring deep link argv: payload too large");
                    return;
                }

                // Strictly validate scheme/host/path to prevent prefix bypasses
                let Ok(parsed) = url::Url::parse(url) else {
                    tracing::warn!("Ignoring malformed deep link argv");
                    return;
                };

                let is_expected = parsed.scheme() == "aroeira"
                    && parsed.host_str() == Some("auth")
                    && parsed.path() == "/callback";

                if !is_expected {
                    tracing::warn!("Ignoring unexpected deep link argv");
                    return;
                }

                // Avoid logging full URL (may contain OAuth code/state)
                let redacted = match parsed.query() {
                    Some(_) => format!(
                        "{}://{}{}?<redacted>",
                        parsed.scheme(),
                        parsed.host_str().unwrap_or(""),
                        parsed.path()
                    ),
                    None => url.clone(),
                };
                tracing::info!(
                    "Received deep link in single-instance handler: {}",
                    redacted
                );
                if let Err(e) = app.emit("deep-link", url.clone()) {
                    tracing::warn!("Failed to emit deep-link event: {}", e);
                }
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .setup(|app| {
            register_deep_links_for_linux(app);

            // Use block_on to await async setup within the synchronous setup hook.
            // Added timeout to prevent indefinite blocking during startup.
            // This is acceptable in the setup phase since it happens once during app initialization
            // and the Tauri runtime is available. The setup should be relatively quick to avoid
            // blocking the event loop for extended periods.
            tauri::async_runtime::block_on(async {
                // Set a timeout for the setup operation to prevent indefinite blocking
                tokio::time::timeout(std::time::Duration::from_secs(30), setup_app(app))
                    .await
                    .map_or_else(
                        |_| {
                            error!("Application setup timed out after 30 seconds");
                            Err("Application setup timed out after 30 seconds".into())
                        },
                        |setup_result| {
                            setup_result.map_err(|e| {
                                error!("Application setup failed {}", e);
                                e
                            })
                        },
                    )
            })
        })
        .invoke_handler(tauri::generate_handler![
            greet,
            commands::auth::login,
            commands::auth::register,
            commands::auth::logout,
            commands::auth::verify_email,
            commands::auth::resend_verification_email,
            commands::auth::get_password_policy,
            commands::notes::get_notes,
            commands::notes::create_note,
            commands::notes::update_note,
            commands::notes::delete_note,
            commands::secure_storage::has_auth_token,
            commands::secure_storage::get_user_id_from_token,
            commands::oauth::start_oauth_flow,
            commands::oauth::handle_oauth_callback,
            commands::oauth::get_oauth_availability,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            error!(
                "Failed to initialize application. Please check logs for details. Error: {}",
                e
            );
            std::process::exit(1);
        });
}
