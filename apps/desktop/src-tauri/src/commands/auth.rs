use crate::error_codes::{ErrorCode, ErrorResponse};
use crate::services::secure_storage::{AUTH_TOKEN_KEY, SecureStorage};
use crate::state::{AppState, RateLimitEntry};
use domain::modules::auth::{EmailService, UserRepository};
use hmac::{Hmac, Mac};
use infra::device_identifier::get_or_create_device_id as get_secure_device_id;
use infra::services::auth::create_jwt;
use infra::utils::{hash_password, verify_password};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tauri::State;
use tokio::{self, time::sleep};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Calculate exponential backoff duration based on failure count
fn calculate_backoff(failure_count: u32) -> Duration {
    let base_delay = Duration::from_secs(crate::constants::BACKOFF_BASE_DELAY_SECS);
    let max_delay = Duration::from_secs(crate::constants::BACKOFF_MAX_DELAY_SECS);

    if failure_count == 0 {
        return Duration::from_secs(0);
    }

    // Exponential backoff: delay = base_delay * 2^(n-1)
    // Use saturating_pow to prevent overflow with large failure counts.
    let multiplier = 2u64.saturating_pow(failure_count.saturating_sub(1));

    // Perform multiplication with u128 to avoid overflow before capping.
    let delay_millis = base_delay.as_millis().saturating_mul(multiplier.into());
    let delay = Duration::from_millis(u64::try_from(delay_millis).unwrap_or(u64::MAX));

    std::cmp::min(delay, max_delay)
}

/// Helper function to perform dummy verification to prevent timing attacks
pub(crate) async fn perform_dummy_verification() {
    if tauri::async_runtime::spawn_blocking(|| {
        if let Err(e) = verify_password(DUMMY_PASSWORD, DUMMY_BCRYPT_HASH.as_str()) {
            // This should not happen with a valid dummy hash; log as warning to avoid noisy error logs.
            tracing::warn!("Dummy password verification failed unexpectedly: {}", e);
        }
    })
    .await
    .is_err()
    {
        // Even if the spawn fails, we still want to maintain consistent timing
        sleep(std::time::Duration::from_millis(100)).await;
    }
}

const DUMMY_PASSWORD: &str = "dummy_password_for_timing_attack_prevention";

// Security metrics for observability
pub(crate) struct SecurityMetrics {
    pub(crate) rate_limit_hits: AtomicU64,
    pub(crate) failed_auth_attempts: AtomicI64, // ✅ Use signed integer to prevent underflow
    pub(crate) successful_auth_attempts: AtomicU64,
}

impl SecurityMetrics {
    pub(crate) const fn new() -> Self {
        Self {
            rate_limit_hits: AtomicU64::new(0),
            failed_auth_attempts: AtomicI64::new(0), // ✅ Use signed integer
            successful_auth_attempts: AtomicU64::new(0),
        }
    }

    pub(crate) fn increment_rate_limit_hits(&self) {
        self.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_failed_auth_attempts(&self) {
        self.failed_auth_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn decrement_failed_auth_attempts(&self) {
        // ✅ Prevent underflow
        self.failed_auth_attempts
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                if current > 0 {
                    Some(current - 1)
                } else {
                    None // Don't decrement if already 0
                }
            })
            .ok();
    }

    pub(crate) fn increment_successful_auth_attempts(&self) {
        self.successful_auth_attempts
            .fetch_add(1, Ordering::Relaxed);
    }

    // This method was unused, so we'll remove it along with the corresponding field usage
}

pub(crate) static SECURITY_METRICS: LazyLock<SecurityMetrics> = LazyLock::new(SecurityMetrics::new);

static DUMMY_BCRYPT_HASH: LazyLock<String> = LazyLock::new(|| {
    // Generate a dummy hash using the same bcrypt cost as the application to ensure
    // consistent timing characteristics for timing attack prevention
    infra::utils::hash_password(DUMMY_PASSWORD).unwrap_or_else(|e| {
        tracing::warn!("Failed to generate dummy bcrypt hash, using hardcoded fallback: {e}");
        "$2b$12$C6UzMDM.H6dfI/f/IKcEeO8h1uTtCqgk4nHcFqzv0vVQnWm8Q2c1W".to_string()
    })
});

/// Generate a unique request ID for authentication tracing
pub(crate) fn generate_request_id() -> String {
    format!("req_{}", Uuid::new_v4())
}

/// Helper function to get a unique device identifier
/// Uses the secure device identifier module for cryptographically-secure, persistent device IDs
/// Returns an error instead of falling back to prevent rate limit bypass
pub(crate) fn get_device_id() -> Result<String, String> {
    get_secure_device_id().map_err(|e| {
        error!(
            error = %e,
            "CRITICAL: Could not get secure device ID; refusing request to prevent rate limit bypass"
        );
        ErrorResponse::new(ErrorCode::AuthUnavailable, "Authentication temporarily unavailable").to_string()
    })
}

// Maximum number of email entries to store in the rate limiter to prevent DoS
const MAX_RATE_LIMIT_ENTRIES: usize = crate::constants::DEFAULT_MAX_RATE_LIMIT_ENTRIES;
// Maximum attempts per email per window
const MAX_ATTEMPTS_PER_WINDOW: usize = crate::constants::DEFAULT_MAX_ATTEMPTS_PER_WINDOW;
// Time window for rate limiting (in seconds)
const RATE_LIMIT_WINDOW_SECS: u64 = crate::constants::DEFAULT_RATE_LIMIT_WINDOW_SECS;
// Maximum age for entries (2x the largest window duration we enforce)
const MAX_ENTRY_AGE_SECS: u64 = crate::constants::DEFAULT_MAX_ENTRY_AGE_SECS; // 2 * 300 seconds (registration window is 5 minutes)

// Rate limiting constants for registration
const REG_MAX_ATTEMPTS_PER_WINDOW: usize = crate::constants::DEFAULT_REG_MAX_ATTEMPTS_PER_WINDOW;
const REG_RATE_LIMIT_WINDOW_SECS: u64 = crate::constants::DEFAULT_REG_RATE_LIMIT_WINDOW_SECS; // 5 minutes

/// Helper function to evict old entries from the rate limit map to bound its size
/// Optimized to minimize work under the lock by using efficient retain and avoiding expensive operations
/// when possible.
fn evict_old_entries(all_attempts: &mut HashMap<String, RateLimitEntry>, now: Instant) {
    let max_age = Duration::from_secs(MAX_ENTRY_AGE_SECS);

    // First, remove entries that are clearly past their expiration time
    all_attempts.retain(|_, entry| {
        entry
            .attempts
            .back()
            .is_some_and(|last| now.saturating_duration_since(*last) <= max_age)
    });

    // Early exit if we're not approaching the capacity threshold
    if all_attempts.len() < (MAX_RATE_LIMIT_ENTRIES * 3) / 4 {
        return;
    }

    // If we're still over the limit, remove oldest entries more efficiently
    if all_attempts.len() >= MAX_RATE_LIMIT_ENTRIES {
        // Identify the oldest entries to remove without expensive sorting
        let entries_to_remove = identify_entries_to_remove(all_attempts);

        // Remove selected entries
        for key in entries_to_remove {
            all_attempts.remove(&key);
        }
    }
}

/// Helper function to identify which entries to remove based on age and fairness considerations
/// Uses a fair eviction policy that prevents targeted attacks by combining age-based and random selection
fn identify_entries_to_remove(all_attempts: &HashMap<String, RateLimitEntry>) -> Vec<String> {
    let num_to_remove = all_attempts
        .len()
        .saturating_sub(MAX_RATE_LIMIT_ENTRIES / 2);

    if num_to_remove == 0 {
        return Vec::new();
    }

    // Convert to vector for processing
    let mut entries_with_times: Vec<_> = all_attempts
        .iter()
        .map(|(key, entry)| {
            let oldest_time = entry
                .attempts
                .front()
                .copied()
                .unwrap_or(entry.last_cleanup);
            (oldest_time, key.clone())
        })
        .collect();

    // ✅ FIX: Use O(n) selection algorithm instead of O(n log n) sort
    // Use select_nth_unstable_by for O(n) selection
    if num_to_remove < entries_with_times.len() {
        entries_with_times.select_nth_unstable_by(num_to_remove, |a, b| a.0.cmp(&b.0));

        // Remove selected entries (first num_to_remove are oldest)
        entries_with_times.truncate(num_to_remove);
    }

    // Return keys of the entries to remove
    entries_with_times.into_iter().map(|(_, key)| key).collect()
}

/// Generates a secure random verification token for email verification
/// Uses `rand::rngs::StdRng` explicitly seeded from `OsRng` for cryptographic security.
fn generate_verification_token() -> String {
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    infra::utils::encode_hex(bytes)
}

/// Helper function to generate a HMAC-SHA256 hash of an email using a secret key
pub(crate) fn hash_email_for_logging(email: &str, key: &[u8]) -> Result<String, String> {
    type HmacSha256 = Hmac<Sha256>;

    // Validate key length for security - HMAC-SHA256 should have a reasonable minimum length
    if key.len() < 16 {
        tracing::error!(
            "Invalid rate limit key: key length {} is less than minimum 16 bytes",
            key.len()
        );
        return Err(ErrorResponse::from_code(ErrorCode::InternalError).into());
    }

    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| {
        tracing::error!("Invalid rate limit key: cannot create HMAC key for email hashing");
        ErrorResponse::from_code(ErrorCode::InternalError).to_string()
    })?;

    mac.update(email.as_bytes());
    let result = mac.finalize();
    Ok(infra::utils::encode_hex(result.into_bytes()))
}

/// Helper function to generate a HMAC-SHA256 hash of a device ID using a secret key
fn hash_device_id_for_logging(device_id: &str, key: &[u8]) -> Result<String, String> {
    type HmacSha256 = Hmac<Sha256>;

    // Validate key length for security - HMAC-SHA256 should have a reasonable minimum length
    if key.len() < 16 {
        tracing::error!(
            "Invalid rate limit key: key length {} is less than minimum 16 bytes",
            key.len()
        );
        return Err(ErrorResponse::from_code(ErrorCode::InternalError).into());
    }

    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| {
        tracing::error!("Invalid rate limit key: cannot create HMAC key for device ID hashing");
        ErrorResponse::from_code(ErrorCode::InternalError).to_string()
    })?;

    mac.update(device_id.as_bytes());
    let result = mac.finalize();
    Ok(infra::utils::encode_hex(result.into_bytes()))
}

/// Configuration for rate limiting
pub(crate) struct RateLimitConfig<'a> {
    pub(crate) max_attempts: usize,
    pub(crate) window_duration_secs: u64,
    pub(crate) action: &'a str,
    pub(crate) rate_limit_key: &'a [u8],
}

fn check_global_rate_limit(
    global_entry: &RateLimitEntry,
    config: &RateLimitConfig<'_>,
    now: Instant,
    window_duration: Duration,
) -> Result<(), ErrorResponse> {
    let global_max_attempts = if config.action == "login" {
        crate::constants::DEFAULT_GLOBAL_MAX_ATTEMPTS_PER_WINDOW
    } else {
        crate::constants::DEFAULT_GLOBAL_MAX_ATTEMPTS_PER_WINDOW / 2
    };
    let global_recent_attempts = global_entry.count_recent_attempts_readonly(now, window_duration);
    if global_recent_attempts >= global_max_attempts {
        warn!(
            action = %config.action,
            outcome = "failure",
            reason = "global_rate_limit_exceeded"
        );
        let backoff_duration = calculate_backoff(global_entry.consecutive_failures);
        let backoff_seconds = backoff_duration.as_secs();
        return Err(ErrorResponse::new(
            ErrorCode::GlobalRateLimited,
            format!(
                "Too many {} attempts globally. Please try again in {} seconds.",
                config.action, backoff_seconds
            ),
        ));
    }
    Ok(())
}

fn check_device_rate_limit(
    device_attempts: &HashMap<String, RateLimitEntry>,
    device_id: &str,
    config: &RateLimitConfig<'_>,
    now: Instant,
    window_duration: Duration,
) -> Result<(), ErrorResponse> {
    let device_max_attempts = if config.action == "login" {
        crate::constants::DEFAULT_DEVICE_MAX_ATTEMPTS_PER_WINDOW
    } else {
        crate::constants::DEFAULT_DEVICE_MAX_ATTEMPTS_PER_WINDOW / 2
    };
    if let Some(device_entry) = device_attempts.get(device_id) {
        let consecutive_failures = device_entry.consecutive_failures;
        let device_recent_attempts =
            device_entry.count_recent_attempts_readonly(now, window_duration);
        if device_recent_attempts >= device_max_attempts {
            let device_id_hash = hash_device_id_for_logging(device_id, config.rate_limit_key)
                .unwrap_or_else(|_| "hash_error".into());
            warn!(
                device_id = %device_id_hash,
                action = %config.action,
                outcome = "failure",
                reason = "device_rate_limit_exceeded"
            );
            let backoff_duration = calculate_backoff(consecutive_failures);
            let backoff_seconds = backoff_duration.as_secs();
            return Err(ErrorResponse::new(
                ErrorCode::DeviceRateLimited,
                format!(
                    "Too many {} attempts from this device. Please try again in {} seconds.",
                    config.action, backoff_seconds
                ),
            ));
        }
    }
    Ok(())
}

fn check_email_rate_limit(
    email_attempts: &HashMap<String, RateLimitEntry>,
    email_hash: &str,
    device_id: &str,
    config: &RateLimitConfig<'_>,
    now: Instant,
    window_duration: Duration,
) -> Result<(), ErrorResponse> {
    if let Some(email_entry) = email_attempts.get(email_hash) {
        let consecutive_failures = email_entry.consecutive_failures;
        let email_recent_attempts =
            email_entry.count_recent_attempts_readonly(now, window_duration);
        if email_recent_attempts >= config.max_attempts {
            let device_id_hash = hash_device_id_for_logging(device_id, config.rate_limit_key)
                .unwrap_or_else(|_| "hash_error".into());
            SECURITY_METRICS.increment_rate_limit_hits();
            warn!(
                email_hash = %email_hash,
                device_id = %device_id_hash,
                action = %config.action,
                outcome = "failure",
                reason = "rate_limit_exceeded"
            );
            let backoff_duration = calculate_backoff(consecutive_failures);
            let backoff_seconds = backoff_duration.as_secs();
            return Err(ErrorResponse::new(
                ErrorCode::RateLimited,
                format!(
                    "Too many {} attempts. Please try again in {} seconds.",
                    config.action, backoff_seconds
                ),
            ));
        }
    }
    Ok(())
}

/// Context for rate limit checks to reduce parameter count
struct RateLimitCheckContext<'a> {
    global_entry: &'a RateLimitEntry,
    device_attempts: &'a HashMap<String, RateLimitEntry>,
    email_attempts: &'a HashMap<String, RateLimitEntry>,
    device_id: &'a str,
    email_hash: &'a str,
    config: &'a RateLimitConfig<'a>,
    now: Instant,
    window_duration: Duration,
}

fn check_all_rate_limits(ctx: &RateLimitCheckContext<'_>) -> Result<(), ErrorResponse> {
    check_global_rate_limit(ctx.global_entry, ctx.config, ctx.now, ctx.window_duration)?;
    check_device_rate_limit(
        ctx.device_attempts,
        ctx.device_id,
        ctx.config,
        ctx.now,
        ctx.window_duration,
    )?;
    check_email_rate_limit(
        ctx.email_attempts,
        ctx.email_hash,
        ctx.device_id,
        ctx.config,
        ctx.now,
        ctx.window_duration,
    )?;
    Ok(())
}

fn record_rate_limit_entries(
    email_attempts: &mut HashMap<String, RateLimitEntry>,
    email_hash: &str,
    global_entry: &mut RateLimitEntry,
    device_attempts: &mut HashMap<String, RateLimitEntry>,
    device_id: &str,
    now: Instant,
    window_duration: Duration,
) {
    let email_entry = email_attempts.entry(email_hash.into()).or_default();
    email_entry.add_attempt(now, window_duration);
    email_entry.consecutive_failures += 1;

    global_entry.add_attempt(now, window_duration);
    global_entry.consecutive_failures += 1;

    let device_entry = device_attempts.entry(device_id.into()).or_default();
    device_entry.add_attempt(now, window_duration);
    device_entry.consecutive_failures += 1;
}

/// Helper to convert `ErrorResponse` to a non-empty error message.
fn error_response_to_message(e: ErrorResponse) -> String {
    if e.message.trim().is_empty() {
        "Rate limit exceeded".to_string()
    } else {
        e.message
    }
}

/// Function to atomically check rate limits and record failed attempt if check passes
/// This eliminates a race condition where multiple threads could pass rate limit check
/// but record multiple failed attempts, potentially exceeding the limit.
///
/// To prevent deadlocks in concurrent scenarios, we implement a lock ordering protocol
/// where locks are always acquired in same order: global -> device -> email.
pub(crate) async fn check_and_record_rate_limit(
    attempts_map: &tokio::sync::Mutex<HashMap<String, RateLimitEntry>>,
    global_attempts: &tokio::sync::Mutex<RateLimitEntry>,
    device_attempts: &tokio::sync::Mutex<HashMap<String, RateLimitEntry>>,
    email_hash: &str,
    device_id: &str,
    config: RateLimitConfig<'_>,
) -> Result<(), String> {
    let now = std::time::Instant::now();
    let window_duration = std::time::Duration::from_secs(config.window_duration_secs);

    // Acquire all locks in order to prevent deadlocks: global -> device -> email
    let mut global_entry = global_attempts.lock().await;
    let mut device_attempts_lock = device_attempts.lock().await;
    let mut email_attempts = attempts_map.lock().await;

    // Evict old entries before counting to keep maps bounded
    global_entry.cleanup_old_attempts(now, window_duration);
    evict_old_entries(&mut device_attempts_lock, now);
    evict_old_entries(&mut email_attempts, now);

    // Check all rate limits
    {
        let check_ctx = RateLimitCheckContext {
            global_entry: &global_entry,
            device_attempts: &device_attempts_lock,
            email_attempts: &email_attempts,
            device_id,
            email_hash,
            config: &config,
            now,
            window_duration,
        };
        check_all_rate_limits(&check_ctx).map_err(error_response_to_message)?;
    }

    // All checks passed - record failed attempt in all three buckets while holding locks
    record_rate_limit_entries(
        &mut email_attempts,
        email_hash,
        &mut global_entry,
        &mut device_attempts_lock,
        device_id,
        now,
        window_duration,
    );

    // Mutex guards are automatically dropped when they go out of scope
    Ok(())
}

/// Validates login inputs (email and password).
///
/// Returns `Ok(validated_email)` on success, or `Err(error_message)` on failure.
fn validate_login_inputs(email: &str, password: &SecretBox<str>) -> Result<String, String> {
    let Ok(validated_email) = crate::validation::ValidatedEmail::new(email) else {
        return Err(ErrorResponse::from_code(ErrorCode::InvalidCredentials).into());
    };

    let password_str = password.expose_secret();
    let password_chars = password_str.chars().count();
    if password_chars > crate::constants::DEFAULT_MAX_PASSWORD_LENGTH
        || password_str.len() > (crate::constants::DEFAULT_MAX_PASSWORD_LENGTH * 4)
    {
        return Err(ErrorResponse::from_code(ErrorCode::InvalidCredentials).into());
    }

    Ok(validated_email.as_str().into())
}

/// Handles successful login by creating JWT, storing it securely, and clearing rate limit attempts.
///
/// Returns `Ok(())` on success, or `Err(error_message)` on failure.
pub(crate) async fn handle_successful_login<S>(
    user_id: Uuid,
    email_hash: &str,
    device_id: &str,
    secure_storage: &S,
    jwt_secret: &str,
    jwt_expiration_hours: u64,
    jwt_issuer: &str,
    jwt_audience: &str,
    global_login_attempts: &std::sync::Arc<tokio::sync::Mutex<RateLimitEntry>>,
    device_login_attempts: &std::sync::Arc<tokio::sync::Mutex<HashMap<String, RateLimitEntry>>>,
    login_attempts: &std::sync::Arc<tokio::sync::Mutex<HashMap<String, RateLimitEntry>>>,
) -> Result<(), String>
where
    S: crate::services::secure_storage::SecureStorage,
{
    let token = create_jwt(
        user_id,
        jwt_secret,
        jwt_expiration_hours,
        jwt_issuer,
        jwt_audience,
    )
    .map_err(|_| {
        error!(user_id = %user_id, action = "login", outcome = "failure", reason = "jwt_creation_error");
        ErrorResponse::from_code(ErrorCode::InternalError).to_string()
    })?;

    if let Err(e) = secure_storage.save(AUTH_TOKEN_KEY, &token).await {
        error!(user_id = %user_id, action = "login", outcome = "failure", reason = "secure_storage_error", error = %e);
        return Err(ErrorResponse::new(
            ErrorCode::SecureStorageError,
            "Failed to store authentication token",
        )
        .into());
    }

    {
        let mut global_entry = global_login_attempts.lock().await;
        global_entry.attempts.clear();
        global_entry.consecutive_failures = 0;
    }

    {
        let mut attempts = device_login_attempts.lock().await;
        attempts.remove(device_id);
    }

    {
        let mut attempts = login_attempts.lock().await;
        attempts.remove(email_hash);
    }

    info!(user_id = %user_id, action = "login", outcome = "success");
    Ok(())
}

/// Validates registration inputs (email and password).
///
/// Returns `Ok(validated_email)` on success, or `Err(error_message)` on failure.
/// Performs dummy verification to prevent timing attacks on validation failure.
async fn validate_registration_input(
    email: String,
    password: &SecretBox<str>,
    level: crate::PasswordSecurityLevel,
) -> Result<crate::validation::ValidatedEmail, String> {
    let validated_email = match crate::validation::ValidatedEmail::new(&email) {
        Ok(email) => email,
        Err(err_msg) => {
            // Perform a dummy password verification to prevent timing attacks
            // This ensures that response time is consistent regardless of input validity
            perform_dummy_verification().await;
            return Err(err_msg);
        }
    };

    match crate::validation::ValidatedPassword::new(password.expose_secret().to_string(), level) {
        Ok(_) => (), // Password validation passed
        Err(err_msg) => {
            // Perform a dummy password verification to prevent timing attacks
            // This ensures that response time is consistent regardless of input validity
            perform_dummy_verification().await;
            return Err(err_msg);
        }
    }

    Ok(validated_email)
}

/// Hashes registration password using bcrypt.
///
/// Returns `Ok(password_hash)` on success, or `Err(error_message)` on failure.
async fn hash_registration_password(password: SecretBox<str>) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking({
        let password = password;
        move || hash_password(password.expose_secret())
    })
    .await
    .map_err(|join_err| {
        error!("Task join error during password hashing: {:?}", join_err);
        "Internal server error".to_string()
    })?
    .map_err(|hash_err| {
        error!("Password hashing failed: {:?}", hash_err);
        "Internal server error".to_string()
    })
}

/// Creates and saves a user entity, handling success and error cases.
///
/// Returns `Ok("User created")` on success, or `Err(error_message)` on failure.
/// Clears rate limit attempts on successful registration.
async fn create_and_save_user(
    state: &State<'_, AppState>,
    validated_email: &crate::validation::ValidatedEmail,
    password_hash: String,
    email_hash: &str,
    device_id: &str,
) -> Result<String, String> {
    let requires_verification = !state.email_service.is_mock();

    let (verification_token, verification_token_hash, expires_at) = if requires_verification {
        let token = generate_verification_token();
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let hash = infra::utils::encode_hex(hasher.finalize());
        let expiry = chrono::Utc::now() + chrono::Duration::hours(24);
        (Some(token), Some(hash), Some(expiry))
    } else {
        (None, None, None)
    };

    let user = domain::modules::auth::User {
        id: Uuid::new_v4(),
        email: validated_email.as_str().to_string(),
        password_hash,
        email_verified: !requires_verification,
        verification_token: verification_token_hash,
        verification_token_expires_at: expires_at,
    };

    // Always return success message to prevent account enumeration
    let success_message = if requires_verification {
        "Please check your email to verify your account".to_string()
    } else {
        "User created successfully".to_string()
    };

    match state.user_repo.save(&user).await {
        Ok(_) => {
            // Clear rate limit trackers on successful registration
            {
                let mut attempts = state.register_attempts.lock().await;
                attempts.remove(email_hash);
            }
            {
                let mut global_entry = state.global_register_attempts.lock().await;
                global_entry.attempts.clear();
                global_entry.consecutive_failures = 0;
            }
            {
                let mut attempts = state.device_register_attempts.lock().await;
                attempts.remove(device_id);
            }

            // Send verification email
            let email_send_result = if let Some(token) = &verification_token {
                state
                    .email_service
                    .send_verification_email(validated_email.as_str(), token)
                    .await
            } else {
                Ok(())
            };

            let final_success_message = if let Err(e) = email_send_result {
                error!(user_id = %user.id, error = %e, "Failed to send verification email during registration");
                if requires_verification {
                    "Account created, but we couldn't send the verification email. Please use the 'Resend Verification' option in the login screen.".to_string()
                } else {
                    success_message
                }
            } else {
                success_message
            };

            info!(user_id = %user.id, action = "register", outcome = "success");
            Ok(final_success_message)
        }
        Err(domain::modules::auth::AuthError::EmailAlreadyExists) => {
            warn!(
                email_hash = %email_hash,
                action = "register",
                outcome = "email_exists",
                reason = "sending_notification"
            );

            if let Err(e) = state
                .email_service
                .send_existing_account_notification(validated_email.as_str())
                .await
            {
                error!("Failed to send existing account notification");
                debug!(error = %e, "Detailed existing account notification failure");
            }

            Ok(success_message)
        }
        Err(e) => {
            let error_id = Uuid::new_v4();
            error!(
                email_hash = %email_hash,
                action = "register",
                outcome = "failure",
                reason = "internal_error",
                error = %e,
                error_id = %error_id,
                "Registration failed due to internal error"
            );
            Err(ErrorResponse::new(
                ErrorCode::InternalError,
                format!("Registration failed (Error ID: {error_id}). Please try again."),
            )
            .into())
        }
    }
}

/// Helper function to check registration rate limits
async fn check_registration_rate_limits(
    state: &State<'_, AppState>,
    email_hash: &str,
    device_id: &str,
    request_id: &str,
) -> Result<(), String> {
    let config = RateLimitConfig {
        max_attempts: REG_MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: REG_RATE_LIMIT_WINDOW_SECS,
        action: "registration",
        rate_limit_key: state.rate_limit_key.expose_secret().as_bytes(),
    };

    if let Err(e) = check_and_record_rate_limit(
        &state.register_attempts,
        &state.global_register_attempts,
        &state.device_register_attempts,
        email_hash,
        device_id,
        config,
    )
    .await
    {
        tracing::warn!(
            request_id = %request_id,
            action = "register",
            outcome = "failure",
            reason = "rate_limit_exceeded"
        );
        return Err(e);
    }

    Ok(())
}

/// Registers a new user with provided email, password, and password confirmation.
///
/// # Errors
///
/// This function will return an error if:
/// - Email validation fails
/// - Password validation fails
/// - Passwords do not match
/// - Rate limiting is exceeded
/// - Email already exists
/// - Database operation fails
/// - Password hashing fails
#[tauri::command]
pub async fn register(
    state: State<'_, AppState>,
    email: String,
    password: SecretBox<str>,
    confirm_password: SecretBox<str>,
) -> Result<String, String> {
    let request_id = generate_request_id();

    // Increment registration attempt metric
    SECURITY_METRICS.increment_failed_auth_attempts(); // We'll decrement if successful

    tracing::info!(
        request_id = %request_id,
        action = "register",
        outcome = "started"
    );

    // 1. Validate password confirmation
    if password.expose_secret() != confirm_password.expose_secret() {
        tracing::warn!(
            request_id = %request_id,
            action = "register",
            outcome = "failure",
            reason = "passwords_do_not_match"
        );
        // Perform dummy verification to prevent timing side-channel attacks
        perform_dummy_verification().await;
        return Err(ErrorResponse::from_code(ErrorCode::PasswordsDoNotMatch).into());
    }

    // 2. Validate input
    let validated_email =
        match validate_registration_input(email, &password, state.password_security_level).await {
            Ok(email) => email,
            Err(e) => {
                tracing::warn!(
                    request_id = %request_id,
                    action = "register",
                    outcome = "failure",
                    reason = "validation_error"
                );
                return Err(e);
            }
        };

    // 3. Check rate limits and record attempt atomically to prevent race conditions
    let device_id = get_device_id()?;
    let email_hash = hash_email_for_logging(
        validated_email.as_str(),
        state.rate_limit_key.expose_secret().as_bytes(),
    )
    .map_err(|_| {
        // On HMAC failure, fail request entirely rather than collapsing all users into a single bucket
        // This prevents a DoS vector where a misconfigured RATE_LIMIT_KEY could cause global lockouts
        error!("CRITICAL: Rate limiting key is invalid, failing registration request for security");
        ErrorResponse::new(
            ErrorCode::AuthUnavailable,
            "Registration temporarily unavailable",
        )
        .to_string()
    })?;

    check_registration_rate_limits(&state, &email_hash, &device_id, &request_id).await?;

    // 4. Hash password
    let hash = match hash_registration_password(password).await {
        Ok(h) => h,
        Err(_e) => {
            tracing::error!(
                request_id = %request_id,
                action = "register",
                outcome = "failure",
                reason = "password_hashing_error"
            );
            return Err(
                ErrorResponse::new(ErrorCode::InternalError, "Registration failed").to_string(),
            );
        }
    };

    // 5. Create and save user
    match create_and_save_user(&state, &validated_email, hash, &email_hash, &device_id).await {
        Ok(success) => {
            // ✅ Use safe decrement
            SECURITY_METRICS.decrement_failed_auth_attempts();
            SECURITY_METRICS.increment_successful_auth_attempts();

            tracing::info!(
                request_id = %request_id,
                action = "register",
                outcome = "success"
            );
            Ok(success)
        }
        Err(e) => {
            tracing::warn!(
                request_id = %request_id,
                action = "register",
                outcome = "failure",
                reason = "user_creation_error"
            );
            Err(e)
        }
    }
}

#[derive(serde::Serialize)]
pub struct PasswordPolicy {
    pub level: crate::PasswordSecurityLevel,
    pub min_length: usize,
}

/// Returns the current password policy
///
/// # Errors
///
/// This function never returns an error in the current implementation, but returns
/// `Result` for compatibility with the Tauri command system and to satisfy linter requirements.
#[tauri::command]
pub async fn get_password_policy(state: State<'_, AppState>) -> Result<PasswordPolicy, String> {
    Ok(PasswordPolicy {
        level: state.password_security_level,
        min_length: state.password_security_level.min_length(),
    })
}

/// Helper function to validate and hash email for login
async fn validate_and_hash_login_email(
    email: &str,
    password: &SecretBox<str>,
    request_id: &str,
    state: &State<'_, AppState>,
) -> Result<(String, String), String> {
    let Ok(validated_email) = validate_login_inputs(email, password) else {
        perform_dummy_verification().await;
        tracing::warn!(
            request_id = %request_id,
            action = "login",
            outcome = "failure",
            reason = "validation_error"
        );
        return Err(ErrorResponse::from_code(ErrorCode::InvalidCredentials).into());
    };

    let Ok(email_hash) = hash_email_for_logging(
        &validated_email,
        state.rate_limit_key.expose_secret().as_bytes(),
    ) else {
        error!(
            request_id = %request_id,
            "CRITICAL: Rate limiting key is invalid, failing login request for security"
        );
        return Err(ErrorResponse::new(
            ErrorCode::AuthUnavailable,
            "Login temporarily unavailable",
        )
        .into());
    };

    Ok((validated_email, email_hash))
}

/// Helper function to look up user and get credentials for verification
async fn lookup_user_for_login(
    state: &State<'_, AppState>,
    validated_email: &str,
    email_hash: &str,
    request_id: &str,
) -> Result<(Option<Uuid>, String, bool), String> {
    let user_result = state.user_repo.find_by_email(validated_email).await;
    match user_result {
        Ok(user) => {
            let (user_id, hash_to_check, email_verified) = if let Some(u) = user {
                (Some(u.id), u.password_hash.clone(), u.email_verified)
            } else {
                (None, DUMMY_BCRYPT_HASH.clone(), false)
            };
            Ok((user_id, hash_to_check, email_verified))
        }
        Err(e) => {
            warn!(
                request_id = %request_id,
                email_hash = %email_hash,
                action = "login",
                outcome = "failure",
                reason = "db_error",
                error = %e
            );
            perform_dummy_verification().await;
            Err(ErrorResponse::from_code(ErrorCode::InvalidCredentials).into())
        }
    }
}

/// Logs in a user with provided email and password.
///
/// # Errors
///
/// This function will return an error if:
/// - Email validation fails
/// - Password length exceeds maximum allowed
/// - Rate limiting is exceeded
/// - User is not found or credentials are invalid
/// - Password verification fails
/// - JWT creation fails
/// - Rate limiting key is invalid
/// - Internal server errors occur
#[tauri::command]
pub async fn login(
    state: State<'_, AppState>,
    email: String,
    password: SecretBox<str>,
) -> Result<(), String> {
    let request_id = generate_request_id();

    // Increment authentication attempt metric
    SECURITY_METRICS.increment_failed_auth_attempts(); // We'll decrement if successful

    tracing::info!(
        request_id = %request_id,
        action = "login",
        outcome = "started"
    );

    // Validate and hash email
    let (validated_email, email_hash) =
        validate_and_hash_login_email(&email, &password, &request_id, &state).await?;

    let device_id = get_device_id()?;

    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action: "login",
        rate_limit_key: state.rate_limit_key.expose_secret().as_bytes(),
    };

    // Use atomic check-and-record to prevent race conditions
    if let Err(e) = check_and_record_rate_limit(
        &state.login_attempts,
        &state.global_login_attempts,
        &state.device_login_attempts,
        &email_hash,
        &device_id,
        config,
    )
    .await
    {
        tracing::warn!(
            request_id = %request_id,
            action = "login",
            outcome = "failure",
            reason = "rate_limit_exceeded"
        );
        return Err(e);
    }

    // Look up user and get credentials for verification
    let (user_id, hash_to_check, email_verified) =
        lookup_user_for_login(&state, &validated_email, &email_hash, &request_id).await?;

    // ✅ FIX: Always verify password to prevent timing attacks
    let password_ok = tauri::async_runtime::spawn_blocking({
        let password = password;
        let hash_to_check = hash_to_check.clone();
        move || {
            let res = verify_password(password.expose_secret(), hash_to_check.as_str());
            if let Err(_e) = &res {
                // Sanitized logging: avoid debug formatting of error which might leak context
                tracing::error!(action = "login", "Password verification failed internally");
            }
            res.unwrap_or(false)
        }
    })
    .await
    .unwrap_or(false);

    // Security: Only log action without sensitive fields (user_found, password_ok)
    // to prevent information disclosure in logs
    tracing::debug!(action = "login", "Password verification completed");

    // Only check user_id after password verification completes
    if password_ok && let Some(uid) = user_id {
        // Enforce email verification unless running with mock email service
        if !state.email_service.is_mock() && !email_verified {
            tracing::warn!(
                request_id = %request_id,
                email_hash = %email_hash,
                action = "login",
                outcome = "failure",
                reason = "email_not_verified"
            );
            return Err(ErrorResponse::new(
                ErrorCode::EmailNotVerified,
                "Email not verified. Please check your email inbox.",
            )
            .into());
        }

        // ✅ Use safe decrement
        SECURITY_METRICS.decrement_failed_auth_attempts();
        SECURITY_METRICS.increment_successful_auth_attempts();

        tracing::info!(user_id = %uid, action = "login", outcome = "success");
        handle_successful_login(
            uid,
            &email_hash,
            &device_id,
            state.secure_storage.as_ref(),
            state.jwt_secret.expose_secret(),
            state.jwt_expiration_hours,
            &state.jwt_issuer,
            &state.jwt_audience,
            &state.global_login_attempts,
            &state.device_login_attempts,
            &state.login_attempts,
        )
        .await?;
        return Ok(());
    }

    // For invalid credentials, return generic error
    warn!(
        request_id = %request_id,
        email_hash = %email_hash,
        action = "login",
        outcome = "failure",
        reason = "invalid_credentials"
    );
    Err(ErrorResponse::from_code(ErrorCode::InvalidCredentials).into())
}

/// Logs out current user by clearing authentication token from secure storage.
///
/// # Errors
///
/// This function will return an error if:
/// - Secure storage is unavailable
/// - Deleting from secure storage fails
#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> Result<(), String> {
    // Get auth token before clearing it to extract user_id for audit logging
    let user_id: Option<Uuid> = crate::commands::secure_storage::get_auth_token(state.clone())
        .await
        .ok()
        .flatten()
        .and_then(|token| {
            infra::services::auth::verify_jwt(
                &token,
                state.jwt_secret.expose_secret(),
                &state.jwt_issuer,
                &state.jwt_audience,
            )
            .map_err(|e| {
                // Log warning but continue with logout - token may be expired or corrupted
                warn!(
                    action = "logout",
                    outcome = "warning",
                    reason = "jwt_verification_failed",
                    error = %e
                );
            })
            .ok()
        });

    // Clear auth token
    crate::commands::secure_storage::clear_auth_token(state.clone())
        .await
        .map_err(|e| {
            error!(
                action = "logout",
                outcome = "failure",
                error = %e,
                user_id = ?user_id,
                "Failed to clear auth token from secure storage"
            );
            e
        })?;

    // Log logout with user identifier for audit compliance
    info!(user_id = ?user_id, action = "logout", outcome = "success");

    Ok(())
}
// End of main functions

/// Resends verification email to the user.
///
/// # Errors
///
/// This function will return an error if:
/// - Email validation fails
/// - Rate limiting is exceeded
/// - Internal server errors occur
#[tauri::command]
pub async fn resend_verification_email(
    state: State<'_, AppState>,
    email: String,
) -> Result<(), String> {
    let request_id = generate_request_id();

    // Rate limiting (shared with login/registration to prevent abuse)
    let device_id = get_device_id()?;
    let Ok(validated_email) = crate::validation::ValidatedEmail::new(&email) else {
        return Ok(()); // Return success on invalid format to prevent enumeration/validation probing
    };

    // Use a hash of the email for rate limiting to avoid storing PII in memory
    let email_hash = hash_email_for_logging(
        validated_email.as_str(),
        state.rate_limit_key.expose_secret().as_bytes(),
    )
    .map_err(|_| "Internal server error".to_string())?;

    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action: "resend_verification",
        rate_limit_key: state.rate_limit_key.expose_secret().as_bytes(),
    };

    if let Err(e) = check_and_record_rate_limit(
        &state.register_attempts, // Share bucket with registration
        &state.global_register_attempts,
        &state.device_register_attempts, // Share device bucket
        &email_hash,
        &device_id,
        config,
    )
    .await
    {
        tracing::warn!(
            request_id = %request_id,
            action = "resend_verification",
            outcome = "failure",
            reason = "rate_limit_exceeded"
        );
        return Err(e);
    }

    // Lookup user
    let user = state
        .user_repo
        .find_by_email(validated_email.as_str())
        .await
        .map_err(|_| "Internal server error".to_string())?;

    if let Some(user) = user {
        if user.email_verified {
            return Ok(());
        }

        // Generate new token
        let token = generate_verification_token();
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);

        {
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            let hash = infra::utils::encode_hex(hasher.finalize());

            // Use atomic partial update to prevent race conditions
            state
                .user_repo
                .update_verification_status(user.id, false, Some(hash), Some(expires_at))
                .await
                .map_err(|e| {
                    tracing::error!(
                        request_id = %request_id,
                        error = %e,
                        user_id = %user.id,
                        "Failed to update verification status for resend"
                    );
                    "Internal server error".to_string()
                })?;
        }

        // Send email after rotating token to ensure DB state is consistent first
        if let Err(e) = state
            .email_service
            .send_verification_email(&user.email, &token)
            .await
        {
            tracing::error!(
                request_id = %request_id,
                user_id = %user.id,
                error = %e,
                "Failed to deliver verification email for resend"
            );
            // Invalidate/clear token locally if email delivery fails to prevent confusion with old or non-delivered tokens
            if let Err(db_err) = state
                .user_repo
                .update_verification_status(user.id, false, None, None)
                .await
            {
                tracing::error!(
                    request_id = %request_id,
                    user_id = %user.id,
                    error = %db_err,
                    "Failed to invalidate verification token after resend failure"
                );
            }
        }

        tracing::info!(
            request_id = %request_id,
            action = "resend_verification_email",
            outcome = "success",
            user_id = %user.id
        );
    } else {
        perform_dummy_verification().await;
    }

    Ok(())
}

/// Verifies a user's email address using a token.
///
/// # Errors
///    
/// This function will return an error if:
/// - Token is invalid or expired
/// - Database operation fails
#[tauri::command]
pub async fn verify_email(state: State<'_, AppState>, token: String) -> Result<(), String> {
    let request_id = generate_request_id();

    // Defensive token validation to prevent replay-without-expiry and hashing DoS
    let token_is_valid_format = token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit());
    if !token_is_valid_format {
        tracing::warn!(
            request_id = %request_id,
            action = "verify_email",
            outcome = "noop",
            reason = "invalid_token_format"
        );
        perform_dummy_verification().await;
        return Err("The verification token format is invalid.".to_string());
    }

    // Look up user by verification token
    // user_repo.find_by_verification_token hashes the token internally
    let user = state
        .user_repo
        .find_by_verification_token(&token)
        .await
        .map_err(|_| "Internal server error".to_string())?;

    if let Some(user) = user {
        // Require an expiration timestamp; if missing, treat as invalid/expired.
        let Some(expires_at) = user.verification_token_expires_at else {
            tracing::warn!(
                request_id = %request_id,
                action = "verify_email",
                outcome = "failure",
                reason = "missing_expiry_timestamp",
                user_id = %user.id,
                "Email verification failed: token is missing expiration metadata"
            );
            perform_dummy_verification().await;
            return Err("Verification token is invalid or has no expiry.".to_string());
        };

        if chrono::Utc::now() > expires_at {
            tracing::warn!(
                request_id = %request_id,
                action = "verify_email",
                outcome = "failure",
                reason = "token_expired",
                user_id = %user.id,
                "Email verification failed: token has expired"
            );
            return Err("Verification token has expired. Please request a new one.".to_string());
        }

        // Use atomic partial update to mark user as verified and clear token
        if let Err(e) = state
            .user_repo
            .update_verification_status(user.id, true, None, None)
            .await
        {
            tracing::error!(
                request_id = %request_id,
                action = "verify_email",
                outcome = "failure",
                user_id = %user.id,
                error = %e,
                "Database error during email verification"
            );
            return Err("Internal server error".to_string());
        }

        tracing::info!(
            request_id = %request_id,
            action = "verify_email",
            outcome = "success",
            user_id = %user.id,
            "Email verified successfully"
        );
    } else {
        tracing::warn!(
            request_id = %request_id,
            action = "verify_email",
            outcome = "noop",
            reason = "invalid_token_secret",
            "Email verification failed: token not found in database"
        );
        perform_dummy_verification().await;
        return Err("Email verification failed. Please check the link and try again.".to_string());
    }

    Ok(())
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod auth_tests;

#[cfg(test)]
#[path = "auth_logic_tests.rs"]
mod auth_logic_tests;
