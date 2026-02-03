use domain::modules::auth::{EmailService, UserRepository};
use domain::modules::notes::NoteRepository;
use secrecy::SecretBox;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// Define RateLimitEntry struct here since it's used in state
const MAX_STORED_ATTEMPTS: usize = 100;

pub struct RateLimitEntry {
    pub attempts: std::collections::VecDeque<Instant>,
    pub last_cleanup: Instant,
    pub consecutive_failures: u32, // Track consecutive failures for exponential backoff
}

impl RateLimitEntry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            attempts: std::collections::VecDeque::new(),
            last_cleanup: Instant::now(),
            consecutive_failures: 0,
        }
    }

    /// Add a new attempt and clean up old attempts
    pub fn add_attempt(&mut self, now: Instant, window_duration: Duration) {
        // Clean up old attempts before adding new one
        self.cleanup_old_attempts(now, window_duration);

        // Add the new attempt
        self.attempts.push_back(now);
        self.last_cleanup = now;
    }

    /// Count attempts within current window (with cleanup)
    pub fn count_recent_attempts(&mut self, now: Instant, window_duration: Duration) -> usize {
        self.cleanup_old_attempts(now, window_duration);
        self.attempts.len()
    }

    /// Count attempts within current window (read-only, no cleanup)
    #[must_use]
    pub fn count_recent_attempts_readonly(&self, now: Instant, window_duration: Duration) -> usize {
        self.attempts
            .iter()
            .filter(|&&attempt| now.saturating_duration_since(attempt) <= window_duration)
            .count()
    }

    /// Get a clone of attempts for read-only operations
    #[must_use]
    pub fn get_attempts_clone(&self) -> std::collections::VecDeque<Instant> {
        self.attempts.clone()
    }

    /// Remove attempts that are outside time window
    pub fn cleanup_old_attempts(&mut self, now: Instant, window_duration: Duration) {
        // Always remove attempts that are outside the time window to prevent unbounded growth
        while let Some(first_attempt) = self.attempts.front() {
            if now.saturating_duration_since(*first_attempt) > window_duration {
                self.attempts.pop_front();
            } else {
                // Since VecDeque is ordered by time, remaining attempts are all within the window
                break;
            }
        }

        // Additionally, enforce a hard cap on the number of attempts stored to prevent
        // DoS via excessive memory usage in case of extremely high frequency attempts
        // Reasonable upper bound
        while self.attempts.len() > MAX_STORED_ATTEMPTS {
            self.attempts.pop_front(); // Remove oldest attempts first
        }

        // Track recent activity for eviction/aging logic.
        self.last_cleanup = now;
    }
}

impl Default for RateLimitEntry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AppState {
    pub user_repo: Arc<dyn UserRepository>,
    pub note_repo: Arc<dyn NoteRepository>,
    pub email_service: Arc<dyn EmailService>,
    pub secure_storage: Arc<dyn crate::services::secure_storage::SecureStorage>,
    pub jwt_secret: SecretBox<str>,
    pub password_min_length: usize,
    pub jwt_expiration_hours: u64,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub rate_limit_key: SecretBox<str>,
    pub login_attempts: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
    pub register_attempts: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
    // Global rate limiters (across all users)
    pub global_login_attempts: Arc<Mutex<RateLimitEntry>>,
    pub global_register_attempts: Arc<Mutex<RateLimitEntry>>,
    // Device-level rate limiters (per device)
    pub device_login_attempts: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
    pub device_register_attempts: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
    pub password_security_level: crate::PasswordSecurityLevel,
}
