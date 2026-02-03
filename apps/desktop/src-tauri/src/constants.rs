/// Constants for rate limiting
pub const DEFAULT_MAX_RATE_LIMIT_ENTRIES: usize = 1000;
pub const DEFAULT_MAX_ATTEMPTS_PER_WINDOW: usize = 5;
pub const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 60;
pub const DEFAULT_MAX_ENTRY_AGE_SECS: u64 = 600; // 2 * 300 seconds (registration window is 5 minutes)
pub const DEFAULT_REG_MAX_ATTEMPTS_PER_WINDOW: usize = 3;
pub const DEFAULT_REG_RATE_LIMIT_WINDOW_SECS: u64 = 300; // 5 minutes

// Global and device rate limiting constants
pub const DEFAULT_GLOBAL_MAX_ATTEMPTS_PER_WINDOW: usize = 100;
pub const DEFAULT_DEVICE_MAX_ATTEMPTS_PER_WINDOW: usize = 20;

// Exponential backoff constants
pub const BACKOFF_BASE_DELAY_SECS: u64 = 1; // Base delay of 1 second
pub const BACKOFF_MAX_DELAY_SECS: u64 = 300; // Maximum delay of 5 minutes

/// Constants for input validation
pub const DEFAULT_MAX_EMAIL_LENGTH: usize = 320;
pub const DEFAULT_MAX_PASSWORD_LENGTH: usize = 128;

/// Constants for note validation
pub const MAX_NOTE_TITLE_LENGTH: usize = 100;
pub const MAX_NOTE_CONTENT_LENGTH: usize = 10000;
pub const MAX_NOTE_TITLE_BYTES: usize = 500;
pub const MAX_NOTE_CONTENT_BYTES: usize = 50000;

/// Default database URL - uses a more secure path in the app's data directory
pub const DEFAULT_SQLITE_DB_URL: &str = "sqlite:data/Aroeira_local.db?mode=rwc";
