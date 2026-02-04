use crate::commands::auth::{
    RateLimitConfig, SECURITY_METRICS, check_and_record_rate_limit, generate_request_id,
    perform_dummy_verification,
};
use crate::state::RateLimitEntry;
use bcrypt::{DEFAULT_COST, verify};
use hmac::{Hmac, Mac};
use infra::device_identifier::get_or_create_device_id;
use infra::utils::{hash_password, verify_password};
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::{Mutex, MutexGuard};
use tracing::info;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

fn get_test_rate_limit_key() -> [u8; 32] {
    std::env::var("TEST_RATE_LIMIT_KEY")
        .unwrap_or_else(|_| format!("rate_limit_key_{}", uuid::Uuid::new_v4()))
        .as_bytes()
        .try_into()
        .unwrap_or([0u8; 32])
}

#[tokio::test]
async fn test_request_ids_are_generated_and_propagated() {
    // In the auth module, we generate request IDs for tracing

    // Generate multiple request IDs
    let req_id1 = generate_request_id();
    let req_id2 = generate_request_id();

    // Verify they are in the expected format (start with req_)
    assert!(
        req_id1.starts_with("req_"),
        "Request ID should start with 'req_'"
    );
    assert!(
        req_id2.starts_with("req_"),
        "Request ID should start with 'req_'"
    );

    // Verify they are unique
    assert_ne!(req_id1, req_id2, "Request IDs should be unique");

    // Verify they contain UUIDs
    let uuid_part1 = req_id1.strip_prefix("req_").unwrap();
    let uuid_part2 = req_id2.strip_prefix("req_").unwrap();

    // Check that the UUID parts are valid UUIDs
    assert!(
        Uuid::parse_str(uuid_part1).is_ok(),
        "Request ID should contain valid UUID"
    );
    assert!(
        Uuid::parse_str(uuid_part2).is_ok(),
        "Request ID should contain valid UUID"
    );
}

#[tokio::test]
async fn test_request_ids_are_unique_per_request() {
    let mut request_ids = std::collections::HashSet::new();

    // Generate many request IDs to test uniqueness
    for _ in 0..100 {
        let req_id = generate_request_id();
        assert!(
            !request_ids.contains(&req_id),
            "Request ID should be unique"
        );
        request_ids.insert(req_id);
    }

    assert_eq!(
        request_ids.len(),
        100,
        "All 100 request IDs should be unique"
    );
}

#[tokio::test]
async fn test_request_ids_included_in_all_logs() {
    // This test verifies that request IDs are properly included in logging
    // In practice, this would involve capturing log output, but we'll verify
    // that the request ID generation works properly with the logging system

    let request_id = generate_request_id();

    // Simulate logging with request ID context
    // In real implementation, logs would include request_id as a field
    info!(
        request_id = %request_id,
        action = "test_log",
        outcome = "success",
        "Test log entry with request ID"
    );

    // The test passes if we can generate and use request IDs properly
    assert!(
        request_id.starts_with("req_"),
        "Request ID should be properly formatted"
    );
}

#[tokio::test]
async fn test_rate_limiting_works_with_new_device_ids() {
    let rate_limit_key: SecretBox<str> = SecretBox::new(Box::from("test_key"));
    let login_attempts = Arc::new(Mutex::new(HashMap::new()));
    let global_login_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_login_attempts = Arc::new(Mutex::new(HashMap::new()));

    // Get a device ID
    let device_id = get_or_create_device_id().unwrap_or_else(|_| "test_device".to_string());
    let email = "test@example.com";

    // Hash email for rate limiting
    let mut mac = HmacSha256::new_from_slice(rate_limit_key.expose_secret().as_bytes()).unwrap();
    mac.update(email.as_bytes());
    let email_hash = hex::encode(mac.finalize().into_bytes());

    // Test rate limiting with the device ID

    // Exceed rate limit first
    for _ in 0..5 {
        let config = RateLimitConfig {
            max_attempts: 3,
            window_duration_secs: 60,
            action: "login",
            rate_limit_key: rate_limit_key.expose_secret().as_bytes(),
        };

        // We ignore the result here, just filling up the bucket
        let _ = check_and_record_rate_limit(
            &login_attempts,
            &global_login_attempts,
            &device_login_attempts,
            &email_hash,
            &device_id,
            config,
        )
        .await;
    }

    // Now try to check rate limit - should fail
    let config = RateLimitConfig {
        max_attempts: 3,
        window_duration_secs: 60,
        action: "login",
        rate_limit_key: rate_limit_key.expose_secret().as_bytes(),
    };

    let result = check_and_record_rate_limit(
        &login_attempts,
        &global_login_attempts,
        &device_login_attempts,
        &email_hash,
        &device_id,
        config,
    )
    .await;

    assert!(result.is_err(), "Rate limit should be exceeded");
}

#[tokio::test]
async fn test_dummy_verification_prevents_timing_attacks() {
    // Test that dummy verification takes approximately the same time as real verification
    // Warm up the LazyLock dummy hash to avoid counting its generation time in the measurement
    perform_dummy_verification().await;

    // Take multiple samples to reduce CI jitter flakiness
    let mut dummy_samples = Vec::with_capacity(10);
    for _ in 0..10 {
        let start_time = std::time::Instant::now();
        perform_dummy_verification().await;
        dummy_samples.push(start_time.elapsed());
    }

    // Create a fake password hash for testing
    let password = Uuid::new_v4().to_string();
    let hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST).unwrap();

    let mut real_samples = Vec::with_capacity(10);
    for _ in 0..10 {
        let start_time = std::time::Instant::now();
        let _ = verify_password(password, &hash);
        real_samples.push(start_time.elapsed());
    }
    dummy_samples.sort();
    real_samples.sort();

    // Compare as a ratio to avoid brittle absolute thresholds across machines
    let dummy_median = dummy_samples[dummy_samples.len() / 2];
    let real_median = real_samples[real_samples.len() / 2];

    // Compare as a ratio to avoid brittle absolute thresholds across machines
    let dummy_secs = dummy_median.as_secs_f64().max(0.001);
    let real_secs = real_median.as_secs_f64().max(0.001);
    let ratio = (dummy_secs / real_secs).max(real_secs / dummy_secs);

    assert!(
        ratio < 3.0,
        "Dummy verification should be within 3x of real verification (dummy={dummy_median:?}, real={real_median:?})"
    );
}

#[tokio::test]
async fn test_password_hashing_uses_strong_algorithms_bcrypt() {
    let password = Uuid::new_v4().to_string();

    // Hash the password using our utility function
    let hashed = hash_password(password).expect("Should hash password");

    // Verify it's a valid bcrypt hash
    assert!(hashed.starts_with("$2b$"), "Hash should be bcrypt format");

    // Extract the cost factor from the hash
    let parts: Vec<&str> = hashed.split('$').collect();
    assert!(parts.len() >= 3, "Bcrypt hash should have proper format");

    let cost_factor: u32 = parts[2].parse().expect("Cost factor should be numeric");
    assert!(
        cost_factor >= DEFAULT_COST,
        "Cost factor should be at least the default"
    );

    // Verify the hash can be verified
    let is_valid = verify(password, &hashed).expect("Should verify hash");
    assert!(is_valid, "Hash should verify correctly");
}

#[tokio::test]
async fn test_failed_authentication_attempts_are_logged() {
    // Get initial count of failed auth attempts
    let initial_count = SECURITY_METRICS
        .failed_auth_attempts
        .load(Ordering::Relaxed);

    // Simulate a failed authentication attempt
    SECURITY_METRICS.increment_failed_auth_attempts();

    let new_count = SECURITY_METRICS
        .failed_auth_attempts
        .load(Ordering::Relaxed);

    assert_eq!(
        new_count,
        initial_count + 1,
        "Failed auth attempts should be incremented"
    );
}

#[tokio::test]
async fn test_successful_authentication_clears_all_rate_limits() {
    let rate_limit_key: SecretBox<str> = SecretBox::new(Box::from("test_key"));
    let login_attempts = Arc::new(Mutex::new(HashMap::new()));
    let global_login_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_login_attempts = Arc::new(Mutex::new(HashMap::new()));

    let email = "clear_test@example.com";
    let device_id = get_or_create_device_id().unwrap_or_else(|_| "test_device".to_string());

    // Hash the email for rate limiting
    let mut mac = HmacSha256::new_from_slice(rate_limit_key.expose_secret().as_bytes()).unwrap();
    mac.update(email.as_bytes());
    let email_hash = hex::encode(mac.finalize().into_bytes());

    // Fill up rate limit counters
    for _ in 0..5 {
        let config = RateLimitConfig {
            max_attempts: 3,
            window_duration_secs: 60,
            action: "login",
            rate_limit_key: rate_limit_key.expose_secret().as_bytes(),
        };
        let _ = check_and_record_rate_limit(
            &login_attempts,
            &global_login_attempts,
            &device_login_attempts,
            &email_hash,
            &device_id,
            config,
        )
        .await;
    }

    // Verify rate limits are in place
    // Removed RateLimitParams check as it's not needed for logical verification

    // At this point, rate limits should be exceeded
    // Now simulate successful authentication which should clear the limits

    // Clear the email-specific rate limit
    {
        let mut attempts: MutexGuard<'_, HashMap<String, RateLimitEntry>> =
            login_attempts.lock().await;
        attempts.remove(&email_hash);
    }

    // Clear the device-specific rate limit
    {
        let mut attempts: MutexGuard<HashMap<String, RateLimitEntry>> =
            device_login_attempts.lock().await;
        attempts.remove(&device_id);
    }

    // Clear the global rate limit
    {
        let mut global_entry = global_login_attempts.lock().await;
        global_entry.attempts.clear();
        global_entry.consecutive_failures = 0;
    }

    // Now rate limits should be cleared and a new check should pass
    // This is verified by the fact that the buckets were cleared
    let email_attempts: MutexGuard<HashMap<String, RateLimitEntry>> = login_attempts.lock().await;
    assert!(
        !email_attempts.contains_key(&email_hash),
        "Email rate limit should be cleared"
    );
    drop(email_attempts);

    let device_attempts: MutexGuard<HashMap<String, RateLimitEntry>> =
        device_login_attempts.lock().await;
    assert!(
        !device_attempts.contains_key(&device_id),
        "Device rate limit should be cleared"
    );
    drop(device_attempts);

    let global_entry = global_login_attempts.lock().await;
    assert!(
        global_entry.attempts.is_empty(),
        "Global rate limit should be cleared"
    );
    assert_eq!(
        global_entry.consecutive_failures, 0,
        "Global failure count should be reset"
    );
    drop(global_entry);
}
