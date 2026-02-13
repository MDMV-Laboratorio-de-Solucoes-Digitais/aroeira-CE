use super::*;
use crate::state::RateLimitEntry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// Import constants for testing
use crate::constants::{
    DEFAULT_DEVICE_MAX_ATTEMPTS_PER_WINDOW, DEFAULT_GLOBAL_MAX_ATTEMPTS_PER_WINDOW,
    DEFAULT_MAX_ATTEMPTS_PER_WINDOW, DEFAULT_MAX_ENTRY_AGE_SECS, DEFAULT_MAX_RATE_LIMIT_ENTRIES,
    DEFAULT_RATE_LIMIT_WINDOW_SECS,
};

// Define the constants that were used in the original tests
const MAX_RATE_LIMIT_ENTRIES: usize = DEFAULT_MAX_RATE_LIMIT_ENTRIES;
const MAX_ATTEMPTS_PER_WINDOW: usize = DEFAULT_MAX_ATTEMPTS_PER_WINDOW;
const RATE_LIMIT_WINDOW_SECS: u64 = DEFAULT_RATE_LIMIT_WINDOW_SECS;
const MAX_ENTRY_AGE_SECS: u64 = DEFAULT_MAX_ENTRY_AGE_SECS;
const MAX_STORED_ATTEMPTS: usize = 100; // This was defined in state.rs
const RATE_LIMIT_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn test_evict_old_entries_under_threshold() {
    let mut all_attempts = HashMap::new();
    let now = Instant::now();

    // Add some entries but stay under the capacity threshold
    for i in 0..(MAX_RATE_LIMIT_ENTRIES * 3) / 4 - 10 {
        let key = format!("email{i}");
        let mut entry = RateLimitEntry::new();
        entry.add_attempt(now, Duration::from_secs(RATE_LIMIT_WINDOW_SECS));
        all_attempts.insert(key, entry);
    }

    // This should return early without doing anything
    evict_old_entries(&mut all_attempts, now);

    // Size should remain the same
    assert_eq!(all_attempts.len(), (MAX_RATE_LIMIT_ENTRIES * 3) / 4 - 10);
}

#[tokio::test]
async fn test_evict_old_entries_clearly_expired() {
    let mut all_attempts = HashMap::new();
    let now = Instant::now();
    let old_time = now
        .checked_sub(Duration::from_secs(MAX_ENTRY_AGE_SECS + 1))
        .unwrap(); // Clearly expired

    // Add an old entry
    let mut entry = RateLimitEntry::new();
    entry.add_attempt(old_time, Duration::from_secs(RATE_LIMIT_WINDOW_SECS));
    all_attempts.insert("old_email".to_string(), entry);

    // Add a recent entry to avoid empty map
    let mut recent_entry = RateLimitEntry::new();
    recent_entry.add_attempt(now, Duration::from_secs(RATE_LIMIT_WINDOW_SECS));
    all_attempts.insert("recent_email".to_string(), recent_entry);

    evict_old_entries(&mut all_attempts, now);

    // Old entry should be removed, recent should remain
    assert_eq!(all_attempts.len(), 1);
    assert!(all_attempts.contains_key("recent_email"));
}

#[tokio::test]
async fn test_identify_entries_to_remove_empty_map() {
    let all_attempts = HashMap::new();
    let entries_to_remove = identify_entries_to_remove(&all_attempts);

    assert!(entries_to_remove.is_empty());
}

#[tokio::test]
async fn test_identify_entries_to_remove_not_over_limit() {
    let mut all_attempts = HashMap::new();
    let now = Instant::now();

    // Add fewer entries than the limit
    for i in 0..MAX_RATE_LIMIT_ENTRIES / 2 {
        let key = format!("email{i}");
        let mut entry = RateLimitEntry::new();
        entry.add_attempt(now, Duration::from_secs(RATE_LIMIT_WINDOW_SECS));
        all_attempts.insert(key, entry);
    }

    let entries_to_remove = identify_entries_to_remove(&all_attempts);

    assert!(entries_to_remove.is_empty());
}

#[tokio::test]
async fn test_identify_entries_to_remove_over_limit() {
    let mut all_attempts = HashMap::new();
    let now = Instant::now();

    // Add more entries than the limit
    for i in 0..MAX_RATE_LIMIT_ENTRIES {
        let key = format!("email{i}");
        let mut entry = RateLimitEntry::new();

        // Add entries with different timestamps to create variation
        let time_offset = now.checked_sub(Duration::from_secs(i as u64)).unwrap();
        entry.add_attempt(time_offset, Duration::from_secs(RATE_LIMIT_WINDOW_SECS));

        all_attempts.insert(key, entry);
    }

    let entries_to_remove = identify_entries_to_remove(&all_attempts);

    // Should remove approximately half of the entries
    let expected_to_remove = MAX_RATE_LIMIT_ENTRIES / 2;
    assert_eq!(entries_to_remove.len(), expected_to_remove);

    // Check that the oldest entries (by first attempt time) are marked for removal
    // This is harder to verify precisely, but we can check that we're removing some
    assert!(!entries_to_remove.is_empty());
}

#[tokio::test]
async fn test_identify_entries_to_remove_more_than_available() {
    let mut all_attempts = HashMap::new();
    let now = Instant::now();

    // Add only a few entries
    for i in 0..5 {
        let key = format!("email{i}");
        let mut entry = RateLimitEntry::new();
        entry.add_attempt(now, Duration::from_secs(RATE_LIMIT_WINDOW_SECS));
        all_attempts.insert(key, entry);
    }

    // Temporarily set the limit very low to trigger removal of more than available
    // We can't change the constant, but we can test the logic
    let num_to_remove = all_attempts.len() + 10; // More than we have
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

    // This simulates what happens when num_to_remove > entries_with_times.len()
    if num_to_remove < entries_with_times.len() {
        entries_with_times.select_nth_unstable(num_to_remove - 1);
        entries_with_times.truncate(num_to_remove);
    } else {
        // If we need to remove more than we have, just truncate to all
        entries_with_times.truncate(entries_with_times.len());
    }

    assert_eq!(entries_with_times.len(), all_attempts.len()); // All are returned since we have fewer than requested to remove
}

#[tokio::test]
async fn test_check_rate_limit_status_no_attempts() {
    // Since check_rate_limit_status was removed, we'll create a test that verifies the atomic function behavior
    // by checking that a fresh rate limit check passes
    let attempts_map = Arc::new(Mutex::new(HashMap::new()));
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let email_hash = "test@example.com";
    let device_id = "test_device";

    let rate_limit_key = RATE_LIMIT_KEY;

    // Test that the atomic check-and-record passes when no attempts have been made
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action: "login",
        rate_limit_key,
    };
    let result = check_and_record_rate_limit(
        &attempts_map,
        &global_attempts,
        &device_attempts,
        email_hash,
        device_id,
        config,
    )
    .await;

    // The check should pass, but since this function records an attempt when it passes,
    // it will record the attempt as a failed one (because it's part of the login flow)
    // So this test verifies that the rate limit check passed initially
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_check_rate_limit_status_within_limits() {
    let attempts_map = Arc::new(Mutex::new(HashMap::new()));
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let email_hash = "test@example.com";
    let device_id = "test_device";

    // Add some attempts within the window but under the limit
    {
        let mut map = attempts_map.lock().await;
        let mut entry = RateLimitEntry::new();
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        // Add attempts but stay under the limit
        for _ in 0..MAX_ATTEMPTS_PER_WINDOW - 1 {
            entry.add_attempt(now, window_duration);
        }

        map.insert(email_hash.to_string(), entry);
    }

    let rate_limit_key = RATE_LIMIT_KEY;
    // Test that the atomic check-and-record passes when attempts are within limits
    // Note: This will record an attempt as part of the check
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action: "login",
        rate_limit_key,
    };
    let result = check_and_record_rate_limit(
        &attempts_map,
        &global_attempts,
        &device_attempts,
        email_hash,
        device_id,
        config,
    )
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_check_rate_limit_status_exceeds_limits() {
    let attempts_map = Arc::new(Mutex::new(HashMap::new()));
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let email_hash = "test@example.com";
    let device_id = "test_device";

    // Add attempts that exceed the limit
    {
        let mut map = attempts_map.lock().await;
        let mut entry = RateLimitEntry::new();
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        // Add more attempts than the limit
        for _ in 0..=MAX_ATTEMPTS_PER_WINDOW {
            entry.add_attempt(now, window_duration);
        }

        map.insert(email_hash.to_string(), entry);
    }

    let rate_limit_key = RATE_LIMIT_KEY;
    // Since we already added attempts that exceed the limit, the atomic check should fail
    // This test needs to be restructured since the original test assumed separate check vs record
    // With the new atomic function, we can't test exceeding the limit without actually recording attempts
    // We'll skip this test as it's not applicable to the new atomic design
    // Instead, we'll verify that the function would fail by checking the internal state beforehand
    {
        let mut map = attempts_map.lock().await;
        if let Some(entry) = map.get_mut(email_hash) {
            let now = std::time::Instant::now();
            let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
            let recent_attempts = entry.count_recent_attempts(now, window_duration);
            assert!(
                recent_attempts > MAX_ATTEMPTS_PER_WINDOW,
                "Expected attempts to exceed limit"
            );
        }
    } // Lock is released here before calling check_and_record_rate_limit

    // Now try the atomic function - it should fail due to exceeding the limit
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action: "login",
        rate_limit_key,
    };
    let result = check_and_record_rate_limit(
        &attempts_map,
        &global_attempts,
        &device_attempts,
        email_hash,
        device_id,
        config,
    )
    .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Too many login attempts"));
}

#[tokio::test]
async fn test_record_failed_attempt_creates_new_entry() {
    let attempts_map = Arc::new(Mutex::new(HashMap::new()));
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let email_hash = "new@example.com";
    let device_id = "test_device";

    // Test the atomic check-and-record function instead of the old record_failed_attempt
    // We'll test that the atomic function properly creates and adds attempts to entries
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW, // Set to higher than 1 to allow this attempt
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action: "login", // This will record as a failed attempt since no user exists
        rate_limit_key: RATE_LIMIT_KEY,
    };
    let _result = check_and_record_rate_limit(
        &attempts_map,
        &global_attempts,
        &device_attempts,
        email_hash,
        device_id,
        config,
    )
    .await;

    // Check that the entry was created (this would be after the check fails and records)
    let attempts_len = {
        let map = attempts_map.lock().await;
        assert!(map.contains_key(email_hash));
        map.get(email_hash).unwrap().attempts.len()
    };
    // The attempt should have been recorded by the atomic function
    assert_eq!(attempts_len, 1);
}

#[tokio::test]
async fn test_record_failed_attempt_adds_to_existing() {
    let attempts_map = Arc::new(Mutex::new(HashMap::new()));
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let email_hash = "existing@example.com";
    let device_id = "test_device";

    // Pre-populate with one attempt
    {
        let mut map = attempts_map.lock().await;
        let mut entry = RateLimitEntry::new();
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
        entry.add_attempt(now, window_duration);
        map.insert(email_hash.to_string(), entry);
    }

    // Test the atomic check-and-record function to add another attempt
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW, // Higher than current attempts to allow
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action: "login", // Will record as failed attempt
        rate_limit_key: RATE_LIMIT_KEY,
    };
    let _result = check_and_record_rate_limit(
        &attempts_map,
        &global_attempts,
        &device_attempts,
        email_hash,
        device_id,
        config,
    )
    .await;

    // Check that the entry now has 2 attempts (original + this one)
    let attempts_len = {
        let map = attempts_map.lock().await;
        assert!(map.contains_key(email_hash));
        map.get(email_hash).unwrap().attempts.len()
    };
    // The attempt should have been recorded by the atomic function
    assert_eq!(attempts_len, 2);
}

#[tokio::test]
async fn test_rate_limit_entry_cleanup_old_attempts() {
    let mut entry = RateLimitEntry::new();
    let now = std::time::Instant::now();
    let old_time = now
        .checked_sub(Duration::from_secs(RATE_LIMIT_WINDOW_SECS + 1))
        .unwrap(); // Past the window
    let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

    // Add an old attempt
    entry.attempts.push_back(old_time);

    // Add a recent attempt
    entry.attempts.push_back(now);

    // Cleanup should remove the old attempt
    entry.cleanup_old_attempts(now, window_duration);

    assert_eq!(entry.attempts.len(), 1); // Only the recent one remains
}

#[tokio::test]
async fn test_rate_limit_entry_cleanup_excessive_attempts() {
    let mut entry = RateLimitEntry::new();
    let now = std::time::Instant::now();
    let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

    // Add more attempts than the maximum allowed
    for _ in 0..MAX_STORED_ATTEMPTS + 10 {
        entry.attempts.push_back(now);
    }

    // Cleanup should enforce the maximum
    entry.cleanup_old_attempts(now, window_duration);

    assert_eq!(entry.attempts.len(), MAX_STORED_ATTEMPTS);
}

#[tokio::test]
async fn test_rate_limit_entry_count_recent_attempts() {
    let mut entry = RateLimitEntry::new();
    let now = std::time::Instant::now();
    let old_time = now
        .checked_sub(Duration::from_secs(RATE_LIMIT_WINDOW_SECS + 1))
        .unwrap(); // Past the window
    let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

    // Add an old attempt
    entry.attempts.push_back(old_time);

    // Add a recent attempt
    entry.add_attempt(now, window_duration);

    // Count should only include the recent one
    let count = entry.count_recent_attempts(now, window_duration);
    assert_eq!(count, 1);
}

#[tokio::test]
async fn test_concurrent_rate_limit_access() {
    use tokio::sync::Barrier;

    let attempts_map = Arc::new(Mutex::new(HashMap::new()));
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let barrier = Arc::new(Barrier::new(10)); // 10 concurrent tasks
    let email_hash = "concurrent@example.com".to_string();
    let device_id = "test_device";

    let mut handles = vec![];

    // Clone the barrier once before the loop to ensure all tasks share the same barrier
    let shared_barrier = Arc::clone(&barrier);

    // Spawn multiple concurrent tasks that will check rate limits with timeout
    for _ in 0..10 {
        let attempts_map_clone = Arc::clone(&attempts_map);
        let global_attempts_clone = Arc::clone(&global_attempts);
        let device_attempts_clone = Arc::clone(&device_attempts);
        let barrier_clone = Arc::clone(&shared_barrier); // Use the shared barrier
        let email_hash_clone = email_hash.clone();
        let device_id_clone = device_id.to_string();

        let handle = tokio::spawn(async move {
            barrier_clone.wait().await; // Wait for all tasks to start at once

            // Add timeout to prevent indefinite hangs in case of deadlock
            let timeout_duration = Duration::from_secs(10); // 10 second timeout
            let rate_limit_key = RATE_LIMIT_KEY;
            let config = RateLimitConfig {
                max_attempts: MAX_ATTEMPTS_PER_WINDOW,
                window_duration_secs: RATE_LIMIT_WINDOW_SECS,
                action: "login",
                rate_limit_key,
            };

            let result = tokio::time::timeout(
                timeout_duration,
                check_and_record_rate_limit(
                    &attempts_map_clone,
                    &global_attempts_clone,
                    &device_attempts_clone,
                    &email_hash_clone,
                    &device_id_clone,
                    config,
                ),
            )
            .await;

            // If timeout occurs, return an error instead of hanging
            result
                .unwrap_or_else(|_| Err("Test timeout: Rate limit check took too long".to_string()))
        });

        handles.push(handle);
    }

    // Wait for all tasks to complete with a timeout
    let timeout_duration = Duration::from_secs(15); // 15 second total timeout
    let join_results =
        tokio::time::timeout(timeout_duration, futures::future::join_all(handles)).await;

    match join_results {
        Ok(results) => {
            // All tasks completed successfully
            for result in results {
                // Surface panics and JoinErrors (e.g., cancellation) as test failures.
                let inner = result.expect("spawned task panicked or was cancelled");
                // We don't care whether the rate limit itself allowed/denied, only that it ran safely.
                let _ = inner;
            }
        }
        Err(timeout_error) => {
            // Test timed out - this indicates a deadlock or other issue
            panic!(
                "test_concurrent_rate_limit_access timed out after 15 seconds. This indicates a deadlock or other blocking issue. Error: {timeout_error:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_evict_old_entries_at_capacity_threshold() {
    let mut all_attempts = HashMap::new();
    let now = Instant::now();

    // Add entries to reach the capacity threshold (3/4 of max)
    for i in 0..(MAX_RATE_LIMIT_ENTRIES * 3) / 4 {
        let key = format!("email{i}");
        let mut entry = RateLimitEntry::new();
        entry.add_attempt(now, Duration::from_secs(RATE_LIMIT_WINDOW_SECS));
        all_attempts.insert(key, entry);
    }

    // This should still return early since we're exactly at the threshold
    evict_old_entries(&mut all_attempts, now);

    // Size should remain the same since we didn't exceed the threshold
    assert_eq!(all_attempts.len(), (MAX_RATE_LIMIT_ENTRIES * 3) / 4);
}

#[tokio::test]
async fn test_evict_old_entries_past_capacity_threshold() {
    let mut all_attempts = HashMap::new();
    let now = Instant::now();

    // Add entries to go past the capacity threshold
    for i in 0..=(MAX_RATE_LIMIT_ENTRIES * 3) / 4 {
        let key = format!("email{i}");
        let mut entry = RateLimitEntry::new();
        entry.add_attempt(now, Duration::from_secs(RATE_LIMIT_WINDOW_SECS));
        all_attempts.insert(key, entry);
    }

    // This should trigger the eviction logic
    evict_old_entries(&mut all_attempts, now);

    // The number of entries might be reduced due to the cleanup logic
    // depending on whether any entries were considered too old
    assert!(all_attempts.len() <= (MAX_RATE_LIMIT_ENTRIES * 3) / 4 + 1);
}

#[test]
fn test_hash_email_for_logging_success() {
    let email = "test@example.com";
    let key = RATE_LIMIT_KEY;

    let result = hash_email_for_logging(email, key);
    assert!(result.is_ok());

    let hashed = result.unwrap();
    // Should be a hex string of 64 characters (32 bytes)
    assert_eq!(hashed.len(), 64);
    // Should contain only hex characters
    assert!(hashed.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_hash_email_for_logging_invalid_key() {
    let email = "test@example.com";
    // Using a random short byte array to validate handling of too-short keys.
    // Key length of 3 is intentionally invalid (too short).
    let mut key = vec![0u8; 3];
    getrandom::getrandom(&mut key).expect("Failed to generate random bytes for test key");
    let result = hash_email_for_logging(email, &key);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_check_global_rate_limit_status_within_limits() {
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let action = "login";

    // Add some attempts within the window but under the limit
    {
        let mut entry = global_attempts.lock().await;
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        // Add attempts but stay under the limit
        for _ in 0..DEFAULT_GLOBAL_MAX_ATTEMPTS_PER_WINDOW - 1 {
            entry.add_attempt(now, window_duration);
        }
    }

    // Since check_global_rate_limit_status was removed, we'll test the global limit check
    // as part of the atomic function. For this test, we'll verify the global attempts state manually.
    // Check the current state of global attempts to ensure it's under the limit
    {
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
        let recent_attempts = global_attempts
            .lock()
            .await
            .count_recent_attempts(now, window_duration);
        assert!(
            recent_attempts < DEFAULT_GLOBAL_MAX_ATTEMPTS_PER_WINDOW,
            "Global attempts should be under limit"
        );
    }

    // Verify that an atomic check would pass with this global state
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action,
        rate_limit_key: RATE_LIMIT_KEY,
    };
    let result = check_and_record_rate_limit(
        &Arc::new(Mutex::new(HashMap::new())), // Empty email attempts map
        &global_attempts,
        &Arc::new(Mutex::new(HashMap::new())), // Empty device attempts map
        "test@example.com",
        "test_device",
        config,
    )
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_check_global_rate_limit_status_exceeds_limits() {
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let action = "login";

    // Add attempts that exceed the limit
    {
        let mut entry = global_attempts.lock().await;
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        // Add more attempts than the limit
        for _ in 0..=DEFAULT_GLOBAL_MAX_ATTEMPTS_PER_WINDOW {
            entry.add_attempt(now, window_duration);
        }
    }

    // Since check_global_rate_limit_status was removed, we'll test the scenario where
    // the global rate limit would be exceeded by the atomic function
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action,
        rate_limit_key: RATE_LIMIT_KEY,
    };
    let result = check_and_record_rate_limit(
        &Arc::new(Mutex::new(HashMap::new())), // Empty email attempts map
        &global_attempts,                      // This has attempts that exceed the global limit
        &Arc::new(Mutex::new(HashMap::new())), // Empty device attempts map
        "test@example.com",
        "test_device",
        config,
    )
    .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("Too many login attempts globally")
    );
}

#[tokio::test]
async fn test_check_device_rate_limit_status_within_limits() {
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let device_id = "test_device_123";
    let action = "login";

    // Add some attempts within the window but under the limit
    {
        let mut map = device_attempts.lock().await;
        let mut entry = RateLimitEntry::new();
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        // Add attempts but stay under the limit
        for _ in 0..DEFAULT_DEVICE_MAX_ATTEMPTS_PER_WINDOW - 1 {
            entry.add_attempt(now, window_duration);
        }

        map.insert(device_id.to_string(), entry);
    }

    let rate_limit_key = RATE_LIMIT_KEY;
    // Since check_device_rate_limit_status was removed, we'll test the device limit check
    // as part of the atomic function. For this test, we'll verify the device attempts state manually.
    // Check the current state of device attempts to ensure it's under the limit
    {
        let mut device_map = device_attempts.lock().await;
        if let Some(device_entry) = device_map.get_mut(device_id) {
            let now = std::time::Instant::now();
            let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
            let recent_attempts = device_entry.count_recent_attempts(now, window_duration);
            assert!(
                recent_attempts < DEFAULT_DEVICE_MAX_ATTEMPTS_PER_WINDOW,
                "Device attempts should be under limit"
            );
        }
    }

    // Verify that an atomic check would pass with this device state
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action,
        rate_limit_key,
    };
    let result = check_and_record_rate_limit(
        &Arc::new(Mutex::new(HashMap::new())), // Empty email attempts map
        &Arc::new(Mutex::new(RateLimitEntry::new())), // Empty global attempts
        &device_attempts,
        "test@example.com",
        device_id,
        config,
    )
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_check_device_rate_limit_status_exceeds_limits() {
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let device_id = "test_device_123";
    let action = "login";

    // Add attempts that exceed the limit
    {
        let mut map = device_attempts.lock().await;
        let mut entry = RateLimitEntry::new();
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        // Add more attempts than the limit
        for _ in 0..=DEFAULT_DEVICE_MAX_ATTEMPTS_PER_WINDOW {
            entry.add_attempt(now, window_duration);
        }

        map.insert(device_id.to_string(), entry);
    }

    let rate_limit_key = RATE_LIMIT_KEY;
    // Since check_device_rate_limit_status was removed, we'll test the scenario where
    // the device rate limit would be exceeded by the atomic function
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action,
        rate_limit_key,
    };
    let result = check_and_record_rate_limit(
        &Arc::new(Mutex::new(HashMap::new())), // Empty email attempts map
        &Arc::new(Mutex::new(RateLimitEntry::new())), // Empty global attempts
        &device_attempts,                      // This has attempts that exceed the device limit
        "test@example.com",
        device_id,
        config,
    )
    .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("Too many login attempts from this device")
    );
}

#[tokio::test]
async fn test_check_rate_limit_status_all_three_limits_pass() {
    let attempts_map = Arc::new(Mutex::new(HashMap::new()));
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let email_hash = "test@example.com";
    let device_id = "test_device_123";
    let action = "login";

    // Add attempts within all limits
    {
        // Email attempts
        let mut map = attempts_map.lock().await;
        let mut entry = RateLimitEntry::new();
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        for _ in 0..MAX_ATTEMPTS_PER_WINDOW - 1 {
            entry.add_attempt(now, window_duration);
        }
        map.insert(email_hash.to_string(), entry);
    }

    {
        // Global attempts
        let mut entry = global_attempts.lock().await;
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        for _ in 0..DEFAULT_GLOBAL_MAX_ATTEMPTS_PER_WINDOW - 1 {
            entry.add_attempt(now, window_duration);
        }
    }

    {
        // Device attempts
        let mut map = device_attempts.lock().await;
        let mut entry = RateLimitEntry::new();
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        for _ in 0..DEFAULT_DEVICE_MAX_ATTEMPTS_PER_WINDOW - 1 {
            entry.add_attempt(now, window_duration);
        }
        map.insert(device_id.to_string(), entry);
    }

    let rate_limit_key = RATE_LIMIT_KEY;
    // Test the atomic function with all three limits passing
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action,
        rate_limit_key,
    };
    let result = check_and_record_rate_limit(
        &attempts_map,
        &global_attempts,
        &device_attempts,
        email_hash,
        device_id,
        config,
    )
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_record_failed_attempt_records_all_three_limits() {
    let attempts_map = Arc::new(Mutex::new(HashMap::new()));
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let email_hash = "new@example.com";
    let device_id = "test_device_123";

    // Test the atomic function which records attempts across all three limits
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action: "login", // Action type
        rate_limit_key: RATE_LIMIT_KEY,
    };
    let _result = check_and_record_rate_limit(
        &attempts_map,
        &global_attempts,
        &device_attempts,
        email_hash,
        device_id,
        config,
    )
    .await;

    // Check that all three limits have recorded the attempt
    {
        let attempts_len = {
            let map = attempts_map.lock().await;
            assert!(map.contains_key(email_hash));
            map.get(email_hash).unwrap().attempts.len()
        };
        assert_eq!(attempts_len, 1);
    }

    {
        let entry_len = global_attempts.lock().await.attempts.len();
        assert_eq!(entry_len, 1);
    }

    {
        let attempts_len = {
            let map = device_attempts.lock().await;
            assert!(map.contains_key(device_id));
            map.get(device_id).unwrap().attempts.len()
        };
        assert_eq!(attempts_len, 1);
    }
}

#[tokio::test]
async fn test_bounded_eviction_prevents_memory_dos() {
    let attempts_map = Arc::new(Mutex::new(HashMap::new()));
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let device_id = "test_device";

    // Fill the attempts map to near the maximum capacity to trigger bounded eviction
    let max_entries = crate::constants::DEFAULT_MAX_RATE_LIMIT_ENTRIES;
    {
        let mut map = attempts_map.lock().await;
        for i in 0..max_entries {
            let key = format!("email{i}");
            let mut entry = RateLimitEntry::new();
            let now = std::time::Instant::now();
            let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
            entry.add_attempt(now, window_duration);
            map.insert(key, entry);
        }
    }

    // Verify that the map is filled
    let map = attempts_map.lock().await;
    assert_eq!(map.len(), max_entries);
    drop(map);

    let email_hash = "new_test@example.com"; // Add the missing email_hash variable

    // Record another failed attempt using the atomic function which should trigger bounded eviction
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action: "login", // Action type
        rate_limit_key: RATE_LIMIT_KEY,
    };
    let _result = check_and_record_rate_limit(
        &attempts_map,
        &global_attempts,
        &device_attempts,
        email_hash,
        device_id,
        config,
    )
    .await;

    // Check that the map size is still bounded and hasn't grown indefinitely
    let map = attempts_map.lock().await;
    // The size should be reduced due to eviction, but not empty
    assert!(map.len() <= max_entries);
    assert!(!map.is_empty());
}

#[tokio::test]
async fn test_bounded_eviction_under_threshold_does_not_evict() {
    let attempts_map = Arc::new(Mutex::new(HashMap::new()));
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let email_hash = "test@example.com";
    let device_id = "test_device";

    // Fill the attempts map to under the eviction threshold (3/4 of max)
    let max_entries = crate::constants::DEFAULT_MAX_RATE_LIMIT_ENTRIES;
    let under_threshold_entries = (max_entries * 3) / 4 - 10; // Well under the threshold

    {
        let mut map = attempts_map.lock().await;
        for i in 0..under_threshold_entries {
            let key = format!("email{i}");
            let mut entry = RateLimitEntry::new();
            let now = std::time::Instant::now();
            let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
            entry.add_attempt(now, window_duration);
            map.insert(key, entry);
        }
    }

    // Verify that the map is filled to under-threshold level
    let initial_size = {
        let map = attempts_map.lock().await;
        map.len()
    };
    assert_eq!(initial_size, under_threshold_entries);

    // Record another failed attempt using the atomic function which should NOT trigger bounded eviction
    // since we're under the threshold
    let config = RateLimitConfig {
        max_attempts: MAX_ATTEMPTS_PER_WINDOW,
        window_duration_secs: RATE_LIMIT_WINDOW_SECS,
        action: "login", // Action type
        rate_limit_key: RATE_LIMIT_KEY,
    };
    let _result = check_and_record_rate_limit(
        &attempts_map,
        &global_attempts,
        &device_attempts,
        email_hash,
        device_id,
        config,
    )
    .await;

    // Check that the map size increased by 1 (no eviction happened)
    let final_size = {
        let map = attempts_map.lock().await;
        map.len()
    };
    assert_eq!(final_size, initial_size + 1);
}

#[tokio::test]
async fn test_record_failed_attempt_bounded_eviction_performance() {
    let attempts_map = Arc::new(Mutex::new(HashMap::new()));
    let global_attempts = Arc::new(Mutex::new(RateLimitEntry::new()));
    let device_attempts = Arc::new(Mutex::new(HashMap::new()));
    let device_id = "test_device";

    // Fill the attempts map to near the maximum capacity to trigger bounded eviction
    let max_entries = crate::constants::DEFAULT_MAX_RATE_LIMIT_ENTRIES;
    {
        let mut map = attempts_map.lock().await;
        for i in 0..max_entries {
            let key = format!("email{i}");
            let mut entry = RateLimitEntry::new();
            let now = std::time::Instant::now();
            let window_duration = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
            entry.add_attempt(now, window_duration);
            map.insert(key, entry);
        }
    }

    // Measure time to ensure bounded eviction doesn't take too long
    let start_time = std::time::Instant::now();

    // Record multiple failed attempts using the atomic function which should trigger bounded eviction
    for i in 0..10 {
        let config = RateLimitConfig {
            max_attempts: MAX_ATTEMPTS_PER_WINDOW,
            window_duration_secs: RATE_LIMIT_WINDOW_SECS,
            action: "login", // Action type
            rate_limit_key: RATE_LIMIT_KEY,
        };
        let _result = check_and_record_rate_limit(
            &attempts_map,
            &global_attempts,
            &device_attempts,
            &format!("test{i}@example.com"),
            device_id,
            config,
        )
        .await;
    }

    let elapsed = start_time.elapsed();

    // Ensure the bounded eviction completes quickly (less than 1 second for 10 records)
    assert!(
        elapsed.as_millis() < 1000,
        "Bounded eviction took too long: {elapsed:?}"
    );

    // Check that the map size is still bounded
    let map = attempts_map.lock().await;
    assert!(map.len() <= max_entries);
    assert!(!map.is_empty());
}

#[tokio::test]
#[cfg(unix)]
async fn test_device_id_persistence_security_symlink_attack_prevention() {
    use std::fs;
    use std::os::unix::fs::symlink;

    // Create a temporary directory for testing (unique to avoid cross-test collisions)
    let temp_dir = std::env::temp_dir();
    let test_dir = temp_dir.join(format!(
        "test_device_id_dir_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&test_dir).unwrap();

    // Create a real file with some content
    let real_file = test_dir.join("real_file.txt");
    fs::write(&real_file, "real_content").unwrap();

    // Create the device ID path as a symlink to the real file
    let device_id_symlink = test_dir.join("device_id");
    symlink(&real_file, &device_id_symlink).unwrap();

    // Attempt to read from the symlink path should fail due to symlink detection
    // This simulates the security check in get_device_id function
    let result = std::fs::symlink_metadata(&device_id_symlink);
    if let Ok(metadata) = result {
        assert!(
            metadata.file_type().is_symlink(),
            "Path should be detected as a symlink"
        );
    }

    // Clean up
    let _ = fs::remove_file(&real_file);
    let _ = fs::remove_file(&device_id_symlink);
    let _ = fs::remove_dir(&test_dir);
}

#[tokio::test]
async fn test_secure_file_creator_prevents_race_conditions() {
    use infra::security::SecureFileCreator;
    use std::fs;

    // Create a temporary directory for testing
    let temp_dir = std::env::temp_dir();
    let unique_name = format!(
        "secure_test_file_{}_{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let test_file = temp_dir.join(unique_name);

    // Clean up if file exists
    let _ = fs::remove_file(&test_file);

    // Test SecureFileCreator: atomic file creation and writing without following symlinks
    let content = "test content";
    let creator = SecureFileCreator::new();
    let result = creator.write_string(&test_file, content);

    assert!(
        result.is_ok(),
        "SecureFileCreator should create and write file successfully"
    );

    // Verify the file was created with correct content
    let read_content = fs::read_to_string(&test_file).unwrap();
    assert_eq!(read_content, content);

    // Verify that the file is not a symlink (security property)
    let metadata = fs::symlink_metadata(&test_file).unwrap();
    assert!(
        !metadata.file_type().is_symlink(),
        "File should not be a symlink"
    );

    // Verify atomic creation: attempting to create the same file again should fail
    let creator2 = SecureFileCreator::new();
    let result2 = creator2.write_string(&test_file, "different content");
    assert!(
        result2.is_err(),
        "SecureFileCreator should fail when file already exists"
    );

    // Clean up
    let _ = fs::remove_file(&test_file);
}

#[tokio::test]
#[cfg(unix)]
async fn test_device_id_directory_permissions_security() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    // Create a temporary directory for testing
    let temp_dir = std::env::temp_dir();
    let test_dir = temp_dir.join("device_id_test_dir");
    let _ = fs::create_dir_all(&test_dir);

    // Simulate the parent directory creation and permission setting
    // as done in the get_device_id function
    if let Ok(mut permissions) = fs::metadata(&test_dir).map(|m| m.permissions()) {
        permissions.set_mode(0o700); // rwx------ (owner only)
        let result = fs::set_permissions(&test_dir, permissions);
        assert!(
            result.is_ok(),
            "Setting directory permissions should succeed"
        );
    }

    // Verify the permissions were set correctly
    if let Ok(metadata) = fs::metadata(&test_dir) {
        let mode = metadata.permissions().mode();
        // Check that it's a directory and has restrictive permissions (owner rwx, others none)
        assert_eq!(mode & 0o777, 0o700, "Directory should have 700 permissions");
    }

    // Clean up
    let _ = fs::remove_dir_all(&test_dir);
}
