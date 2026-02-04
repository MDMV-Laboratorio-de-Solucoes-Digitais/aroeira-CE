use anyhow::Result;
use bcrypt::{hash, verify};

const DEFAULT_COST: u32 = 12;
const MIN_COST: u32 = 10;
const MAX_COST: u32 = 16;

// Get bcrypt cost from environment or use default
fn get_bcrypt_cost() -> u32 {
    let cost = std::env::var("BCRYPT_COST")
        .ok()
        .and_then(|val| val.parse::<u32>().ok())
        .unwrap_or(DEFAULT_COST);

    cost.clamp(MIN_COST, MAX_COST)
}

/// Hashes a password using bcrypt
///
/// # Errors
///
/// This function will return an error if:
/// - The bcrypt hashing operation fails
pub fn hash_password(password: &str) -> Result<String> {
    let cost = get_bcrypt_cost();
    Ok(hash(password, cost)?)
}

/// Verifies a password against a bcrypt hash
///
/// # Errors
///
/// This function will return an error if:
/// - The bcrypt verification operation fails
#[tracing::instrument(skip(password, hash))]
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    Ok(verify(password, hash)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prev = std::env::var_os(key);
            // SAFETY: Access is serialized by ENV_LOCK in tests.
            // unsafe is required in Rust 1.81+ for set_var.
            unsafe {
                std::env::set_var(key, val);
            }
            Self { key, prev }
        }

        fn unset(key: &'static str) -> Self {
            let prev = std::env::var_os(key);
            // SAFETY: Access is serialized by ENV_LOCK in tests.
            // unsafe is required in Rust 1.81+ for remove_var.
            unsafe {
                std::env::remove_var(key);
            }
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(v) = self.prev.take() {
                // SAFETY: Access is serialized by ENV_LOCK in tests.
                // unsafe is required in Rust 1.81+ for set_var.
                unsafe {
                    std::env::set_var(self.key, v);
                }
            } else {
                // SAFETY: Access is serialized by ENV_LOCK in tests.
                // unsafe is required in Rust 1.81+ for remove_var.
                unsafe {
                    std::env::remove_var(self.key);
                }
            }
        }
    }

    #[test]
    fn test_hash_and_verify_password() {
        let _lock = ENV_LOCK.lock().unwrap();
        // Use a low cost for testing.
        let _guard = EnvGuard::set("BCRYPT_COST", "4"); // Min valid bcrypt cost is 4

        let password = uuid::Uuid::new_v4().to_string();
        let hash = hash_password(&password).unwrap();

        assert_ne!(password, hash);
        assert!(verify_password(&password, &hash).unwrap());
        let wrong_password = uuid::Uuid::new_v4().to_string();
        assert!(!verify_password(&wrong_password, &hash).unwrap());
    }

    #[test]
    fn test_bcrypt_cost_parsing() {
        let _lock = ENV_LOCK.lock().unwrap();

        {
            let _g = EnvGuard::set("BCRYPT_COST", "8");
            assert_eq!(get_bcrypt_cost(), 10); // clamped to min 10
        }

        {
            let _g = EnvGuard::set("BCRYPT_COST", "20");
            assert_eq!(get_bcrypt_cost(), 16); // clamped to max 16
        }

        {
            let _g = EnvGuard::set("BCRYPT_COST", "invalid");
            assert_eq!(get_bcrypt_cost(), DEFAULT_COST);
        }

        {
            let _g = EnvGuard::unset("BCRYPT_COST");
            assert_eq!(get_bcrypt_cost(), DEFAULT_COST);
        }
    }
}
