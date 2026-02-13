#[cfg(test)]
mod database_tests {
    use crate::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    use std::sync::{LazyLock, Mutex};

    static ENV_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(val) = &self.prev {
                unsafe { std::env::set_var(self.key, val) };
            } else {
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

    #[test]
    fn test_resolve_and_validate_fallback_path_valid_relative() {
        // Serialize tests that modify environment variables to prevent race conditions
        let _guard = ENV_MUTEX.lock().expect("Failed to acquire env var lock");

        // Store the previous value to restore later
        let prev_value = std::env::var("SQLITE_FALLBACK_PATH").ok();
        let _env_guard = EnvVarGuard {
            key: "SQLITE_FALLBACK_PATH",
            prev: prev_value,
        };

        // Test valid relative path
        unsafe {
            std::env::set_var("SQLITE_FALLBACK_PATH", "test.db");
        }

        let result = database::resolve_and_validate_fallback_path();
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path, PathBuf::from("test.db"));
    }

    #[test]
    fn test_resolve_and_validate_fallback_path_with_path_traversal() {
        // Serialize tests that modify environment variables to prevent race conditions
        let _guard = ENV_MUTEX.lock().expect("Failed to acquire env var lock");

        // Test path traversal attempt
        let prev_value = std::env::var("SQLITE_FALLBACK_PATH").ok();
        let _env_guard = EnvVarGuard {
            key: "SQLITE_FALLBACK_PATH",
            prev: prev_value,
        };

        unsafe {
            std::env::set_var("SQLITE_FALLBACK_PATH", "../etc/passwd");
        }

        let result = database::resolve_and_validate_fallback_path();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must not contain parent directory references")
        );
    }

    #[test]
    fn test_resolve_and_validate_fallback_path_absolute_without_opt_in() {
        // Serialize tests that modify environment variables to prevent race conditions
        let _guard = ENV_MUTEX.lock().expect("Failed to acquire env var lock");

        // Store the previous values to restore later
        let prev_fallback_path = std::env::var("SQLITE_FALLBACK_PATH").ok();
        let _env_guard1 = EnvVarGuard {
            key: "SQLITE_FALLBACK_PATH",
            prev: prev_fallback_path,
        };
        let prev_allow_path = std::env::var("ALLOW_ABSOLUTE_FALLBACK_PATH").ok();
        let _env_guard2 = EnvVarGuard {
            key: "ALLOW_ABSOLUTE_FALLBACK_PATH",
            prev: prev_allow_path,
        };

        // Test absolute path without opt-in
        unsafe {
            std::env::set_var("SQLITE_FALLBACK_PATH", "/tmp/test.db");
            std::env::remove_var("ALLOW_ABSOLUTE_FALLBACK_PATH");
        }

        let result = database::resolve_and_validate_fallback_path();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("requires explicit opt-in")
        );
    }

    #[test]
    fn test_resolve_and_validate_fallback_path_absolute_with_opt_in() {
        // Serialize tests that modify environment variables to prevent race conditions
        let _guard = ENV_MUTEX.lock().expect("Failed to acquire env var lock");

        // Test absolute path with opt-in
        let temp_dir = TempDir::new().unwrap();
        let temp_file = temp_dir.path().join("test.db");
        let temp_file_str = temp_file.to_string_lossy().to_string();

        // Store the previous values to restore later
        let prev_fallback_path = std::env::var("SQLITE_FALLBACK_PATH").ok();
        let _env_guard1 = EnvVarGuard {
            key: "SQLITE_FALLBACK_PATH",
            prev: prev_fallback_path,
        };
        let prev_allow_path = std::env::var("ALLOW_ABSOLUTE_FALLBACK_PATH").ok();
        let _env_guard2 = EnvVarGuard {
            key: "ALLOW_ABSOLUTE_FALLBACK_PATH",
            prev: prev_allow_path,
        };

        unsafe {
            std::env::set_var("SQLITE_FALLBACK_PATH", &temp_file_str);
            std::env::set_var("ALLOW_ABSOLUTE_FALLBACK_PATH", "true");
        }

        let result = database::resolve_and_validate_fallback_path();
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path, PathBuf::from(&temp_file_str));
    }

    #[test]
    fn test_encode_path_for_sqlite_url_with_reserved_chars() {
        // Test path with reserved characters
        let temp_dir = TempDir::new().unwrap();
        let malicious_path = temp_dir.path().join("test?with#reserved\0chars.db");

        let result = database::encode_path_for_sqlite_url(&malicious_path);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("contains reserved URL characters")
        );
    }

    #[test]
    fn test_encode_path_for_sqlite_url_normal_path() {
        // Test normal path encoding
        let temp_dir = TempDir::new().unwrap();
        let normal_path = temp_dir.path().join("normal.db");

        let result = database::encode_path_for_sqlite_url(&normal_path);
        assert!(result.is_ok());
        let url = result.unwrap();
        assert!(url.starts_with("sqlite:"));
        assert!(url.contains("normal.db"));
    }

    #[cfg(unix)]
    #[test]
    fn test_set_file_permissions_600() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test_perms.db");

        // Create the file
        fs::write(&test_file, "test content").unwrap();

        // Initially set permissions to something else
        fs::set_permissions(&test_file, fs::Permissions::from_mode(0o644)).unwrap();

        // Call our function
        database::set_file_permissions_600(&test_file);

        // Check that permissions were set to 600
        let metadata = fs::metadata(&test_file).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn test_ensure_secure_sqlite_permissions_memory_db() {
        // Test that memory database doesn't cause errors
        let result = database::ensure_secure_sqlite_permissions("sqlite::memory:");
        assert!(result.is_ok());
    }

    #[test]
    fn test_ensure_secure_sqlite_permissions_invalid_prefix() {
        // Test that non-SQLite URLs don't cause errors
        let result = database::ensure_secure_sqlite_permissions("postgres://localhost/test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_ensure_secure_sqlite_permissions_with_symlink() {
        // Serialize tests that rely on global environment state (TMPDIR)
        let _guard = ENV_MUTEX.lock().expect("Failed to acquire env var lock");

        let temp_dir = TempDir::new().unwrap();

        let real_file = temp_dir.path().join("real.db");
        let symlink_file = temp_dir.path().join("symlink.db");

        // Create real file
        fs::write(&real_file, "test").unwrap();

        // Create symlink to the real file
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_file, &symlink_file).unwrap();

        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&real_file, &symlink_file).unwrap();

        // Test with symlink should fail
        let symlink_url = format!("sqlite:{}", symlink_file.to_string_lossy());
        let result = database::ensure_secure_sqlite_permissions(&symlink_url);

        // Should fail because path is a symlink
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("must not be a symlink"),
            "Unexpected error message: {err}",
        );
    }

    #[test]
    fn test_validate_relative_path_containment() {
        // Serialize tests that rely on global environment state (TMPDIR)
        let _guard = ENV_MUTEX.lock().expect("Failed to acquire env var lock");

        let temp_dir = TempDir::new().unwrap();
        let base_dir = temp_dir.path().to_path_buf();
        let contained_file = base_dir.join("safe.db");

        // This should succeed
        let result = database::validate_relative_path_containment(
            &contained_file,
            &PathBuf::from("safe.db"),
            &base_dir,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_relative_path_containment_outside() {
        // Serialize tests that rely on global environment state (TMPDIR)
        let _guard = ENV_MUTEX.lock().expect("Failed to acquire env var lock");

        let temp_dir = TempDir::new().unwrap();
        let base_dir = temp_dir.path().to_path_buf();
        let outside_dir = TempDir::new().unwrap();
        let outside_file = outside_dir.path().join("outside.db"); // Outside the base

        // This should fail
        let result = database::validate_relative_path_containment(
            &outside_file,
            &PathBuf::from("../outside.db"),
            &base_dir,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("resolves outside"),
            "Unexpected error message: {err}"
        );
    }

    #[test]
    fn test_handle_fallback_to_temp_with_symlink() {
        // Serialize tests that modify environment variables to prevent race conditions
        let _guard = ENV_MUTEX.lock().expect("Failed to acquire env var lock");

        let temp_dir = TempDir::new().unwrap();
        let original_temp = std::env::temp_dir();
        let app_temp_dir = temp_dir.path().join("Aroeira_app_data");

        // Store the previous TMPDIR value to restore later
        let prev_tmpdir = std::env::var("TMPDIR").ok();
        let _env_guard = EnvVarGuard {
            key: "TMPDIR",
            prev: prev_tmpdir,
        };

        // Create a symlink to somewhere else
        #[cfg(unix)]
        std::os::unix::fs::symlink(&original_temp, &app_temp_dir).unwrap();

        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&original_temp, &app_temp_dir).unwrap();

        // Change temp dir to our test dir
        unsafe {
            std::env::set_var("TMPDIR", temp_dir.path());
        }

        // This should fail because temp directory is a symlink
        let fallback_path = PathBuf::from("test.db");
        let result = database::handle_fallback_to_temp(&fallback_path);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("is a symlink, refusing to use")
        );
    }

    #[test]
    fn test_securely_create_db_file_with_symlink() {
        // Serialize tests that rely on global environment state (TMPDIR)
        let _guard = ENV_MUTEX.lock().expect("Failed to acquire env var lock");

        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let real_file = temp_dir.path().join("real.db");
        let symlink_file = temp_dir.path().join("symlink.db");

        // Create real file
        fs::write(&real_file, "test").unwrap();

        // Create symlink to the real file
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_file, &symlink_file).unwrap();

        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&real_file, &symlink_file).unwrap();

        // Test with symlink should fail
        let result = database::securely_create_db_file(&symlink_file);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must not be a symlink")
        );
    }

    #[test]
    fn test_securely_create_db_file_successfully_creates() {
        let temp_dir = TempDir::new().unwrap();
        let db_file = temp_dir.path().join("new.db");

        // This should succeed and create the file
        let result = database::securely_create_db_file(&db_file);
        assert!(result.is_ok());

        // File should now exist
        assert!(db_file.exists());
    }

    #[test]
    fn test_apply_sqlite_security_hardening_non_sqlite_url() {
        // Test that non-SQLite URLs don't trigger security hardening
        let result = database::apply_sqlite_security_hardening("postgres://localhost/test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_apply_sqlite_security_hardening_sqlite_url() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db_url = format!("sqlite:{}", db_path.to_string_lossy());

        // This should succeed
        let result = database::apply_sqlite_security_hardening(&db_url);
        assert!(result.is_ok());
    }
}
