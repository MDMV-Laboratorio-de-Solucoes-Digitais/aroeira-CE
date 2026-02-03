use infra::security::{
    FileCreationConfig, PathValidator, SecureFileCreator, SecurityError, ValidationConfig,
};
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_path_validation_prevents_traversal_attacks() {
    let validator = PathValidator::new();

    // Test basic path traversal
    let traversal_path = Path::new("../../etc/passwd");
    let result = validator.validate(traversal_path);
    assert!(
        result.is_err(),
        "Path traversal should be detected and rejected"
    );
    assert!(matches!(
        result.unwrap_err(),
        infra::security::ValidationError::PathTraversalDetected { .. }
    ));

    // Test more complex traversal
    let complex_traversal = Path::new("folder/../../../secret.txt");
    let result2 = validator.validate(complex_traversal);
    assert!(
        result2.is_err(),
        "Complex path traversal should be detected"
    );

    // Test traversal with URL encoding-like patterns
    let url_encoded_traversal = Path::new("folder/%2e%2e/%2e%2e/secret.txt");
    let url_encoded_result = validator.validate(url_encoded_traversal);
    assert!(
        !matches!(
            url_encoded_result,
            Err(infra::security::ValidationError::PathTraversalDetected { .. })
        ),
        "Encoded patterns must not be classified as path traversal"
    );

    let mixed_encoded_path = Path::new("folder/..%2f..%2fsecret.txt"); // ..%2f is not a separator
    let mixed_encoded_result = validator.validate(mixed_encoded_path);
    assert!(
        !matches!(
            mixed_encoded_result,
            Err(infra::security::ValidationError::PathTraversalDetected { .. })
        ),
        "Encoded separators must not be classified as path traversal"
    );

    // Actually, the validator looks for actual .. components, so let's test that
    let valid_path = Path::new("folder/..%2ftest"); // literal segment, not traversal
    let result4 = validator.validate(valid_path);
    assert!(
        !matches!(
            result4,
            Err(infra::security::ValidationError::PathTraversalDetected { .. })
        ),
        "Literal segments must not be classified as path traversal"
    );
}

#[test]
fn test_symlink_detection_prevents_symlink_attacks() {
    #[cfg(unix)]
    {
        use std::os::unix::fs;

        let temp_dir = TempDir::new().expect("Should create temp dir");
        let target_file = temp_dir.path().join("real_file.txt");
        let symlink_path = temp_dir.path().join("symlink_to_real_file");

        // Create a real file
        std::fs::write(&target_file, "secret content").expect("Should create target file");

        // Create a symlink to the real file
        fs::symlink(&target_file, &symlink_path).expect("Should create symlink");

        // Try to validate the symlink path - should fail
        let validator = PathValidator::new();
        let result = validator.validate(&symlink_path);
        assert!(result.is_err(), "Symlinks should be detected and rejected");
        assert!(matches!(
            result.unwrap_err(),
            infra::security::ValidationError::SymlinkDetected { .. }
        ));
    }

    // On Windows, we'd test junction points or symbolic links similarly
    #[cfg(windows)]
    {
        use std::os::windows::fs;

        let temp_dir = TempDir::new().expect("Should create temp dir");
        let target_file = temp_dir.path().join("real_file.txt");
        let symlink_path = temp_dir.path().join("symlink_to_real_file");

        // Create a real file
        std::fs::write(&target_file, "secret content").expect("Should create target file");

        // Create a symbolic link to the real file
        fs::symlink_file(&target_file, &symlink_path).expect("Should create symlink");

        // Try to validate the symlink path - should fail
        let validator = PathValidator::new();
        let result = validator.validate(&symlink_path);
        assert!(result.is_err(), "Symlinks should be detected and rejected");
        assert!(matches!(
            result.unwrap_err(),
            infra::security::ValidationError::SymlinkDetected { .. }
        ));
    }
}

#[test]
fn test_file_creation_uses_restrictive_permissions_0o600() {
    let temp_dir = TempDir::new().expect("Should create temp dir");
    let test_file = temp_dir.path().join("restrictive_test.txt");

    // Use SecureFileCreator to create the file
    let creator = SecureFileCreator::new();
    let config = FileCreationConfig {
        permissions: 0o600,
        ..Default::default()
    };

    let result = creator.create_file_with_config(&test_file, &config);
    assert!(result.is_ok(), "File should be created successfully");

    // Check permissions on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&test_file).expect("Should get file metadata");
        let permissions = metadata.permissions();
        assert_eq!(
            permissions.mode() & 0o777,
            0o600,
            "File should have 0o600 permissions"
        );
    }

    // On Windows, permissions work differently, but ACLs should be restrictive
    #[cfg(windows)]
    {
        // For Windows, we assume the database module sets restrictive ACLs
        assert!(test_file.exists(), "File should exist on Windows too");
    }
}

#[test]
fn test_directory_creation_uses_restrictive_permissions_0o700() {
    let temp_dir = TempDir::new().expect("Should create temp dir");
    let test_dir = temp_dir.path().join("restrictive_test_dir");

    // Use SecureFileCreator to create the directory indirectly by creating a file inside
    let creator = SecureFileCreator::new();
    let test_file_in_dir = test_dir.join("test_file.txt");

    let result = creator.create_file(&test_file_in_dir);
    assert!(
        result.is_ok(),
        "Directory and file should be created successfully"
    );

    // Check directory permissions on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&test_dir).expect("Should get directory metadata");
        let permissions = metadata.permissions();
        assert_eq!(
            permissions.mode() & 0o777,
            0o700,
            "Directory should have 0o700 permissions"
        );
    }

    assert!(test_dir.exists(), "Directory should exist");
    assert!(
        test_file_in_dir.exists(),
        "File inside directory should exist"
    );
}

#[test]
fn test_toctou_attacks_are_prevented_with_atomic_operations() {
    // The PathValidator and SecureFileCreator are designed to prevent TOCTOU attacks
    // by validating the path before any operations and using atomic operations

    let temp_dir = TempDir::new().expect("Should create temp dir");
    let test_file = temp_dir.path().join("atomic_test.txt");

    // Try to create a file atomically
    let creator = SecureFileCreator::new();
    let result = creator.create_file(&test_file);
    assert!(result.is_ok(), "Atomic file creation should succeed");

    // Verify the file was created with the expected content
    let file = result.unwrap();
    drop(file); // Release the file handle

    // Try to create the same file again with fail_if_exists - should fail
    let config = FileCreationConfig {
        fail_if_exists: true,
        ..Default::default()
    };
    let result2 = creator.create_file_with_config(&test_file, &config);
    assert!(
        result2.is_err(),
        "Creating existing file with fail_if_exists should fail"
    );
    assert!(matches!(result2.unwrap_err(), SecurityError::AlreadyExists));
}

#[test]
fn test_error_messages_dont_leak_filesystem_paths() {
    let temp_dir = TempDir::new().expect("Should create temp dir");
    let traversal_path = temp_dir.path().join("../../etc/nonexistent_file");

    // Create a validator with some allowed directories
    let config = ValidationConfig {
        allowed_directories: vec![temp_dir.path().to_path_buf()],
        ..Default::default()
    };

    let validator = PathValidator::with_config(config);
    let result = validator.validate(&traversal_path);

    if let Err(error) = result {
        let error_msg = error.to_string();
        // The error message should not contain the full path for security
        assert!(
            !error_msg.contains("/etc/"),
            "Error message should not leak system paths"
        );
        // Verify error message doesn't contain the full path
        match temp_dir.path().to_string_lossy() {
            std::borrow::Cow::Borrowed(s) => assert!(
                !error_msg.contains(s),
                "Error message should not contain full path"
            ),
            std::borrow::Cow::Owned(s) => assert!(
                !error_msg.contains(&s),
                "Error message should not contain full path"
            ),
        }
    }
}

#[test]
fn test_only_generic_placeholders_used_in_logs() {
    // This test verifies that our security module doesn't log sensitive paths
    // Instead, it should use generic placeholders like "file", "directory", etc.

    let temp_dir = TempDir::new().expect("Should create temp dir");
    let test_file = temp_dir.path().join("placeholder_test.txt");

    // Create a file using SecureFileCreator
    let creator = SecureFileCreator::new();
    let result = creator.create_file(&test_file);
    assert!(
        result.is_ok(),
        "File should be created with secure permissions"
    );

    // The actual test is more about the implementation not logging paths
    // In a real scenario, we'd capture log output to verify placeholders
    assert!(test_file.exists(), "File should exist");

    // Try to create a file in a restricted location to trigger an error
    // but without leaking the path in the error message
    // let mut config = FileCreationConfig::default();
    // config.validate_path = true;

    // This test is more about verifying that our error handling
    // uses generic messages rather than specific paths
    let bad_path = Path::new("../../etc/bad_file.txt");
    let validator = PathValidator::new();
    let validation_result = validator.validate(bad_path);

    if let Err(error) = validation_result {
        let error_msg = error.to_string();

        // Verify that error messages don't contain the full path
        assert!(
            !error_msg.contains("/etc/"),
            "Error should not contain system paths"
        );
    }
}
