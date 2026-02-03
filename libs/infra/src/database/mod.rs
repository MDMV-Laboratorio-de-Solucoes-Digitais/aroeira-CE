pub mod entities;
pub mod repositories;
pub mod utils;

#[cfg(test)]
mod tests;

use crate::security::{PathValidator, SecureFileCreator};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use sea_orm::{Database, DatabaseConnection};
use std::path::PathBuf;
use tracing::{error, info, warn};

// Import security module components
// Windows-specific security functions for file ACLs
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{BOOL, CloseHandle, ERROR_SUCCESS, HANDLE, LPCWSTR, PCWSTR, PSID},
    Security::{
        CreateWellKnownSid, GetTokenInformation, SE_FILE_OBJECT, SetKernelObjectSecurity,
        SetSecurityInfo, TOKEN_INFORMATION_CLASS, TOKEN_USER, WinBuiltinAdministratorsSid,
        WinBuiltinSystemSid,
    },
    Storage::FileSystem::{
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_TRAVERSE,
    },
    Storage::FileSystem::{SetFileSecurityW, SetNamedSecurityInfoW},
    System::Memory::LocalFree,
    System::SystemServices::DELETE,
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

// Helper function to set restrictive file permissions (owner read/write only)
#[cfg(unix)]
pub fn set_file_permissions_600(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!("Could not set restrictive permissions on SQLite file. Error: {e}");
    }
}

/// Set secure permissions atomically to prevent TOCTOU race conditions
// Helper function to set secure permissions atomically with O_NOFOLLOW
#[cfg(unix)]
fn set_secure_permissions_atomically(path: &std::path::Path) -> Result<(), anyhow::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    // Open/create the file with O_NOFOLLOW flag to prevent following symlinks
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;

    // Apply permissions via the open fd to avoid path-based TOCTOU.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;

    Ok(())
}

// Helper function to ensure SQLite files have secure permissions
#[cfg(unix)]
/// Ensures that `SQLite` database files have secure permissions (600 on Unix systems)
///
/// # Errors
///
/// Returns an error if:
/// - The database URL is not a `SQLite` URL
/// - The path contains symlinks (security risk)
/// - There are filesystem permission issues
pub fn ensure_secure_sqlite_permissions(db_url: &str) -> Result<(), anyhow::Error> {
    // Extract the file path from the SQLite URL
    if let Some(decoded_path) = extract_path_from_url(db_url) {
        // Skip if it's a memory database
        if decoded_path != ":memory:" {
            // Validate and canonicalize the path
            let canonical_path = validate_and_canonicalize_path(&decoded_path)?;

            // Set secure permissions on the database file
            set_secure_permissions_on_path(&canonical_path)?;
        }
    }
    Ok(())
}

/// Extract the file path from a `SQLite` URL
/// Returns None if the URL is not a `SQLite` URL
fn extract_path_from_url(db_url: &str) -> Option<String> {
    // Extract the file path from the SQLite URL (support both `sqlite://...` and `sqlite:...` formats)
    let path_str = if let Some(p) = db_url.strip_prefix("sqlite://") {
        p
    } else if let Some(p) = db_url.strip_prefix("sqlite:") {
        p
    } else {
        // If it doesn't start with either prefix, return None
        return None;
    };

    // Split the path and query parameters
    let path_part = path_str.split('?').next().unwrap_or(path_str);

    // Support `file:` URIs by extracting the underlying filesystem path.
    let fs_path_part = path_part.strip_prefix("file:").map_or(path_part, |p| p);

    // Percent-decode in case the path is URI-escaped
    let decoded = percent_encoding::percent_decode_str(fs_path_part)
        .decode_utf8_lossy()
        .to_string();

    // Handle POSIX absolute paths commonly written as sqlite:///path/to/db
    // After stripping "sqlite://", an absolute path may still start with "/".
    Some(decoded)
}

/// Validate and canonicalize the path to prevent symlink attacks
pub(crate) fn validate_and_canonicalize_path(
    decoded_path: &str,
) -> Result<std::path::PathBuf, anyhow::Error> {
    let path = std::path::Path::new(decoded_path);

    // ✅ FIX: Explicitly reject ParentDir components BEFORE any processing
    if path
        .components()
        .any(|comp| matches!(comp, std::path::Component::ParentDir))
    {
        return Err(anyhow::anyhow!(
            "Path must not contain parent directory references ('..')"
        ));
    }

    if path.is_dir() {
        return Err(anyhow::anyhow!(
            "Failed to set database file permissions: expected file but got directory"
        ));
    }

    // To prevent symlink attacks, we'll validate the entire path chain atomically
    let canonical_path = if path.exists() {
        validate_existing_path(path)?
    } else {
        validate_and_create_parent_chain(path)?
    };

    Ok(canonical_path)
}

/// Helper to validate an existing path specifically for symlink protection
fn validate_existing_path(path: &std::path::Path) -> Result<std::path::PathBuf, anyhow::Error> {
    // Reject symlinks in parent directory chain first (defense-in-depth).
    if let Some(parent) = path.parent() {
        let mut current_path = std::path::PathBuf::new();
        let mut components: Vec<_> = parent.components().collect();
        components.reverse();

        for component in components.iter().rev() {
            current_path.push(component);

            if current_path.exists() {
                let md = std::fs::symlink_metadata(&current_path)?;
                if md.file_type().is_symlink() {
                    return Err(anyhow::anyhow!(
                        "Parent directory in path must not be a symlink"
                    ));
                }
                if !md.is_dir() {
                    return Err(anyhow::anyhow!(
                        "Expected directory but found non-directory"
                    ));
                }
            }
        }
    }

    // Reject when DB file itself is a symlink.
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!(
            "SQLite database path must not be a symlink"
        ));
    }

    std::fs::canonicalize(path).map_err(|e| {
        tracing::error!(
            error_kind = ?e.kind(),
            error_message = %e.to_string(),
            path_kind = "database_file",
            "Failed to canonicalize existing database file path"
        );
        anyhow::anyhow!("Failed to canonicalize database file path: {e}")
    })
}

/// Helper to safely validate and create the parent directory chain for a non-existent path
fn validate_and_create_parent_chain(
    path: &std::path::Path,
) -> Result<std::path::PathBuf, anyhow::Error> {
    if let Some(parent) = path.parent() {
        // Recursively validate the parent directory path to ensure no symlinks exist in the chain
        let mut current_path = std::path::PathBuf::new();
        let mut components: Vec<_> = parent.components().collect();

        // Reverse the components to build the path from root to target
        components.reverse();

        // Process components in reverse order (from root toward target)
        for component in components.iter().rev() {
            current_path.push(component);

            // If this part of the path exists, verify it's not a symlink
            validate_directory_safety(&current_path)?;
        }

        // Now that the parent chain is safely created/validated, canonicalize the parent directory
        let parent_canonical = std::fs::canonicalize(&current_path).map_err(|e| {
            tracing::error!(
                error_kind = ?e.kind(),
                error_message = %e.to_string(),
                "Failed to canonicalize parent directory"
            );
            anyhow::anyhow!("Failed to canonicalize parent directory: {e}")
        })?;

        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("SQLite database path must include a filename"))?;
        Ok(parent_canonical.join(file_name))
    } else {
        Err(anyhow::anyhow!(
            "SQLite database path must include a parent directory"
        ))
    }
}

/// Validates or creates a directory in the path chain safely
fn validate_directory_safety(current_path: &std::path::Path) -> Result<(), anyhow::Error> {
    if current_path.exists() {
        let metadata = std::fs::symlink_metadata(current_path)?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!(
                "Parent directory in path must not be a symlink"
            ));
        }

        if !metadata.is_dir() {
            return Err(anyhow::anyhow!(
                "Expected directory but found non-directory"
            ));
        }

        // Warn if existing directories are overly permissive (non-fatal for compatibility).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o777;
            if (mode & 0o077) != 0 {
                tracing::warn!(
                    "Parent directory permissions are overly permissive (mode={:04o}, expected 0o700)",
                    mode
                );
            }
        }
    } else {
        // Create it safely (handle concurrent creation races)
        match std::fs::create_dir(current_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Another process/thread created it; continue with verification below.
            }
            Err(e) => return Err(e.into()),
        }

        // Verify that the path is a real directory and not a symlink
        let metadata = std::fs::symlink_metadata(current_path)?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!(
                "Directory was replaced with symlink after creation"
            ));
        }
        if !metadata.is_dir() {
            return Err(anyhow::anyhow!(
                "Expected directory but found non-directory"
            ));
        }

        // Enforce restrictive permissions after verification (also for concurrent creation).
        #[cfg(unix)]
        if std::fs::set_permissions(
            current_path,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .is_err()
        {
            tracing::warn!(
                "Could not set permissions on parent directory: {}",
                current_path
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new("unknown"))
                    .to_string_lossy()
            );
        }
    }
    Ok(())
}

/// Set secure permissions on the database file path
pub(crate) fn set_secure_permissions_on_path(
    canonical_path: &std::path::Path,
) -> Result<(), anyhow::Error> {
    // ✅ FIX: Use atomic operations with O_NOFOLLOW to prevent TOCTOU race conditions
    #[cfg(unix)]
    {
        set_secure_permissions_atomically(canonical_path)?;
    }

    #[cfg(windows)]
    {
        // Ensure the file exists so ACLs can be applied deterministically.
        // Use create_new to avoid clobbering an existing file.
        if !canonical_path.exists() {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(canonical_path)
                .map_err(|e| {
                    anyhow::anyhow!("Failed to create SQLite database file for ACL hardening: {e}")
                })?;
        }

        // Refuse to operate on symlinks.
        let metadata = std::fs::symlink_metadata(canonical_path)?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!("Database file path must not be a symlink"));
        }

        if !metadata.is_file() {
            return Err(anyhow::anyhow!("Expected file but found non-file"));
        }

        set_restrictive_windows_acl(canonical_path)?;

        if let Some(parent) = canonical_path.parent() {
            if parent.exists() {
                set_restrictive_windows_acl(parent)?;
            }
        }
    }

    Ok(())
}

// Define the set of characters that need to be percent-encoded in file paths
pub const SQLITE_PATH_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'}');

/// Establishes a connection to the database
///
/// # Errors
///
/// This function will return an error if:
/// - Connection to the primary database fails and fallback is disabled
/// - Connection to the fallback `SQLite` database fails
pub async fn establish_connection(db_url: &str) -> Result<DatabaseConnection, anyhow::Error> {
    let db_kind = if db_url.starts_with("postgres://") || db_url.starts_with("postgresql://") {
        "PostgreSQL"
    } else if db_url.starts_with("sqlite:") {
        "SQLite"
    } else {
        "Database"
    };

    info!("Attempting to connect to {db_kind}");

    // Apply security hardening for SQLite databases
    apply_sqlite_security_hardening(db_url)?;

    match Database::connect(db_url).await {
        Ok(conn) => handle_successful_connection(conn, db_url),
        Err(e) => handle_connection_failure(e, db_url).await,
    }
}

///
/// # Errors
///
/// Returns an error if:
/// - The database URL is not a `SQLite` URL
/// - There are filesystem permission issues during hardening
pub fn apply_sqlite_security_hardening(db_url: &str) -> Result<(), anyhow::Error> {
    if db_url.starts_with("sqlite:") {
        #[cfg(unix)]
        {
            // Apply the same security hardening used for fallback databases to primary connections
            ensure_secure_sqlite_permissions(db_url)?;
        }

        #[cfg(windows)]
        {
            apply_windows_sqlite_hardening(db_url)?;
        }
    }
    Ok(())
}

/// Apply Windows-specific security hardening for SQLite connections
#[cfg(windows)]
fn apply_windows_sqlite_hardening(db_url: &str) -> Result<(), anyhow::Error> {
    // Extract the file path from the SQLite URL
    let path_str = if let Some(p) = db_url.strip_prefix("sqlite://") {
        p
    } else if let Some(p) = db_url.strip_prefix("sqlite:") {
        p
    } else {
        // If it doesn't start with either prefix, return early
        return Ok(());
    };

    // Split the path and query parameters
    let path_part = path_str.split('?').next().unwrap_or(path_str);

    // Skip if it's a memory database
    if path_part != ":memory:" {
        // Support `file:` URIs by extracting the underlying filesystem path.
        let fs_path_part = if let Some(p) = path_part.strip_prefix("file:") {
            p
        } else {
            path_part
        };

        // Percent-decode in case the path is URI-escaped
        let decoded = percent_encoding::percent_decode_str(fs_path_part)
            .decode_utf8_lossy()
            .to_string();

        // Handle POSIX absolute paths commonly written as sqlite:///path/to/db
        // After stripping "sqlite://", an absolute path may still start with "/".
        let path = std::path::Path::new(&decoded);

        // ✅ FIX: Explicitly reject ParentDir components BEFORE any processing
        if path
            .components()
            .any(|comp| matches!(comp, std::path::Component::ParentDir))
        {
            return Err(anyhow::anyhow!(
                "Path must not contain parent directory references ('..')"
            ));
        }

        if path.is_dir() {
            return Err(anyhow::anyhow!(
                "SQLite database path must be a file, got directory"
            ));
        } else {
            // To prevent symlink attacks, we'll validate the entire path chain atomically
            let canonical_path = if path.exists() {
                // Check if the path is a symlink before canonicalizing to prevent symlink attacks
                let metadata = std::fs::symlink_metadata(path)?;
                if metadata.file_type().is_symlink() {
                    return Err(anyhow::anyhow!(
                        "Failed to set database file permissions: security violation - path must not be a symlink"
                    ));
                }
                // Use canonicalize to resolve any symbolic links in parent directories while keeping the file itself
                std::fs::canonicalize(path)?
            } else {
                // For non-existent paths, validate the parent path chain atomically
                // to prevent TOCTOU race conditions where symlinks could be created between
                // directory creation and canonicalization
                if let Some(parent) = path.parent() {
                    // Recursively validate the parent directory path to ensure no symlinks exist in the chain
                    let mut current_path = std::path::PathBuf::new();

                    // Build a component list that excludes Windows Prefix/Root, since we seed those separately.
                    let mut components: Vec<_> = parent
                        .components()
                        .filter(|c| {
                            !matches!(
                                c,
                                std::path::Component::Prefix(_) | std::path::Component::RootDir
                            )
                        })
                        .collect();

                    // Reverse the components to build the path from root to target
                    components.reverse();

                    // Seed `current_path` from the actual prefix/root components of `parent`
                    for c in parent.components() {
                        match c {
                            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                                current_path.push(c)
                            }
                            _ => break,
                        }
                    }

                    // Process components in reverse order (from root toward target)
                    for component in components.iter().rev() {
                        current_path.push(component);

                        // If this part of the path exists, verify it's not a symlink
                        if current_path.exists() {
                            let metadata = std::fs::symlink_metadata(&current_path)?;
                            if metadata.file_type().is_symlink() {
                                return Err(anyhow::anyhow!(
                                    "Failed to validate database path: parent directory contains a symlink which is not allowed for security reasons"
                                ));
                            }

                            if !metadata.is_dir() {
                                return Err(anyhow::anyhow!(
                                    "Failed to create database directory: expected directory but found file"
                                ));
                            }
                        } else {
                            // If the directory doesn't exist yet, create it safely
                            std::fs::create_dir(&current_path)?;

                            // Verify that what we created is indeed a directory and not a symlink
                            let metadata = std::fs::symlink_metadata(&current_path)?;
                            if metadata.file_type().is_symlink() {
                                return Err(anyhow::anyhow!(
                                    "Failed to create database directory: security violation - directory was replaced with symlink during creation"
                                ));
                            }

                            if !metadata.is_dir() {
                                return Err(anyhow::anyhow!(
                                    "Failed to validate database path: expected directory but found file"
                                ));
                            }
                        }
                    }

                    // Now that the parent chain is safely created/validated, canonicalize the parent directory
                    let parent_canonical = std::fs::canonicalize(&current_path)?;

                    let file_name = path.file_name().ok_or_else(|| {
                        anyhow::anyhow!("SQLite database path must include a filename")
                    })?;
                    parent_canonical.join(file_name)
                } else {
                    return Err(anyhow::anyhow!(
                        "SQLite database path must include a parent directory"
                    ));
                }
            };

            // Apply restrictive ACLs to the database file
            if canonical_path.exists() {
                if let Err(e) = set_restrictive_windows_acl(&canonical_path) {
                    tracing::warn!("Failed to set restrictive ACLs on SQLite file. Error: {e}");
                }
            }

            // Also apply ACLs to the parent directory if it exists
            if let Some(parent_dir) = canonical_path.parent() {
                if let Err(e) = set_restrictive_windows_acl(parent_dir) {
                    tracing::warn!(
                        "Failed to set restrictive ACLs on parent directory. Error: {e}"
                    );
                }
            }
        }
    }
    Ok(())
}

/// Handle successful database connection
fn handle_successful_connection(
    conn: DatabaseConnection,
    db_url: &str,
) -> Result<DatabaseConnection, anyhow::Error> {
    // Determine database type from URL for accurate logging
    let db_type = if db_url.starts_with("postgres://") || db_url.starts_with("postgresql://") {
        "PostgreSQL"
    } else if db_url.starts_with("sqlite:") {
        "SQLite"
    } else {
        "Database"
    };
    info!("Successfully connected to {db_type}");

    // Ensure primary SQLite DB file perms are restrictive even when created on first connect.
    #[cfg(unix)]
    if db_url.starts_with("sqlite:") {
        // Reuse the hardened parser that correctly supports both `sqlite://...` and `sqlite:...`.
        ensure_secure_sqlite_permissions(db_url)?;
    }

    // On Windows, ensure the DB file receives restrictive ACLs even if it was created during connect.
    #[cfg(windows)]
    if db_url.starts_with("sqlite:") {
        // Reuse the centralized hardening logic to ensure canonicalization + symlink checks.
        if let Err(e) = apply_windows_sqlite_hardening(db_url) {
            tracing::warn!("Windows SQLite hardening after connect failed: {e}");
        }
    }

    Ok(conn)
}

/// Handle database connection failure with fallback logic
async fn handle_connection_failure(
    e: sea_orm::DbErr,
    db_url: &str,
) -> Result<DatabaseConnection, anyhow::Error> {
    // Only fall back when the configured URL is a "primary" network DB.
    // If the configured URL is already SQLite, returning the error is safer than silently
    // creating/using a different file.
    let is_sqlite = db_url.starts_with("sqlite:");
    if is_sqlite {
        // Log database connection failure without exposing sensitive connection details
        warn!(
            db_type = "SQLite",
            action = "connect",
            outcome = "failure",
            reason = "connection_error"
        );
        return Err(e.into());
    }

    let allow_fallback = std::env::var("ALLOW_SQLITE_FALLBACK")
        .ok()
        .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");

    if !allow_fallback {
        // Log primary database connection failure without exposing sensitive details
        warn!(
            db_type = if db_url.starts_with("postgres://") || db_url.starts_with("postgresql://") {
                "PostgreSQL"
            } else {
                "Primary database"
            },
            action = "connect",
            outcome = "failure",
            reason = "fallback_disabled"
        );
        return Err(e.into());
    }

    // Log primary database connection failure before falling back to SQLite
    warn!(
        db_type = if db_url.starts_with("postgres://") || db_url.starts_with("postgresql://") {
            "PostgreSQL"
        } else {
            "Primary database"
        },
        action = "connect",
        outcome = "failure",
        reason = "fallback_initiated"
    );

    handle_db_connection_fallback().await
}

/// Helper function to handle database connection fallback to `SQLite`
async fn handle_db_connection_fallback() -> Result<DatabaseConnection, anyhow::Error> {
    // 1. Resolve and validate the initial fallback path
    let fallback_path = resolve_and_validate_fallback_path()?;

    // 2. Ensure the parent directory exists and is writable, possibly falling back to temp
    let absolute_file = ensure_writable_parent(&fallback_path)?;

    // 3. Securely create the database file and set permissions
    securely_create_db_file(&absolute_file)?;

    // 4. Encode the path for the connection string
    let sqlite_path = encode_path_for_sqlite_url(&absolute_file)?;

    info!("Connecting to SQLite fallback database");
    let conn = Database::connect(&sqlite_path).await?;

    // On Windows, apply alternative security measures
    #[cfg(windows)]
    {
        // On Windows, ensure the file exists and apply restrictive ACLs
        if absolute_file.exists() {
            // Apply restrictive ACLs to the database file to limit access to the current user only
            if let Err(e) = set_restrictive_windows_acl(&absolute_file) {
                tracing::warn!(
                    "Failed to set restrictive ACLs on SQLite file: {}. Error: {e}",
                    absolute_file
                        .file_name()
                        .unwrap_or(std::ffi::OsStr::new("unknown"))
                        .to_string_lossy()
                );
            }
        } else {
            tracing::warn!("SQLite fallback file does not exist after connection attempt");
        }

        // Also apply ACLs to the parent directory if it exists
        if let Some(parent_dir) = absolute_file.parent() {
            if let Err(e) = set_restrictive_windows_acl(parent_dir) {
                tracing::warn!("Failed to set restrictive ACLs on parent directory. Error: {e}");
            }
        }
    }

    Ok(conn)
}

/// Resolve and validate the initial fallback path
/// Resolves and validates the fallback path for `SQLite` database
///
/// # Errors
///
/// Returns an error if:
/// - The `SQLITE_FALLBACK_PATH` environment variable is not set
/// - The path contains parent directory references ('..')
/// - Absolute paths are used without `ALLOW_ABSOLUTE_FALLBACK_PATH` set
pub fn resolve_and_validate_fallback_path() -> Result<std::path::PathBuf, anyhow::Error> {
    // Require an explicit path to avoid writing into an unknown CWD.
    // This prevents data from being stored in potentially insecure locations.
    let fallback_file = std::env::var("SQLITE_FALLBACK_PATH")
        .map_err(|_| {
            let msg = "Critical: SQLITE_FALLBACK_PATH environment variable not set. Fallback requires explicit path for security.";
            error!("{msg}");
            anyhow::anyhow!(msg)
        })?;

    // Sanitize the fallback file path to prevent directory traversal.
    let fallback_path = std::path::PathBuf::from(&fallback_file);

    // Check for path traversal attempts ('..') in all paths, not just relative ones
    // Absolute paths can also contain .. components that could be used for path traversal attacks
    if fallback_path
        .components()
        .any(|comp| matches!(comp, std::path::Component::ParentDir))
    {
        return Err(anyhow::anyhow!(
            "SQLITE_FALLBACK_PATH must not contain parent directory references ('..')"
        ));
    }

    // Use centralized PathValidator for all path validation
    let validator = PathValidator::new();

    // Validate the path using the centralized validator
    validator
        .validate(&fallback_path)
        .map_err(|e| anyhow::anyhow!("Path validation failed: {e}"))?;

    // Handle absolute vs relative paths appropriately
    // For security, only allow relative paths by default to prevent arbitrary file creation.
    // Absolute paths require explicit opt-in via ALLOW_ABSOLUTE_FALLBACK_PATH environment variable.
    let allow_absolute_paths = std::env::var("ALLOW_ABSOLUTE_FALLBACK_PATH")
        .ok()
        .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");

    if fallback_path.is_absolute() && !allow_absolute_paths {
        return Err(anyhow::anyhow!(
            "Absolute SQLITE_FALLBACK_PATH requires explicit opt-in via ALLOW_ABSOLUTE_FALLBACK_PATH=true"
        ));
    }

    Ok(fallback_path)
}

/// Ensure the parent directory exists and is writable, possibly falling back to temp
fn ensure_writable_parent(
    fallback_path: &std::path::Path,
) -> Result<std::path::PathBuf, anyhow::Error> {
    let base_dir = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());

    // For security, if absolute paths are allowed, we still ensure the file is a regular file
    let absolute_file_path = if fallback_path.is_absolute()
        && std::env::var("ALLOW_ABSOLUTE_FALLBACK_PATH")
            .ok()
            .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1")
    {
        // Additional check: ensure this is a regular file path, not a special file
        // Check for symlinks first to prevent symlink attacks
        let metadata = std::fs::symlink_metadata(fallback_path);
        if let Ok(metadata) = metadata {
            if metadata.file_type().is_symlink() {
                return Err(anyhow::anyhow!(
                    "SQLITE_FALLBACK_PATH must not be a symlink"
                ));
            } else if !metadata.is_file() {
                return Err(anyhow::anyhow!(
                    "SQLITE_FALLBACK_PATH points to a non-regular file (e.g., directory, symlink to special file)"
                ));
            }
        }
        PathBuf::from(fallback_path)
    } else {
        base_dir.join(fallback_path)
    };

    // Ensure the parent directory exists; if not writable, use an app-specific temp directory.
    let _parent_dir = absolute_file_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid SQLITE_FALLBACK_PATH"))?;

    // Use centralized PathValidator for path validation and canonicalization
    // This is critical to prevent TOCTOU attacks - validate/canonicalize before any file creation
    let validator_config = crate::security::ValidationConfig {
        allowed_directories: vec![
            std::env::current_dir()?,
            dirs::data_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine data directory"))?
                .join("Aroeira"),
        ],
        ..Default::default()
    };

    let validator = PathValidator::with_config(validator_config);

    // Validate and canonicalize the path BEFORE attempting any file operations
    // This prevents symlink TOCTOU vulnerabilities
    let validated_path = validator
        .validate_and_canonicalize(&absolute_file_path)
        .map_err(|e| anyhow::anyhow!("Path validation failed: {e}"))?;

    // Now that path is validated and canonicalized, get the parent directory
    let parent_dir_validated = validated_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid validated path - no parent directory"))?;

    // Create the parent directory if it doesn't exist
    let writable = std::fs::create_dir_all(parent_dir_validated)
        .ok()
        .and_then(|()| {
            let unique = format!(
                ".Aroeira_write_probe_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            );
            let probe = parent_dir_validated.join(unique);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&probe)
                .map_or(None, |f| {
                    drop(f); // ensure the handle is closed before removal (important on Windows)
                    let _ = std::fs::remove_file(&probe);
                    Some(())
                })
        })
        .is_some();

    if writable {
        Ok(validated_path)
    } else {
        // If the validated path isn't writable, fall back to temp but still validate that
        let fallback_path = handle_fallback_to_temp(fallback_path)?;

        // Validate the fallback path too
        let final_fallback_path = validator
            .validate_and_canonicalize(&fallback_path)
            .map_err(|e| anyhow::anyhow!("Fallback path validation failed: {e}"))?;

        Ok(final_fallback_path)
    }
}

/// Handle fallback to temp directory when parent is not writable
///
/// # Errors
///
/// Returns an error if:
/// - Unable to create the app-specific temp directory
/// - The fallback path doesn't include a filename
pub fn handle_fallback_to_temp(
    fallback_path: &std::path::Path,
) -> Result<std::path::PathBuf, anyhow::Error> {
    tracing::warn!("Fallback directory not writable; using temp directory for SQLite fallback");

    // Use an app-specific subdirectory under temp to avoid writing into the global temp root.
    // This provides better isolation than using the system temp directory directly.
    let chosen_base_dir = std::env::temp_dir().join("Aroeira_app_data");

    // Check if the chosen temp directory is also a symlink to prevent symlink attacks
    let temp_path = std::env::temp_dir().join("Aroeira_app_data");
    if temp_path.exists() {
        let metadata = std::fs::symlink_metadata(&temp_path)?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!(
                "Security error: temp directory 'Aroeira_app_data' is a symlink, refusing to use for security"
            ));
        }
    }

    if let Err(dir_err) = std::fs::create_dir_all(&chosen_base_dir) {
        return Err(anyhow::anyhow!(
            "Could not create app temp directory: {dir_err}. Giving up on fallback."
        ));
    }

    // Set restrictive permissions on the app-specific temp directory
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(
            &chosen_base_dir,
            std::fs::Permissions::from_mode(0o700), // rwx------ (owner only)
        ) {
            tracing::warn!(
                error = ?e,
                "Could not set restrictive permissions on app temp directory"
            );
        }
    }

    // For absolute paths, we should only use the filename in the new location
    let fallback_file_name = fallback_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("SQLITE_FALLBACK_PATH must include a filename"))?;

    Ok(chosen_base_dir.join(fallback_file_name))
}

/// Validate that relative paths are contained within the expected directory
///
/// # Errors
///
/// Returns an error if:
/// - The absolute file path resolves outside the expected directory
pub fn validate_relative_path_containment(
    absolute_file: &std::path::Path,
    _original_file_path: &std::path::Path,
    base_dir: &std::path::Path,
) -> Result<(), anyhow::Error> {
    let expected_dir = std::fs::canonicalize(base_dir)?;
    if !absolute_file.starts_with(&expected_dir) {
        return Err(anyhow::anyhow!(
            "SQLITE_FALLBACK_PATH resolves outside of the expected directory"
        ));
    }

    // On Unix-like systems, ensure the app temp directory has appropriate permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if base_dir.starts_with(std::env::temp_dir())
            && std::fs::set_permissions(&expected_dir, std::fs::Permissions::from_mode(0o700))
                .is_err()
        {
            tracing::warn!("Could not set permissions on app temp directory");
        }
    }

    Ok(())
}

/// Securely create the database file and set permissions
///
/// # Errors
///
/// Returns an error if:
/// - The path is a symlink (security risk)
/// - There are filesystem permission issues during creation
pub fn securely_create_db_file(absolute_file: &std::path::Path) -> Result<(), anyhow::Error> {
    // Check if file already exists and is a symlink before doing anything
    if absolute_file.exists() {
        let metadata = std::fs::symlink_metadata(absolute_file)?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!(
                "SQLite fallback path must not be a symlink"
            ));
        }
    }

    // Use SecureFileCreator for atomic file creation without TOCTOU window
    let creator = SecureFileCreator::new();

    // Create the file atomically using the secure creator
    match creator.create_file(absolute_file) {
        Ok(_) => {
            // The SecureFileCreator handles permission setting internally, but we'll double-check
            // on existing files to ensure they have proper permissions
            if absolute_file.exists() {
                #[cfg(unix)]
                {
                    // Set restrictive permissions on the file to ensure security
                    set_file_permissions_600(absolute_file);
                }

                #[cfg(windows)]
                {
                    // On Windows, apply restrictive ACLs to the file
                    if let Err(acl_err) = set_restrictive_windows_acl(absolute_file) {
                        tracing::warn!(
                            "Failed to set restrictive ACLs on SQLite file. Error: {acl_err}"
                        );
                    }
                }
            }

            Ok(())
        }
        Err(e) => {
            // If the file now exists (e.g., created concurrently), re-validate it's not a symlink and harden it.
            if absolute_file.exists() {
                let metadata = std::fs::symlink_metadata(absolute_file)?;
                if metadata.file_type().is_symlink() {
                    return Err(anyhow::anyhow!(
                        "SQLite fallback path must not be a symlink"
                    ));
                }

                #[cfg(unix)]
                {
                    set_file_permissions_600(absolute_file);
                }

                #[cfg(windows)]
                {
                    if let Err(acl_err) = set_restrictive_windows_acl(absolute_file) {
                        tracing::warn!(
                            "Failed to set restrictive ACLs on SQLite file. Error: {acl_err}"
                        );
                    }
                }

                return Ok(());
            }

            match e {
                crate::security::SecurityError::SymlinkDetected => Err(anyhow::anyhow!(
                    "SQLite fallback path must not be a symlink"
                )),
                _ => Err(anyhow::anyhow!("Failed to create database file: {e}")),
            }
        }
    }
}

/// Encode the path for the `SQLite` URL
///
/// # Errors
///
/// Returns an error if:
/// - The path contains reserved URL characters (?, #, \0)
pub fn encode_path_for_sqlite_url(
    absolute_file: &std::path::Path,
) -> Result<String, anyhow::Error> {
    let normalized = absolute_file.to_string_lossy().replace('\\', "/");

    // Reject characters that would change URL semantics and could break connection parsing.
    if normalized.contains('?') || normalized.contains('#') || normalized.contains('\0') {
        return Err(anyhow::anyhow!(
            "Invalid SQLite fallback path: contains reserved URL characters or NUL"
        ));
    }

    #[cfg(windows)]
    {
        // If the path looks like a Windows drive path (e.g. "C:/..."), keep the drive colon unencoded
        // and use the sqlite:/// URI form which is broadly supported.
        if normalized.len() >= 3
            && normalized.as_bytes()[1] == b':'
            && normalized.as_bytes()[2] == b'/'
            && normalized.as_bytes()[0].is_ascii_alphabetic()
        {
            let drive = &normalized[..2]; // "C:"
            let rest = &normalized[2..]; // "/path/..."
            let encoded_rest = utf8_percent_encode(rest, SQLITE_PATH_ENCODE_SET).to_string();
            return Ok(format!("sqlite:///{drive}{encoded_rest}?mode=rwc"));
        }

        // Non-drive paths: encode normally.
        let encoded = utf8_percent_encode(&normalized, SQLITE_PATH_ENCODE_SET).to_string();
        Ok(format!("sqlite:{encoded}?mode=rwc"))
    }

    #[cfg(not(windows))]
    {
        let encoded = utf8_percent_encode(&normalized, SQLITE_PATH_ENCODE_SET).to_string();
        // Use an explicit absolute-path form when the filesystem path is absolute.
        if normalized.starts_with('/') {
            // Trim the leading slash from the encoded path to avoid double slashes
            let encoded_trimmed = encoded.trim_start_matches('/');
            Ok(format!("sqlite:///{encoded_trimmed}?mode=rwc"))
        } else {
            Ok(format!("sqlite:{encoded}?mode=rwc"))
        }
    }
}

// Define specific rights constants for Windows ACLs instead of using generic rights
// These provide more granular control compared to GENERIC_ALL (0xF003F)
#[cfg(windows)]
const FILE_ALL_ACCESS: u32 = 0x001F01FF; // Full access rights for files: Read, Write, Execute, Delete, Change permissions, Take ownership
#[cfg(windows)]
const DIRECTORY_ALL_ACCESS: u32 = 0x001F000F; // Full access rights for directories: List, AddFile, AddSubdir, DeleteChild, ReadAttr, WriteAttr, Execute, Delete, ReadPerm, ChangePerm, Take Ownership

/// Helper function to get the last error message from Windows API
#[cfg(windows)]
unsafe fn get_last_error_message() -> String {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::ptr;
    use windows_sys::Win32::System::Diagnostics::Debug::FormatMessageW;
    use windows_sys::Win32::System::Diagnostics::Debug::GetLastError;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

    let error_code = GetLastError();
    if error_code == 0 {
        return "No error".to_string();
    }

    let mut buffer: [u16; 1024] = [0; 1024];
    let result = FormatMessageW(
        0x00001000 | 0x00000200, // FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
        ptr::null(),
        error_code,
        0, // Default language
        buffer.as_mut_ptr(),
        buffer.len() as u32,
        ptr::null(),
    );

    if result == 0 {
        return format!("Error code: {}", error_code);
    }

    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    let message = OsString::from_wide(&buffer[..len]);
    message.to_string_lossy().to_string()
}

#[cfg(windows)]
/// Sets restrictive ACLs on a file or directory to allow access to the current user and essential system accounts
///
/// Security Properties:
/// - Creates a new ACL that explicitly defines allowed access (no inherited permissions from parent)
/// - For files: Access is limited to current user, SYSTEM, and Administrators with no inheritance (NO_INHERITANCE)
/// - For directories: Access is limited to current user, SYSTEM, and Administrators with proper inheritance flags (SUB_CONTAINERS_AND_OBJECTS_INHERIT)
/// - Uses specific access rights (FILE_ALL_ACCESS/DIRECTORY_ALL_ACCESS) instead of generic rights (GENERIC_ALL)
/// - Explicitly disables inheritance from parent directories to ensure truly restrictive permissions
pub fn set_restrictive_windows_acl(path: &std::path::Path) -> Result<(), anyhow::Error> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, PCWSTR, PSID},
        Security::{
            ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EXPLICIT_ACCESS_W, GetLengthSid,
            GetTokenInformation, IsValidSid, LocalFree, NO_INHERITANCE, NO_MULTIPLE_TRUSTEE,
            OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION, SET_ACCESS,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT, SetEntriesInAclW, SetNamedSecurityInfoW,
            TRUSTEE_IS_GROUP, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
        },
        Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_TRAVERSE,
        },
        System::SystemServices::DELETE,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    // RAII guard to ensure LocalFree is always called
    struct SafeLocalFree(isize);
    impl Drop for SafeLocalFree {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    // Convert path to wide string for Windows API
    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Determine if path is a file or directory to set appropriate inheritance flags
    let is_directory = path.is_dir();

    unsafe {
        // Get current process token to retrieve current user's SID
        let mut token_handle: HANDLE = 0;
        let process_handle = GetCurrentProcess();

        if OpenProcessToken(
            process_handle,
            0x0008, /* TOKEN_QUERY */
            &mut token_handle,
        ) == 0
        {
            return Err(anyhow::anyhow!(
                "Failed to open process token: {}",
                get_last_error_message()
            ));
        }

        // RAII guard for token handle
        struct SafeCloseHandle(HANDLE);
        impl Drop for SafeCloseHandle {
            fn drop(&mut self) {
                if self.0 != 0 {
                    unsafe {
                        CloseHandle(self.0);
                    }
                }
            }
        }
        let _token_guard = SafeCloseHandle(token_handle);

        // Get size of token user information
        let mut token_info_size = 0u32;
        let result = GetTokenInformation(
            token_handle,
            1, // TokenUser = 1
            std::ptr::null_mut(),
            0,
            &mut token_info_size,
        );

        // Verify the call failed with ERROR_INSUFFICIENT_BUFFER (122)
        if result != 0 || std::io::Error::last_os_error().raw_os_error() != Some(122) {
            return Err(anyhow::anyhow!(
                "Unexpected result from GetTokenInformation: {}, error: {:?}",
                result,
                std::io::Error::last_os_error()
            ));
        }

        // Allocate buffer for token user information
        let mut token_user_buffer = vec![0u8; token_info_size as usize];
        let token_user_ptr = token_user_buffer.as_mut_ptr() as *mut std::ffi::c_void;

        // Get token user information
        if GetTokenInformation(
            token_handle,
            1, // TokenUser
            token_user_ptr,
            token_info_size,
            &mut token_info_size,
        ) == 0
        {
            return Err(anyhow::anyhow!(
                "Failed to get token user information: {}",
                get_last_error_message()
            ));
        }

        // Extract the user SID from the token information and validate it
        let token_user = &*(token_user_ptr as *const windows_sys::Win32::Security::TOKEN_USER);
        let user_sid = token_user.User.Sid;

        // Validate the SID before using it
        if user_sid.is_null() {
            return Err(anyhow::anyhow!("Invalid user SID: null pointer"));
        }

        if IsValidSid(user_sid) == 0 {
            return Err(anyhow::anyhow!("Invalid SID structure"));
        }

        // Get SID length for additional validation
        let sid_length = GetLengthSid(user_sid);
        if sid_length == 0 {
            return Err(anyhow::anyhow!("Invalid SID length"));
        }

        // Get SYSTEM and Administrators SIDs for essential access
        let mut system_sid: PSID = std::ptr::null_mut();
        let mut admin_sid: PSID = std::ptr::null_mut();

        // Create SYSTEM SID (well-known SID S-1-5-18)
        let mut sid_buffer_system = [0u8; 128];
        let mut sid_size_system = sid_buffer_system.len() as u32;

        if windows_sys::Win32::Security::CreateWellKnownSid(
            windows_sys::Win32::Security::WinBuiltinSystemSid,
            std::ptr::null_mut(),
            sid_buffer_system.as_mut_ptr() as PSID,
            &mut sid_size_system,
        ) != 0
        {
            system_sid = sid_buffer_system.as_mut_ptr() as PSID;
        } else {
            tracing::warn!("Could not create SYSTEM SID, continuing with user-only ACL");
        }

        // Create Administrators SID (well-known SID S-1-5-32-544)
        let mut admin_sid_buffer = [0u8; 128];
        let mut admin_sid_size = admin_sid_buffer.len() as u32;

        if windows_sys::Win32::Security::CreateWellKnownSid(
            windows_sys::Win32::Security::WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            admin_sid_buffer.as_mut_ptr() as PSID,
            &mut admin_sid_size,
        ) != 0
        {
            admin_sid = admin_sid_buffer.as_mut_ptr() as PSID;
        } else {
            tracing::warn!("Could not create Administrators SID, continuing with user-only ACL");
        }

        // Create explicit access structure for the current user with full access
        let mut user_trustee: TRUSTEE_W = std::mem::zeroed();
        user_trustee.pMultipleTrustee = std::ptr::null_mut();
        user_trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        user_trustee.TrusteeForm = TRUSTEE_IS_SID;
        user_trustee.TrusteeType = TRUSTEE_IS_USER;
        user_trustee.ptstrName = user_sid as *mut _;

        let mut user_ea: EXPLICIT_ACCESS_W = std::mem::zeroed();
        // Set appropriate permissions based on file vs directory
        if is_directory {
            // For directories, use specific directory rights
            user_ea.grfAccessPermissions = DIRECTORY_ALL_ACCESS;
            // Use SUB_CONTAINERS_AND_OBJECTS_INHERIT to ensure child files/directories inherit permissions
            user_ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        } else {
            // For files, use specific file rights
            user_ea.grfAccessPermissions = FILE_ALL_ACCESS;
            user_ea.grfInheritance = NO_INHERITANCE;
        }
        user_ea.grfAccessMode = SET_ACCESS;
        user_ea.Trustee = user_trustee;

        // Prepare array of explicit access entries - always include user
        let mut eas = vec![user_ea];

        // Add SYSTEM access if available (essential for system operations)
        if !system_sid.is_null() {
            let mut system_trustee: TRUSTEE_W = std::mem::zeroed();
            system_trustee.pMultipleTrustee = std::ptr::null_mut();
            system_trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
            system_trustee.TrusteeForm = TRUSTEE_IS_SID;
            system_trustee.TrusteeType = TRUSTEE_IS_GROUP;
            system_trustee.ptstrName = system_sid as *mut _;

            let mut system_ea: EXPLICIT_ACCESS_W = std::mem::zeroed();
            // Use specific rights based on object type for SYSTEM account
            system_ea.grfAccessPermissions = if is_directory {
                DIRECTORY_ALL_ACCESS
            } else {
                FILE_ALL_ACCESS
            };
            // For SYSTEM, use inheritance appropriate for the object type
            system_ea.grfInheritance = if is_directory {
                CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
            } else {
                NO_INHERITANCE
            };
            system_ea.grfAccessMode = SET_ACCESS;
            system_ea.Trustee = system_trustee;

            eas.push(system_ea);
        }

        // Add Administrators access if available (for administrative tasks)
        if !admin_sid.is_null() {
            let mut admin_trustee: TRUSTEE_W = std::mem::zeroed();
            admin_trustee.pMultipleTrustee = std::ptr::null_mut();
            admin_trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
            admin_trustee.TrusteeForm = TRUSTEE_IS_SID;
            admin_trustee.TrusteeType = TRUSTEE_IS_GROUP;
            admin_trustee.ptstrName = admin_sid as *mut _;

            let mut admin_ea: EXPLICIT_ACCESS_W = std::mem::zeroed();
            // Use specific rights based on object type for Administrators account
            admin_ea.grfAccessPermissions = if is_directory {
                DIRECTORY_ALL_ACCESS
            } else {
                FILE_ALL_ACCESS
            };
            // For Administrators, use inheritance appropriate for the object type
            admin_ea.grfInheritance = if is_directory {
                CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
            } else {
                NO_INHERITANCE
            };
            admin_ea.grfAccessMode = SET_ACCESS;
            admin_ea.Trustee = admin_trustee;

            eas.push(admin_ea);
        }

        // Create a new ACL with the access entries
        let mut new_dacl = std::ptr::null_mut();
        let result = SetEntriesInAclW(
            eas.len() as u32,     // Count of entries
            eas.as_ptr(),         // Array of explicit access entries
            std::ptr::null_mut(), // Original ACL (null means create new ACL)
            &mut new_dacl,        // Output ACL
        );

        if result != ERROR_SUCCESS {
            return Err(anyhow::anyhow!(
                "Failed to create ACL, error code: {}: {}",
                result,
                get_last_error_message()
            ));
        }

        // Ensure new_dacl is freed when we go out of scope, even if SetNamedSecurityInfoW fails
        let _acl_guard = SafeLocalFree(new_dacl as isize);

        // Apply the new ACL to the file/directory using SetNamedSecurityInfoW
        // Use PROTECTED_DACL_SECURITY_INFORMATION flag to prevent inheritance from parent
        let security_information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;

        let result = SetNamedSecurityInfoW(
            wide_path.as_ptr() as PCWSTR,
            windows_sys::Win32::Security::SE_FILE_OBJECT, // Use the constant instead of hardcoded value
            security_information,
            std::ptr::null_mut(), // Owner (keep current owner)
            std::ptr::null_mut(), // Group (keep current group)
            new_dacl as *mut ACL, // New DACL (this replaces the existing ACL)
            std::ptr::null_mut(), // SACL (keep current SACL)
        );

        if result != ERROR_SUCCESS {
            return Err(anyhow::anyhow!(
                "Failed to set file security, error code: {}: {}",
                result,
                get_last_error_message()
            ));
        }

        tracing::info!(
            "Applied restrictive ACLs to path: {} (directory: {}, protected from inheritance: true)",
            path.file_name()
                .unwrap_or(std::ffi::OsStr::new("unknown"))
                .to_string_lossy(),
            is_directory
        );

        // Verification step: validate that the ACL was applied correctly
        validate_applied_acl(path, is_directory)?;

        Ok(())
    }
}

/// Validates that the ACL was applied correctly and is truly restrictive
/// Additional security validation to prevent privilege escalation (ACL-006)
#[cfg(windows)]
/// Validates that the ACL was applied correctly and is truly restrictive
/// Additional security validation to prevent privilege escalation (ACL-006)
#[cfg(windows)]
pub(crate) fn validate_applied_acl(
    path: &std::path::Path,
    is_directory: bool,
) -> Result<(), anyhow::Error> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{ERROR_SUCCESS, PSECURITY_DESCRIPTOR},
        Security::{
            ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACE_HEADER,
            ACL_INFORMATION_CLASS, ACL_REVISION_INFORMATION, ACL_SIZE_INFORMATION,
            DACL_SECURITY_INFORMATION, GetAclInformation, GetLengthSid, GetNamedSecurityInfoW,
            IsValidSid,
        },
    };

    // Convert path to wide string for Windows API
    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // RAII guard to ensure LocalFree is always called
        struct SafeLocalFree(isize);
        impl Drop for SafeLocalFree {
            fn drop(&mut self) {
                if self.0 != 0 {
                    unsafe { windows_sys::Win32::System::Memory::LocalFree(self.0) };
                }
            }
        }

        let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        let mut dacl_present: i32 = 0;
        let mut dacl_defaulted: i32 = 0;

        // ✅ FIX: Use GetNamedSecurityInfoW for paths, GetSecurityInfo for handles
        let result = windows_sys::Win32::Security::GetNamedSecurityInfoW(
            wide_path.as_ptr() as windows_sys::Win32::Foundation::PCWSTR, // Correct: path as wide string
            windows_sys::Win32::Security::SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(), // Owner
            std::ptr::null_mut(), // Group
            &mut dacl,            // DACL
            std::ptr::null_mut(), // SACL
            &mut security_descriptor,
        );

        // Keep the security descriptor alive for the duration of validation,
        // since `dacl` points into it.
        let _sd_guard = SafeLocalFree(security_descriptor as isize);

        // OLD CODE REMOVED: No longer immediately freeing the security descriptor

        if result != ERROR_SUCCESS {
            return Err(anyhow::anyhow!(
                "Failed to retrieve security information for validation, error code: {}: {}",
                result,
                get_last_error_message()
            ));
        }

        if dacl.is_null() {
            return Err(anyhow::anyhow!("Retrieved DACL is null"));
        }

        // Get ACL size information
        let mut acl_size_info: ACL_SIZE_INFORMATION = std::mem::zeroed();
        let acl_size_result = GetAclInformation(
            dacl,
            &mut acl_size_info as *mut ACL_SIZE_INFORMATION as *mut std::ffi::c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            ACL_INFORMATION_CLASS(1), // AclSizeInformation
        );

        if acl_size_result == 0 {
            return Err(anyhow::anyhow!("Failed to get ACL size information"));
        }

        // Validate each ACE in the ACL
        for i in 0..acl_size_info.AceCount {
            let mut ace_ptr = std::ptr::null_mut();
            let get_ace_result = windows_sys::Win32::Security::GetAce(dacl, i, &mut ace_ptr);

            if get_ace_result == 0 {
                return Err(anyhow::anyhow!("Failed to get ACE at index {}", i));
            }

            let ace_header = &*(ace_ptr as *const ACE_HEADER);
            let ace_type = ace_header.AceType;

            // We only allow ACCESS_ALLOWED_ACE_TYPE in our restrictive ACL
            if ace_type != ACCESS_ALLOWED_ACE_TYPE && ace_type != ACCESS_DENIED_ACE_TYPE {
                return Err(anyhow::anyhow!(
                    "Found unexpected ACE type {} in ACL",
                    ace_type
                ));
            }

            if ace_type == ACCESS_ALLOWED_ACE_TYPE {
                let ace = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
                let sid_ptr = (&ace.SidStart as *const u8) as PSID;

                // Validate that the SID is valid
                if IsValidSid(sid_ptr) == 0 {
                    return Err(anyhow::anyhow!("Invalid SID found in ACL at index {}", i));
                }

                // Check SID length
                let sid_length = GetLengthSid(sid_ptr);
                if sid_length == 0 {
                    return Err(anyhow::anyhow!(
                        "Invalid SID length found in ACL at index {}",
                        i
                    ));
                }

                // Additional validation to prevent privilege escalation (ACL-006)
                // Check that the permissions granted are appropriate for the object type
                let access_mask = ace.Mask;

                // Validate that no overly permissive rights are granted
                // Check for GENERIC_ALL (0x10000000) which should not be used
                if access_mask & 0x10000000 != 0 {
                    return Err(anyhow::anyhow!(
                        "ACL contains overly permissive GENERIC_ALL rights at index {}",
                        i
                    ));
                }

                // For files, ensure that directory-specific permissions are not granted
                if !is_directory && (access_mask & 0x0004 /* ADD_SUBDIRECTORY */ != 0) {
                    return Err(anyhow::anyhow!(
                        "File ACL contains directory-specific permissions (ADD_SUBDIRECTORY) at index {}",
                        i
                    ));
                }
            }
        }

        tracing::info!(
            "ACL validation passed for path: {} (directory: {})",
            path.file_name()
                .unwrap_or(std::ffi::OsStr::new("unknown"))
                .to_string_lossy(),
            is_directory
        );
        Ok(())
    }
}
