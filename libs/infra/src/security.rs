//! Security module for preventing symlink attacks and secure file operations
//!
//! This module provides cross-platform utilities for:
//! - Atomic file creation without following symlinks
//! - Path validation to prevent symlink attacks
//! - Secure file/directory creation with restrictive permissions

use std::io::Seek;
use std::path::{Path, PathBuf};

// ============================================================================
// Error Types
// ============================================================================

/// Security errors for file operations
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Path validation failed: {message}")]
    PathValidationFailed { message: String },

    #[error("Symlink detected at path, refusing to proceed")]
    SymlinkDetected,

    #[error("File open failed: {message}")]
    FileOpenFailed { message: String },

    #[error("Directory creation failed: {message}")]
    DirectoryCreationFailed { message: String },

    #[error("Write operation failed: {message}")]
    WriteFailed { message: String },

    #[error("Permission setting failed: {message}")]
    PermissionSettingFailed { message: String },

    #[error("File already exists and fail_if_exists is set")]
    AlreadyExists,
}

impl From<ValidationError> for SecurityError {
    fn from(err: ValidationError) -> Self {
        match err {
            ValidationError::SymlinkDetected { .. } => Self::SymlinkDetected,
            ValidationError::PathTraversalDetected { .. }
            | ValidationError::PathTooDeep { .. }
            | ValidationError::MetadataFailed { .. }
            | ValidationError::InvalidCharacters { .. }
            | ValidationError::OutsideAllowedDirectory { .. } => Self::PathValidationFailed {
                message: err.to_string(),
            },
        }
    }
}

// ============================================================================
// Cross-Platform Symlink Prevention Trait
// ============================================================================

/// Platform-agnostic symlink prevention
pub trait SymlinkPrevention {
    /// Open file without following symlinks (atomic)
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened due to permission issues,
    /// the path is a symlink (when not allowed), or other filesystem errors.
    fn open_no_follow(&self, path: &Path) -> Result<std::fs::File, SecurityError>;

    /// Check if path is a symlink
    ///
    /// # Errors
    ///
    /// Returns an error if the path metadata cannot be accessed due to permission issues
    /// or other filesystem errors.
    fn is_symlink(&self, path: &Path) -> Result<bool, SecurityError>;

    /// Validate path and all parents are not symlinks
    ///
    /// # Errors
    ///
    /// Returns an error if a symlink is detected in the path or any parent directory,
    /// or if path metadata cannot be accessed due to permission issues or other
    /// filesystem errors.
    fn validate_path(&self, path: &Path) -> Result<(), SecurityError>;

    /// Open existing file without following symlinks (atomic)
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened, is not a regular file,
    /// or if it is a symlink (when not allowed).
    fn open_existing_no_follow(&self, path: &Path) -> Result<std::fs::File, SecurityError>;
}

// ============================================================================
// Unix Implementation
// ============================================================================

#[cfg(unix)]
pub struct UnixSymlinkPrevention;

#[cfg(unix)]
impl SymlinkPrevention for UnixSymlinkPrevention {
    fn open_no_follow(&self, path: &Path) -> Result<std::fs::File, SecurityError> {
        use std::os::unix::fs::OpenOptionsExt;

        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            // We use create_new(true) ensuring O_CREAT | O_EXCL.
            // This is critical to prevent TOCTOU (Time-of-Check Time-of-Use) race conditions
            // by ensuring atomic file creation. This guarantees that the permissions (mode)
            // we set are applied to a fresh file. If we allowed overwriting existing files,
            // we might be tricked into writing sensitive data to a file pre-created by an
            // attacker with wide permissions. While this enables a theoretical DoS
            // (pre-creating the file), integrity and confidentiality are prioritized here.
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    tracing::debug!(
                        error_kind = ?e.kind(),
                        error_message = %e.to_string(),
                        path_kind = "file",
                        "Secure file open failed: file already exists"
                    );
                    SecurityError::AlreadyExists
                } else {
                    tracing::debug!(
                        error_kind = ?e.kind(),
                        error_message = %e.to_string(),
                        path_kind = "file",
                        "Secure file open failed"
                    );
                    SecurityError::FileOpenFailed {
                        message: e.to_string(),
                    }
                }
            })
    }

    fn is_symlink(&self, path: &Path) -> Result<bool, SecurityError> {
        std::fs::symlink_metadata(path)
            .map(|meta| meta.file_type().is_symlink())
            .map_err(|e| SecurityError::PathValidationFailed {
                message: e.to_string(),
            })
    }

    fn validate_path(&self, path: &Path) -> Result<(), SecurityError> {
        // Validate all components
        let mut current = path;
        loop {
            match self.is_symlink(current) {
                Ok(true) | Err(_) => return Err(SecurityError::SymlinkDetected),
                Ok(false) => {}
            }
            match current.parent() {
                Some(parent) => current = parent,
                None => break,
            }
        }
        Ok(())
    }

    fn open_existing_no_follow(&self, path: &Path) -> Result<std::fs::File, SecurityError> {
        use std::os::unix::fs::OpenOptionsExt;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| SecurityError::FileOpenFailed {
                message: e.to_string(),
            })?;

        // Validate via the already-opened handle to avoid races/TOCTOU
        let meta = file.metadata().map_err(|e| SecurityError::FileOpenFailed {
            message: e.to_string(),
        })?;

        if !meta.is_file() {
            return Err(SecurityError::FileOpenFailed {
                message: "Target is not a regular file".to_string(),
            });
        }

        Ok(file)
    }
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(windows)]
pub struct WindowsSymlinkPrevention;

#[cfg(windows)]
impl SymlinkPrevention for WindowsSymlinkPrevention {
    fn open_no_follow(&self, path: &Path) -> Result<std::fs::File, SecurityError> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    tracing::debug!(
                        error_kind = ?e.kind(),
                        error_message = %e.to_string(),
                        path_kind = "file",
                        "Secure file open failed: file already exists"
                    );
                    SecurityError::AlreadyExists
                } else {
                    tracing::debug!(
                        error_kind = ?e.kind(),
                        error_message = %e.to_string(),
                        path_kind = "file",
                        "Secure file open failed"
                    );
                    SecurityError::FileOpenFailed {
                        message: e.to_string(),
                    }
                }
            })
    }

    fn is_symlink(&self, path: &Path) -> Result<bool, SecurityError> {
        std::fs::symlink_metadata(path)
            .map(|meta| meta.file_type().is_symlink())
            .map_err(|e| SecurityError::PathValidationFailed {
                message: e.to_string(),
            })
    }

    fn validate_path(&self, path: &Path) -> Result<(), SecurityError> {
        // Validate all components
        let mut current = path;
        loop {
            match self.is_symlink(current) {
                Ok(true) | Err(_) => return Err(SecurityError::SymlinkDetected),
                Ok(false) => {}
            }
            match current.parent() {
                Some(parent) => current = parent,
                None => break,
            }
        }
        Ok(())
    }

    fn open_existing_no_follow(&self, path: &Path) -> Result<std::fs::File, SecurityError> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|e| SecurityError::FileOpenFailed {
                message: e.to_string(),
            })?;

        // Platform Parity: Validate via handle to ensure it's a regular file
        let meta = file.metadata().map_err(|e| SecurityError::FileOpenFailed {
            message: e.to_string(),
        })?;

        if !meta.is_file() {
            return Err(SecurityError::FileOpenFailed {
                message: "Target is not a regular file".to_string(),
            });
        }

        Ok(file)
    }
}

// ============================================================================
// Path Validator Module
// ============================================================================

/// Configuration for path validation
#[derive(Clone, Debug)]
pub struct ValidationConfig {
    /// Whether to allow symlinks in the path
    pub allow_symlinks: bool,

    /// Whether to validate parent directories
    pub check_parents: bool,

    /// Allowed base directories (for containment)
    pub allowed_directories: Vec<PathBuf>,

    /// Maximum path depth to check
    pub max_depth: usize,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            allow_symlinks: false,
            check_parents: true,
            allowed_directories: vec![],
            max_depth: 32,
        }
    }
}

/// Result of path validation
#[derive(Clone, Debug)]
pub struct ValidationResult {
    /// The validated, canonicalized path
    pub canonical_path: PathBuf,

    /// Whether the path is within allowed directories
    pub is_contained: bool,

    /// Number of path components validated
    pub depth: usize,
}

/// Validation errors
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Path is a symlink, which is not allowed for security reasons")]
    SymlinkDetected { path: PathBuf },

    #[error("Path contains parent directory references ('..'), which is not allowed")]
    PathTraversalDetected { path: PathBuf },

    #[error("Path is outside of allowed directories")]
    OutsideAllowedDirectory { path: PathBuf },

    #[error("Path exceeds maximum depth of {max_depth}")]
    PathTooDeep { path: PathBuf, max_depth: usize },

    #[error("Failed to access path metadata: {reason}")]
    MetadataFailed { path: PathBuf, reason: String },

    #[error("Path contains invalid characters: {chars}")]
    InvalidCharacters { path: PathBuf, chars: String },
}

/// Path validator
pub struct PathValidator {
    config: ValidationConfig,
    symlink_prevention: Box<dyn SymlinkPrevention>,
}

impl Default for PathValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl PathValidator {
    /// Create a new path validator with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ValidationConfig::default())
    }

    /// Create a new path validator with custom configuration
    #[must_use]
    pub fn with_config(config: ValidationConfig) -> Self {
        #[cfg(unix)]
        let symlink_prevention: Box<dyn SymlinkPrevention> = Box::new(UnixSymlinkPrevention);

        #[cfg(windows)]
        let symlink_prevention: Box<dyn SymlinkPrevention> = Box::new(WindowsSymlinkPrevention);

        Self {
            config,
            symlink_prevention,
        }
    }

    /// Validate a path
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path contains traversal components ('..')
    /// - The path contains invalid characters (null bytes, control characters)
    /// - The path exceeds the maximum allowed depth
    /// - The path or parent directories are symlinks (when not allowed)
    /// - The path is outside of allowed directories (when specified)
    /// - Metadata access fails for any path components
    pub fn validate(&self, path: &Path) -> Result<ValidationResult, ValidationError> {
        // 1. Check for path traversal
        Self::check_path_traversal(path)?;

        // 2. Check for invalid characters
        Self::check_invalid_characters(path)?;

        // 3. Check path depth
        Self::check_path_depth(path, self.config.max_depth)?;

        // 4. Check for symlinks
        if !self.config.allow_symlinks {
            self.check_symlinks(path)?;
        }

        // 5. Check containment
        if !self.config.allowed_directories.is_empty() {
            self.check_containment(path)?;
        }

        // 6. Canonicalize path
        let canonical_path = Self::canonicalize_safe(path)?;

        Ok(ValidationResult {
            canonical_path: canonical_path.clone(),
            is_contained: self.is_contained(&canonical_path),
            depth: path.components().count(),
        })
    }

    /// Validate a path and return the canonicalized version
    ///
    /// # Errors
    ///
    /// Returns an error if the validation fails due to any of the reasons
    /// described in the `validate` method.
    pub fn validate_and_canonicalize(&self, path: &Path) -> Result<PathBuf, ValidationError> {
        let result = self.validate(path)?;
        Ok(result.canonical_path)
    }

    /// Check for path traversal attempts
    fn check_path_traversal(path: &Path) -> Result<(), ValidationError> {
        if path
            .components()
            .any(|comp| matches!(comp, std::path::Component::ParentDir))
        {
            return Err(ValidationError::PathTraversalDetected {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    /// Check for invalid characters
    fn check_invalid_characters(path: &Path) -> Result<(), ValidationError> {
        let path_str = path.to_string_lossy();

        // Check for null bytes
        if path_str.contains('\0') {
            return Err(ValidationError::InvalidCharacters {
                path: path.to_path_buf(),
                chars: "null byte".to_string(),
            });
        }

        // Check for control characters (except newline/tab in some contexts)
        if path_str
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return Err(ValidationError::InvalidCharacters {
                path: path.to_path_buf(),
                chars: "control characters".to_string(),
            });
        }

        Ok(())
    }

    /// Check path depth
    fn check_path_depth(path: &Path, max_depth: usize) -> Result<(), ValidationError> {
        let depth = path.components().count();
        if depth > max_depth {
            return Err(ValidationError::PathTooDeep {
                path: path.to_path_buf(),
                max_depth,
            });
        }
        Ok(())
    }

    /// Check for symlinks in path and parent directories
    fn check_symlinks(&self, path: &Path) -> Result<(), ValidationError> {
        // Check the path itself
        if path.exists() {
            match self.symlink_prevention.is_symlink(path) {
                Ok(true) | Err(_) => {
                    return Err(ValidationError::SymlinkDetected {
                        path: path.to_path_buf(),
                    });
                }
                Ok(false) => {}
            }
        }

        // Check parent directories if configured
        if self.config.check_parents {
            let mut current = path.parent();
            while let Some(parent) = current {
                // Only check if parent exists; non-existent parents are safe
                if parent.exists() {
                    match self.symlink_prevention.is_symlink(parent) {
                        Ok(true) | Err(_) => {
                            return Err(ValidationError::SymlinkDetected {
                                path: parent.to_path_buf(),
                            });
                        }
                        Ok(false) => {}
                    }
                }
                current = parent.parent();
            }
        }

        Ok(())
    }

    /// Check if path is within allowed directories
    fn check_containment(&self, path: &Path) -> Result<(), ValidationError> {
        let canonical_path = Self::canonicalize_safe(path)?;

        let is_allowed = self.config.allowed_directories.iter().any(|allowed| {
            // Canonicalize allowed directory for comparison
            std::fs::canonicalize(allowed)
                .is_ok_and(|canonical_allowed| canonical_path.starts_with(&canonical_allowed))
        });

        if !is_allowed {
            return Err(ValidationError::OutsideAllowedDirectory {
                path: path.to_path_buf(),
            });
        }

        Ok(())
    }

    /// Safely canonicalize a path without following symlinks
    fn canonicalize_safe(path: &Path) -> Result<PathBuf, ValidationError> {
        // Refuse to canonicalize through symlinks (defense-in-depth).
        // This prevents callers from accidentally using this helper in a way that follows symlinks.
        let mut current = Some(path);
        while let Some(p) = current {
            if p.exists() {
                let meta =
                    std::fs::symlink_metadata(p).map_err(|e| ValidationError::MetadataFailed {
                        path: p.to_path_buf(),
                        reason: e.to_string(),
                    })?;
                if meta.file_type().is_symlink() {
                    return Err(ValidationError::SymlinkDetected {
                        path: p.to_path_buf(),
                    });
                }
            }
            current = p.parent();
        }

        // Check if path exists
        if !path.exists() {
            // Path doesn't exist, return as-is (with parent canonicalized)
            if let Some(parent) = path.parent()
                && parent.exists()
            {
                let canonical_parent =
                    std::fs::canonicalize(parent).map_err(|e| ValidationError::MetadataFailed {
                        path: parent.to_path_buf(),
                        reason: e.to_string(),
                    })?;
                let filename = path
                    .file_name()
                    .ok_or_else(|| ValidationError::MetadataFailed {
                        path: path.to_path_buf(),
                        reason: "no filename".to_string(),
                    })?;
                return Ok(canonical_parent.join(filename));
            }
            return Ok(path.to_path_buf());
        }

        // Path exists, canonicalize it
        std::fs::canonicalize(path).map_err(|e| ValidationError::MetadataFailed {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })
    }

    /// Check if a path is contained within allowed directories
    fn is_contained(&self, path: &Path) -> bool {
        if self.config.allowed_directories.is_empty() {
            return true;
        }

        self.config.allowed_directories.iter().any(|allowed| {
            std::fs::canonicalize(allowed)
                .ok()
                .is_some_and(|canonical_allowed| path.starts_with(&canonical_allowed))
        })
    }
}

// ============================================================================
// Secure File Creation API
// ============================================================================

/// Configuration for secure file creation
#[derive(Clone, Debug)]
pub struct FileCreationConfig {
    /// Whether to create parent directories
    pub create_parents: bool,

    /// Whether to fail if file already exists
    pub fail_if_exists: bool,

    /// File permissions (Unix only)
    pub permissions: u32,

    /// Whether to validate the path before creation
    pub validate_path: bool,
}

impl Default for FileCreationConfig {
    fn default() -> Self {
        Self {
            create_parents: true,
            fail_if_exists: true,
            permissions: 0o600, // rw-------
            validate_path: true,
        }
    }
}

/// Secure file creator
pub struct SecureFileCreator {
    path_validator: PathValidator,
    config: FileCreationConfig,
    symlink_prevention: Box<dyn SymlinkPrevention>,
}

impl Default for SecureFileCreator {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureFileCreator {
    /// Create a new secure file creator with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(FileCreationConfig::default())
    }

    /// Create a new secure file creator with custom configuration
    #[must_use]
    pub fn with_config(config: FileCreationConfig) -> Self {
        let validation_config = ValidationConfig {
            check_parents: true,
            allow_symlinks: false,
            ..Default::default()
        };

        #[cfg(unix)]
        let symlink_prevention: Box<dyn SymlinkPrevention> = Box::new(UnixSymlinkPrevention);

        #[cfg(windows)]
        let symlink_prevention: Box<dyn SymlinkPrevention> = Box::new(WindowsSymlinkPrevention);

        Self {
            path_validator: PathValidator::with_config(validation_config),
            config,
            symlink_prevention,
        }
    }

    /// Create a new file securely
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Path validation fails (symlinks detected, path traversal, etc.)
    /// - Parent directories cannot be created securely
    /// - The file cannot be created atomically without following symlinks
    /// - Permissions cannot be set on the created file
    /// - The created file is detected as a symlink (defense in depth)
    pub fn create_file(&self, path: &Path) -> Result<std::fs::File, SecurityError> {
        self.create_file_with_config(path, &self.config)
    }

    /// Create a new file with custom configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Path validation fails (symlinks detected, path traversal, etc.)
    /// - Parent directories cannot be created securely
    /// - The file cannot be created atomically without following symlinks
    /// - Permissions cannot be set on the created file
    /// - The created file is detected as a symlink (defense in depth)
    pub fn create_file_with_config(
        &self,
        path: &Path,
        config: &FileCreationConfig,
    ) -> Result<std::fs::File, SecurityError> {
        // 1. Validate path if configured
        if config.validate_path {
            match self.path_validator.validate(path) {
                Ok(_) => {}
                Err(e) => {
                    return Err(SecurityError::PathValidationFailed {
                        message: e.to_string(),
                    });
                }
            }
        }

        // 2. Create parent directories if configured
        if config.create_parents
            && let Some(parent) = path.parent()
        {
            self.create_secure_directory(parent)?;
        }

        // 3. Create file without following symlinks, honoring `fail_if_exists`
        let file = if config.fail_if_exists {
            self.symlink_prevention.open_no_follow(path)?
        } else {
            // Safe overwrite semantics for an API that returns a writable File:
            // 1. Attempt to open existing file without following symlinks and truncate it.
            // 2. If it fails with NotFound, it means we should create it.
            // 3. This eliminates the TOCTOU gap between `path.exists()` and `open`.
            match self.symlink_prevention.open_existing_no_follow(path) {
                Ok(mut f) => {
                    // Validate via the already-opened handle to avoid races/TOCTOU on `path`.
                    // open_existing_no_follow already checks if it's a regular file and not a symlink (via O_NOFOLLOW/FILE_FLAG_OPEN_REPARSE_POINT)
                    // but we verify again for defense in depth.
                    let meta = f.metadata().map_err(|e| SecurityError::FileOpenFailed {
                        message: e.to_string(),
                    })?;

                    if !meta.is_file() {
                        return Err(SecurityError::FileOpenFailed {
                            message: "Target is not a regular file".to_string(),
                        });
                    }

                    f.set_len(0).map_err(|e| SecurityError::WriteFailed {
                        message: e.to_string(),
                    })?;
                    f.rewind().map_err(|e| SecurityError::WriteFailed {
                        message: e.to_string(),
                    })?;
                    f
                }
                Err(e) => {
                    // Determine existence without following symlinks to prevent TOCTOU
                    match std::fs::symlink_metadata(path) {
                        Err(meta_err) if meta_err.kind() == std::io::ErrorKind::NotFound => {
                            self.symlink_prevention.open_no_follow(path)
                        }
                        Ok(_) | Err(_) => Err(e),
                    }?
                }
            }
        };

        // 4. Verify file is not a symlink (defense in depth)
        if matches!(self.symlink_prevention.is_symlink(path), Ok(true)) {
            // Close handle before deletion (important on Windows).
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(SecurityError::SymlinkDetected);
        }
        // If we can't check, proceed with caution

        // 5. Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                file.set_permissions(std::fs::Permissions::from_mode(config.permissions))
            {
                drop(file);
                let _ = std::fs::remove_file(path);
                return Err(SecurityError::PermissionSettingFailed {
                    message: e.to_string(),
                });
            }
        }

        // 6. On Windows, set restrictive ACLs
        #[cfg(windows)]
        {
            if let Err(e) = crate::database::set_restrictive_windows_acl(path) {
                drop(file);
                let _ = std::fs::remove_file(path);
                return Err(SecurityError::PermissionSettingFailed {
                    message: e.to_string(),
                });
            }
        }

        Ok(file)
    }

    /// Write data to a file securely
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be created securely (see `create_file` for error conditions)
    /// - The data cannot be written to the file due to I/O errors
    pub fn write_file(&self, path: &Path, data: &[u8]) -> Result<(), SecurityError> {
        // Atomic write strategy:
        // 1. Check if the file already exists if fail_if_exists is set.
        // 2. Create a temporary file in the same directory as the target.
        // 3. Write data to the temporary file.
        // 4. Rename the temporary file to the target path (atomic on Unix and most Windows scenarios).

        if self.config.fail_if_exists && path.exists() {
            return Err(SecurityError::AlreadyExists);
        }

        let parent = path
            .parent()
            .ok_or_else(|| SecurityError::PathValidationFailed {
                message: "Path must have a parent directory for atomic operations".to_string(),
            })?;

        // Generate a random temp filename to avoid collisions and predictability
        let temp_name = format!(".tmp_{}.tmp", uuid::Uuid::new_v4());
        let temp_path = parent.join(temp_name);

        // Ensure temp file is created securely (no follow, restrictive permissions)
        let mut temp_file = self.create_file_with_config(
            &temp_path,
            &FileCreationConfig {
                fail_if_exists: true, // Should be unique due to UUID
                ..self.config.clone()
            },
        )?;

        // Write data and sync to disk for durability
        std::io::Write::write_all(&mut temp_file, data).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            SecurityError::WriteFailed {
                message: e.to_string(),
            }
        })?;

        temp_file.sync_all().map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            SecurityError::WriteFailed {
                message: e.to_string(),
            }
        })?;

        // Atomic rename
        std::fs::rename(&temp_path, path).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            SecurityError::WriteFailed {
                message: format!("Atomic rename failed: {e}"),
            }
        })?;

        Ok(())
    }

    /// Write string data to a file securely
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be created securely (see `create_file` for error conditions)
    /// - The string data cannot be written to the file due to I/O errors
    pub fn write_string(&self, path: &Path, data: &str) -> Result<(), SecurityError> {
        self.write_file(path, data.as_bytes())
    }

    /// Validate existing parent chain to prevent traversing symlinks.
    #[cfg(unix)]
    fn validate_parent_chain(path: &Path) -> Result<(), SecurityError> {
        if let Some(parent) = path.parent() {
            for ancestor in parent.ancestors() {
                if ancestor.as_os_str().is_empty() || !ancestor.exists() {
                    continue;
                }
                let md = std::fs::symlink_metadata(ancestor).map_err(|e| {
                    SecurityError::PathValidationFailed {
                        message: e.to_string(),
                    }
                })?;
                if md.file_type().is_symlink() {
                    return Err(SecurityError::SymlinkDetected);
                }
            }
        }
        Ok(())
    }

    /// Create a secure directory
    fn create_secure_directory(&self, path: &Path) -> Result<(), SecurityError> {
        // Validate path
        if let Err(e) = self.path_validator.validate(path) {
            return Err(SecurityError::PathValidationFailed {
                message: e.to_string(),
            });
        }

        // Create directory with secure permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            Self::validate_parent_chain(path)?;

            // Create directories incrementally to reduce symlink TOCTOU risk.
            let mut current = std::path::PathBuf::new();
            let mut components: Vec<_> = path.components().collect();
            components.reverse();

            for component in components.iter().rev() {
                current.push(component);

                if current.as_os_str().is_empty() {
                    continue;
                }

                if current.exists() {
                    let md = std::fs::symlink_metadata(&current).map_err(|e| {
                        SecurityError::PathValidationFailed {
                            message: e.to_string(),
                        }
                    })?;
                    if md.file_type().is_symlink() {
                        return Err(SecurityError::SymlinkDetected);
                    }
                    if !md.is_dir() {
                        return Err(SecurityError::DirectoryCreationFailed {
                            message: "Expected directory but found non-directory".to_string(),
                        });
                    }

                    // Log a warning if permissions are overly permissive.
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = md.permissions().mode() & 0o777;
                        if (mode & 0o077) != 0 {
                            tracing::warn!(
                                "Existing parent directory is overly permissive (mode={:04o}, expected 0o700): consider restricting permissions",
                                mode
                            );
                        }
                    }

                    continue;
                }

                match std::fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => {
                        return Err(SecurityError::DirectoryCreationFailed {
                            message: e.to_string(),
                        });
                    }
                }

                let md = std::fs::symlink_metadata(&current).map_err(|e| {
                    SecurityError::PathValidationFailed {
                        message: e.to_string(),
                    }
                })?;
                if md.file_type().is_symlink() {
                    return Err(SecurityError::SymlinkDetected);
                }
                if !md.is_dir() {
                    return Err(SecurityError::DirectoryCreationFailed {
                        message: "Expected directory but found non-directory".to_string(),
                    });
                }

                std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| SecurityError::DirectoryCreationFailed {
                        message: format!("Failed to set directory permissions: {e}"),
                    })?;
            }
        }

        // On Windows, create directory and set restrictive ACLs (fail-fast on ACL failure)
        #[cfg(windows)]
        {
            std::fs::create_dir_all(path).map_err(|e| SecurityError::DirectoryCreationFailed {
                message: e.to_string(),
            })?;

            if let Err(e) = crate::database::set_restrictive_windows_acl(path) {
                // Fail safe: don't leave behind a directory with default/permissive ACLs.
                let _ = std::fs::remove_dir_all(path);
                return Err(SecurityError::DirectoryCreationFailed {
                    message: format!("Failed to set Windows ACLs on directory: {e}"),
                });
            }
        }

        // On other non-Unix platforms, create directory
        #[cfg(all(not(unix), not(windows)))]
        {
            std::fs::create_dir_all(path).map_err(|e| SecurityError::DirectoryCreationFailed {
                message: e.to_string(),
            })?;
        }

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_validate_normal_path() {
        let validator = PathValidator::new();
        let test_path = PathBuf::from("/tmp/test.txt");

        let result = validator.validate(&test_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_traversal() {
        let validator = PathValidator::new();
        let traversal_path = PathBuf::from("/tmp/../etc/passwd");

        let result = validator.validate(&traversal_path);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::PathTraversalDetected { .. }
        ));
    }

    #[test]
    fn test_validate_containment() {
        // Create a temporary directory for testing
        let temp_dir = std::env::temp_dir();
        let test_dir = temp_dir.join("aroeira_security_test");
        std::fs::create_dir_all(&test_dir).unwrap();

        let config = ValidationConfig {
            allowed_directories: vec![test_dir.clone()],
            ..Default::default()
        };
        let validator = PathValidator::with_config(config);

        // Path within allowed directory
        let safe_path = test_dir.join("test.txt");
        let result = validator.validate(&safe_path);
        assert!(
            result.is_ok(),
            "Validation of path within allowed directory should succeed: {result:?}"
        );

        // Verify atomic creation: attempting to create the same file again should fail
        // because SecureFileCreator default config has fail_if_exists: true
        let creator2 = SecureFileCreator::new();
        let test_file = test_dir.join("test_file_for_creator.txt"); // Define test_file for creator
        let _ = creator2.write_string(&test_file, "initial content"); // Create it once
        let result2 = creator2.write_string(&test_file, "different content");
        assert!(
            result2.is_err(),
            "SecureFileCreator should fail when file already exists"
        );

        // Path outside allowed directory
        let unsafe_path = temp_dir.join("unsafe_test.txt");
        let result = validator.validate(&unsafe_path);
        assert!(
            result.is_err(),
            "Validation of path outside allowed directory should fail: {result:?}"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&test_dir);
    }
}
