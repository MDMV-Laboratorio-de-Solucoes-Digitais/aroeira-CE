use crate::constants::{
    DEFAULT_MAX_EMAIL_LENGTH, DEFAULT_MAX_PASSWORD_LENGTH, MAX_NOTE_CONTENT_BYTES,
    MAX_NOTE_CONTENT_LENGTH, MAX_NOTE_TITLE_BYTES, MAX_NOTE_TITLE_LENGTH,
};
use regex::Regex;
use secrecy::{ExposeSecret, SecretBox};
use std::sync::LazyLock;

static EMAIL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap());

/// A validated email address
#[derive(Debug, Clone)]
pub struct ValidatedEmail(String);

impl ValidatedEmail {
    /// Creates a new `ValidatedEmail` after validating the input
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The email is empty
    /// - The email exceeds the maximum length
    /// - The email doesn't match the required format
    pub fn new(email: &str) -> Result<Self, String> {
        let email = email.trim().to_lowercase();

        if email.is_empty()
            || email.len() > DEFAULT_MAX_EMAIL_LENGTH
            || !EMAIL_REGEX.is_match(&email)
        {
            return Err("Invalid email format".to_string());
        }

        Ok(Self(email))
    }

    /// Gets the inner email string
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ValidatedEmail {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A validated password
#[derive(Debug)]
pub struct ValidatedPassword(SecretBox<str>);

impl ValidatedPassword {
    /// Creates a new `ValidatedPassword` after validating the input
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The password is shorter than the minimum length
    /// - The password exceeds the maximum length
    /// - The password is too large in bytes
    pub fn new(password: String, level: crate::PasswordSecurityLevel) -> Result<Self, String> {
        let password_chars = password.chars().count();
        let min_length = level.min_length();

        if password_chars < min_length {
            return Err(format!("Password must be at least {min_length} characters"));
        } else if password_chars > DEFAULT_MAX_PASSWORD_LENGTH {
            return Err(format!(
                "Password must be at most {DEFAULT_MAX_PASSWORD_LENGTH} characters",
            ));
        } else if password.len() > (DEFAULT_MAX_PASSWORD_LENGTH * 4) {
            // DoS protection: reject extremely large UTF-8 inputs regardless of character count.
            return Err("Password is too large".to_string());
        }

        // Complexity checks
        // Note: PasswordSecurityLevel::Minimum intentionally enforces only length requirements (verified above).
        // Additional complexity rules are applied for higher security levels.
        if matches!(
            level,
            crate::PasswordSecurityLevel::Secure
                | crate::PasswordSecurityLevel::Strict
                | crate::PasswordSecurityLevel::Paranoid
        ) {
            let has_uppercase = password.chars().any(char::is_uppercase);
            let has_lowercase = password.chars().any(char::is_lowercase);
            let has_number = password.chars().any(char::is_numeric);
            let has_special = password
                .chars()
                .any(|c| !c.is_alphanumeric() && !c.is_whitespace());

            if !has_uppercase {
                return Err("Password must contain at least one uppercase letter".to_string());
            }
            if !has_lowercase {
                return Err("Password must contain at least one lowercase letter".to_string());
            }
            if !has_number {
                return Err("Password must contain at least one number".to_string());
            }
            if !has_special {
                return Err("Password must contain at least one special character".to_string());
            }
        }

        Ok(Self(SecretBox::from(password.into_boxed_str())))
    }

    /// Exposes the password for use in validation/hashing
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

/// A validated note title
#[derive(Debug, Clone)]
pub struct ValidatedNoteTitle(String);

impl ValidatedNoteTitle {
    /// Creates a new `ValidatedNoteTitle` after validating the input
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The title is empty
    /// - The title exceeds the maximum character length
    /// - The title exceeds the maximum byte length
    pub fn new(title: &str) -> Result<Self, String> {
        if title.trim().is_empty() {
            return Err("Title cannot be empty".to_string());
        }

        if title.chars().count() > MAX_NOTE_TITLE_LENGTH {
            return Err(format!(
                "Title must be at most {MAX_NOTE_TITLE_LENGTH} characters",
            ));
        }

        if title.len() > MAX_NOTE_TITLE_BYTES {
            return Err(format!(
                "Title must be at most {MAX_NOTE_TITLE_BYTES} bytes",
            ));
        }

        Ok(Self(title.trim().to_string()))
    }

    /// Gets the inner title string
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated note content
#[derive(Debug, Clone)]
pub struct ValidatedNoteContent(String);

impl ValidatedNoteContent {
    /// Creates a new `ValidatedNoteContent` after validating the input
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The content exceeds the maximum character length
    /// - The content exceeds the maximum byte length
    pub fn new(content: String) -> Result<Self, String> {
        if content.chars().count() > MAX_NOTE_CONTENT_LENGTH {
            return Err(format!(
                "Content must be at most {MAX_NOTE_CONTENT_LENGTH} characters",
            ));
        }

        if content.len() > MAX_NOTE_CONTENT_BYTES {
            return Err(format!(
                "Content must be at most {MAX_NOTE_CONTENT_BYTES} bytes",
            ));
        }

        Ok(Self(content))
    }

    /// Gets the inner content string
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated note input combining title and content
#[derive(Debug)]
pub struct ValidatedNoteInput {
    pub title: String,
    pub content: String,
}

impl ValidatedNoteInput {
    /// Creates a new `ValidatedNoteInput` after validating both title and content
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The title validation fails
    /// - The content validation fails
    pub fn new(title: &str, content: &str) -> Result<Self, String> {
        let validated_title = ValidatedNoteTitle::new(title)?;
        let validated_content = ValidatedNoteContent::new(content.to_string())?;

        Ok(Self {
            title: validated_title.0,
            content: validated_content.0,
        })
    }
}
