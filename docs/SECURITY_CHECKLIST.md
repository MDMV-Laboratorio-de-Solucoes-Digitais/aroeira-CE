# 🔒 Security Checklist for Developers

This checklist provides a comprehensive guide for developers to ensure security best practices are followed when implementing features, especially those involving file operations, authentication, and data handling.

## Table of Contents

1. [File Operations Security](#file-operations-security)
2. [Path Validation](#path-validation)
3. [Authentication & Authorization](#authentication--authorization)
4. [Error Handling](#error-handling)
5. [Logging & Monitoring](#logging--monitoring)
6. [Secure Logging Checklist](#secure-logging-checklist)
7. [Data Protection](#data-protection)
8. [Code Review Checklist](#code-review-checklist)
9. [Testing Security](#testing-security)

---

## File Operations Security

### ✅ File Creation

- [x] All file creation uses [`SecureFileCreator`](../libs/infra/src/security.rs:509)
- [x] Files are created with restrictive permissions (`0o600` for files, `0o700` for directories)
- [x] Parent directories are validated before file creation
- [x] Atomic file creation is used (no TOCTOU windows)
- [x] File paths are validated before use

### ✅ File Reading

- [ ] File paths are validated with [`PathValidator`](../libs/infra/src/security.rs:246) before reading
- [ ] Symlink checks are performed before file operations
- [ ] File existence is checked with `symlink_metadata()` not `metadata()`
- [ ] Error handling doesn't leak sensitive information

### ✅ File Deletion

- [ ] File paths are validated before deletion
- [ ] Symlink checks prevent unintended deletions
- [ ] Error messages are generic (don't leak file paths)

### ❌ Common Pitfalls to Avoid

- [ ] Never use `std::fs::File::create()` without validation
- [ ] Never use `std::fs::write()` without validation
- [ ] Never use `path.canonicalize()` without prior validation
- [ ] Never create files with default permissions (use `0o600`)
- [ ] Never follow symlinks in security-critical operations

---

## Path Validation

### ✅ Path Validation Checklist

- [ ] All user-supplied paths are validated
- [ ] Path traversal attempts (`..`) are detected and rejected
- [ ] Null bytes are detected and rejected
- [ ] Control characters are detected and rejected
- [ ] Path depth is limited (max 32 components by default)
- [ ] Symlinks are detected and rejected (unless explicitly allowed)
- [ ] Paths are checked against allowed directories (containment)
- [ ] Canonicalization is performed safely

### ✅ Using PathValidator

```rust
use infra::security::{PathValidator, ValidationConfig};

// Basic validation
let validator = PathValidator::new();
let result = validator.validate(&path)?;

// Advanced validation with containment
let mut config = ValidationConfig::default();
config.allowed_directories = vec![
    std::env::current_dir()?,
    dirs::data_local_dir()?.join("Aroeira"),
];
let validator = PathValidator::with_config(config);
let result = validator.validate(&path)?;
```

### ✅ Validation Checks

| Check Type         | Purpose                                    | Status |
| ------------------ | ------------------------------------------ | ------ |
| Path Traversal     | Prevents `..` directory references         | [ ]    |
| Invalid Characters | Detects null bytes and control characters  | [ ]    |
| Path Depth         | Prevents excessively deep paths            | [ ]    |
| Symlink Detection  | Ensures no symlinks in path                | [ ]    |
| Containment        | Ensures path is within allowed directories | [ ]    |

---

## Authentication & Authorization

### ✅ Password Security

- [ ] Passwords are hashed with bcrypt (cost factor ≥ 10)
- [ ] Passwords are never logged or stored in plain text
- [ ] Password validation follows security best practices
- [ ] Password reset tokens are cryptographically secure
- [ ] Password strength requirements are enforced

### ✅ Session Management

- [ ] Session tokens are cryptographically secure
- [ ] Session expiration is enforced
- [ ] Session tokens are not exposed in URLs
- [ ] Session invalidation is implemented on logout
- [ ] Rate limiting is implemented on authentication endpoints

### ✅ Rate Limiting

- [x] Rate limiting is implemented for sensitive operations
- [x] Rate limits are enforced per-user/IP
- [x] Rate limit violations are logged
- [x] Rate limits prevent brute force attacks
- [x] Memory exhaustion is prevented in rate limiter
- [x] Rate limiting implements exponential backoff
- [x] All rate limit buckets cleared on success

### ✅ Timing Attack Prevention

- [x] Constant-time comparison is used for sensitive data
- [x] Dummy verification is implemented for failed attempts
- [x] Response timing is consistent regardless of outcome
- [x] No information is leaked through timing

---

## Error Handling

### ✅ Error Message Guidelines

- [ ] User-facing error messages are generic
- [ ] System information is not leaked in errors
- [ ] File paths are not included in user errors
- [ ] Stack traces are not exposed to users
- [ ] Sensitive data is not logged

### ✅ Error Handling Best Practices

```rust
// ✅ Good: Generic error message
return Err(anyhow::anyhow!("Operation failed"));

// ❌ Bad: Leaks system information
return Err(anyhow::anyhow!("Failed to access /etc/passwd: Permission denied"));
```

### ✅ Logging Security Events

- [ ] Security events are logged with appropriate severity
- [ ] Security events include context without sensitive data
- [ ] Failed authentication attempts are logged
- [ ] Symlink detection attempts are logged
- [ ] Path traversal attempts are logged

### ✅ Logging Examples

```rust
// ✅ Good: Logs security event without sensitive data
tracing::error!(
    security_event = "symlink_detected",
    operation = "file_creation",
    "Security: Symlink detected during file creation"
);

// ❌ Bad: Logs sensitive data
tracing::error!("Secret value: {}", secret);
```

---

## Data Protection

### ✅ Sensitive Data Handling

- [ ] Secrets are never logged or printed
- [ ] Secrets are stored with restrictive permissions
- [ ] Secrets are encrypted at rest (when applicable)
- [ ] Secrets are encrypted in transit (when applicable)
- [ ] Secret rotation is implemented

### ✅ Database Security

- [ ] Database credentials are stored securely
- [ ] Database connections use TLS (when applicable)
- [ ] SQL injection prevention is implemented
- [ ] Database queries use parameterized statements
- [ ] Database access is restricted to necessary operations

### ✅ File Permissions

- [x] Sensitive files use `0o600` permissions (read/write owner only)
- [x] Sensitive directories use `0o700` permissions (read/write/execute owner only)
- [x] File permissions are set immediately on creation
- [x] Windows ACLs are set for sensitive files
- [x] File permissions are verified after creation

---

## Code Review Checklist

### ✅ Pre-Commit Checklist

Before committing code that handles security-sensitive operations:

- [ ] All file operations use `SecureFileCreator`
- [ ] All paths are validated with `PathValidator`
- [ ] Error messages don't leak sensitive information
- [ ] Security events are logged appropriately
- [ ] Tests cover security scenarios
- [ ] No hardcoded secrets or credentials
- [ ] Dependencies are up-to-date
- [ ] Code follows security best practices

### ✅ Security Review Checklist

When reviewing code for security issues:

#### Input Validation

- [ ] All external inputs are validated
- [ ] Input length limits are enforced
- [ ] Input format is validated (regex, schema, etc.)
- [ ] Special characters are handled correctly
- [ ] Type conversions are safe

#### File System Operations

- [ ] Paths are validated against allowed directories
- [ ] Path traversal is prevented
- [ ] Symlinks are checked and handled
- [ ] File permissions are set correctly
- [ ] Race conditions are avoided

#### Authentication & Authorization

- [ ] Passwords are hashed with strong algorithms
- [ ] Timing attacks are prevented
- [ ] Rate limiting is implemented
- [ ] Session management is secure
- [ ] Authorization checks are comprehensive

#### Error Handling

- [ ] Error messages are generic
- [ ] Sensitive information is not leaked
- [ ] Errors are logged appropriately
- [ ] Failures fail closed
- [ ] Resource cleanup is ensured

#### Cryptography

- [ ] Approved algorithms are used
- [ ] Keys are properly managed
- [ ] Random number generation is secure
- [ ] Encryption is applied correctly
- [ ] Certificate validation is implemented

#### Logging & Monitoring

- [ ] Security events are logged
- [ ] Sensitive data is not logged
- [ ] **Filesystem paths are redacted from logs** (see [Secure Logging Practices](SECURITY.md#secure-logging-practices))
- [ ] **Generic placeholders used instead of full paths** (e.g., "file", "directory", "git_executable")
- [ ] **Error codes and types preserved for debugging**
- [ ] **Only filenames logged when necessary** (setup utilities only, no full paths)
- [ ] Logs are protected from tampering
- [ ] Anomalies are detectable
- [ ] Alerts are configured

### ✅ Secure Logging Checklist

#### Path Redaction

- [ ] **Never use `path.display()` in log messages**
- [ ] **Never use `canonical_path.display()` in log messages**
- [ ] **Never use `absolute_file.display()` in log messages**
- [ ] **Never use `parent.display()` in log messages**
- [ ] **Use generic placeholders** ("file", "directory", "temporary_file", etc.)
- [ ] **Preserve error context** (error codes, error types)

#### Structured Logging

- [ ] **Use structured logging fields** for context
- [ ] **Avoid string interpolation with sensitive data**
- [ ] **Log operation types and outcomes** without sensitive details
- [ ] **Use appropriate log levels** (error, warn, info, debug)

#### Error Message Security

- [ ] **Error messages are generic** (no system paths)
- [ ] **Error messages don't leak environment information**
- [ ] **Error messages don't reveal directory structures**
- [ ] **Error messages don't contain usernames or identifiers**

#### Setup Utility Logging

- [ ] **Extract only filenames** when visibility is needed
- [ ] **Never log full paths in setup utilities**
- [ ] **Use filename-only for user-facing messages**
- [ ] **Redact paths in internal error messages**

### ❌ Common Logging Pitfalls to Avoid

```rust
// ❌ VULNERABLE: Logs full filesystem path
tracing::error!("Failed to access file: {}", path.display());

// ✅ SECURE: Uses generic placeholder
tracing::error!("Failed to access file");
```

```rust
// ❌ VULNERABLE: Logs full path in error
return Err(anyhow::anyhow!(
    "Failed to create file at {}: Permission denied",
    path.display()
));

// ✅ SECURE: Generic error message
return Err(anyhow::anyhow!(
    "Failed to create file: Permission denied"
));
```

```rust
// ❌ VULNERABLE: Logs path with error code
tracing::warn!(
    "Failed to set ACLs on {}: Error code {}",
    path.display(),
    error_code
);

// ✅ SECURE: Structured logging without path
tracing::warn!(
    resource_type = "file",
    operation = "set_acls",
    error_code = error_code,
    "Failed to set ACLs on file"
);
```

### ✅ Secure Logging Examples

#### Database Operations

```rust
// ✅ SECURE: Redacted path
tracing::warn!(
    "Failed to set restrictive permissions on SQLite file. Error: {e}"
);

// ❌ VULNERABLE: Full path
tracing::warn!(
    "Failed to set restrictive permissions on SQLite file: {}. Error: {e}",
    path.display()
);
```

#### File Creation

```rust
// ✅ SECURE: Generic placeholder
tracing::error!("Failed to create file");

// ❌ VULNERABLE: Full path
tracing::error!("Failed to create file: {}", path.display());
```

#### Setup Utilities

```rust
// ✅ SECURE: Filename only
if let Some(filename) = path.file_name() {
    println!("Processing file: {}", filename.to_string_lossy());
}

// ❌ VULNERABLE: Full path
println!("Processing file: {}", path.display());
```

#### Security Checks

```rust
// ✅ SECURE: Generic placeholder
eprintln!(
    "❌ ERROR: Git binary is located in a user-writable directory: {}",
    "git_executable"
);

// ❌ VULNERABLE: Full path
eprintln!(
    "❌ ERROR: Git binary is located in a user-writable directory: {}",
    git_path.display()
);
```

---

## Testing Security

### ✅ Unit Tests

- [ ] Path validation tests cover all scenarios
- [ ] Symlink prevention tests are comprehensive
- [ ] Error handling tests cover all paths
- [ ] Permission tests verify correct settings
- [ ] Edge cases are tested

### ✅ Integration Tests

- [ ] End-to-end security flows are tested
- [ ] Real file system operations are tested
- [ ] Cross-platform behavior is verified
- [ ] Security module integration is tested
- [ ] Error propagation is verified

### ✅ Security-Specific Tests

- [ ] Symlink attack prevention is tested
- [ ] Path traversal attacks are tested
- [ ] TOCTOU attacks are prevented
- [ ] Permission escalation is prevented
- [ ] Information disclosure is prevented

### ✅ Running Security Tests

```bash
# Run all security module tests
cargo test -p infra security

# Run with coverage
cargo tarpaulin -p infra --out Html --output-dir coverage/

# Run database security tests
cargo test -p infra --test database

# Run auth security tests
cargo test -p desktop --test auth_tests
```

---

## Common Security Pitfalls

### ❌ File Operations

```rust
// ❌ VULNERABLE: No path validation or symlink prevention
std::fs::write(&secret_path, secret)?;

// ✅ SECURE: Path validation and symlink prevention
let creator = SecureFileCreator::new();
creator.write_string(&secret_path, secret)?;
```

### ❌ Path Validation

```rust
// ❌ VULNERABLE: May follow symlinks during canonicalization
let safe_path = path.canonicalize()?;

// ✅ SECURE: Validates path before canonicalization
let validator = PathValidator::new();
let result = validator.validate(&path)?;
let safe_path = result.canonical_path;
```

### ❌ File Permissions

```rust
// ❌ VULNERABLE: Creates files with 0o666 permissions
let file = std::fs::File::create(&path)?;

// ✅ SECURE: Creates files with 0o600 permissions
let creator = SecureFileCreator::new();
let file = creator.create_file(&path)?;
```

### ❌ Error Messages

```rust
// ❌ VULNERABLE: Leaks system information
return Err(anyhow::anyhow!("Failed to access /etc/passwd: Permission denied"));

// ✅ SECURE: Generic error message
return Err(anyhow::anyhow!("Access denied"));
```

### ❌ Logging

```rust
// ❌ VULNERABLE: Logs sensitive data
tracing::error!("Secret value: {}", secret);

// ✅ SECURE: Logs without sensitive data
tracing::error!("Secret operation failed");
```

---

## Quick Reference

### Security Module APIs

#### PathValidator

```rust
use infra::security::{PathValidator, ValidationConfig};

// Create validator
let validator = PathValidator::new();

// Validate path
let result = validator.validate(&path)?;
let canonical_path = result.canonical_path;

// Validate with configuration
let config = ValidationConfig::default();
let validator = PathValidator::with_config(config);
```

#### SecureFileCreator

```rust
use infra::security::{SecureFileCreator, FileCreationConfig};

// Create file
let creator = SecureFileCreator::new();
let file = creator.create_file(&path)?;

// Write data
creator.write_string(&path, "data")?;
creator.write_file(&path, bytes)?;
```

### Security Error Types

| Error Type                                 | Description                      |
| ------------------------------------------ | -------------------------------- |
| `SecurityError::SymlinkDetected`           | Symlink detected in path         |
| `SecurityError::PathValidationFailed`      | Path validation failed           |
| `ValidationError::PathTraversalDetected`   | Path traversal attempt detected  |
| `ValidationError::OutsideAllowedDirectory` | Path outside allowed directories |

---

## Ongoing Security Maintenance

### ✅ Regular Security Tasks

- [ ] Regular security audits scheduled
- [ ] Security metrics monitoring configured
- [ ] Incident response procedures documented
- [ ] Key rotation schedule maintained

### ✅ Security Monitoring

- [ ] Rate limit bypass attempts monitored
- [ ] Failed authentication attempts tracked
- [ ] ACL application failures logged
- [ ] Memory usage trends monitored
- [ ] Security event alerts configured

### ✅ Incident Response

- [ ] Security incident response plan documented
- [ ] Rollback procedures for security issues defined
- [ ] Communication procedures for security incidents established
- [ ] Post-incident review process defined

---

## Additional Resources

### Documentation

- [Security Policy](SECURITY.md) - High-level security policy and reporting
- [Secure Logging Practices](SECURITY_CHECKLIST.md#secure-logging-checklist) - Secure logging guidelines and implementation

- [Architecture Documentation](ARCHITECTURE.md) - System architecture
- [Development Guide](DEVELOPMENT.md#security-best-practices) - Development security practices
- [Security Architecture Design](../plans/security-architecture-symlink-attack-fixes.md) - Design documentation

### External Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web security risks
- [CWE Top 25](https://cwe.mitre.org/top25/) - Common weaknesses
- [Rust Security Guidelines](https://doc.rust-lang.org/nomicon/unsafe.html) - Rust security
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal) - Path traversal attacks
- [CWE-59: Improper Link Resolution](https://cwe.mitre.org/data/definitions/59.html) - Symlink attacks

---

**Document Version:** 1.1  
**Last Updated:** 2026-01-19  
**Maintained By:** Security Team
