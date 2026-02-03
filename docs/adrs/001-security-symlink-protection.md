# ADR 001: Cross-Platform Symlink Protection Strategy

## Status

Accepted

## Context

The application performs sensitive file operations (writing secrets, creating databases) in user-controlled directories. A security audit identified critical vulnerabilities:

1. **Secrets Leakage**: `persist_env_secret` wrote sensitive keys without verifying if the target path or its parents were symlinks, potentially allowing attackers to redirect writes.
2. **TOCTOU Race Conditions**: On Windows, file creation followed by a separate symlink check created a Time-of-Check-Time-of-Use window.

## Decision

We implemented a unified `SecureFileCreator` and `PathValidator` module within the Infrastructure layer (`libs/infra`) to handle all sensitive file operations.

### Key Architectural Decisions

1. **Atomic Creation**:
   - **Unix**: Use `O_NOFOLLOW` and `O_EXCL` flags during `open()`.
   - **Windows**: Use `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT` and strict sharing modes.

2. **Strict Path Validation**:
   - All paths must be absolute and canonicalized.
   - All parent directories are verified to be owned by the current user (where applicable) and not be writable by others (on Unix).
   - Recursive symlink checks on parent components.

3. **Restricted Permissions**:
   - Files are created with `0o600` (Unix) or restricted ACLs (Windows) immediately at creation time, not via a secondary `chmod`.

## Consequences

### Positive

- Prevents known classes of symlink and TOCTOU attacks.
- Centralizes security logic in one audit-able module.
- Cross-platform consistency for file security.

### Negative

- Slight performance overhead due to recursive path checks.
- Increased complexity in file I/O operations (cannot use simple `std::fs::write`).

## Implementation Details

For implementation specifics, refer to:

- [`libs/infra/src/security.rs`](../../libs/infra/src/security.rs)
- [`libs/infra/src/device_identifier.rs`](../../libs/infra/src/device_identifier.rs)

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-59: Improper Link Resolution](https://cwe.mitre.org/data/definitions/59.html)
