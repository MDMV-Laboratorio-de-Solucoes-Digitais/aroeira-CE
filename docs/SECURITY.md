# 🛡️ Security Policy

## Reporting a Vulnerability

Please report vulnerabilities by opening a draft **Security Advisory** in this repository.

1. Go to the "Security" tab.
2. Click on "Advisories".
3. Click "New draft security advisory".

Do not open public issues for security vulnerabilities.

## Security Checklist

We maintain a comprehensive security checklist for all developers.
👉 **[Read the Security Checklist](/docs/SECURITY_CHECKLIST.md)**

This detailed checklist covers:

- File Operations (Creation, Deletion, Reading)
- Path Validation (Traversal prevention)
- Authentication & Authorization
- Error Handling & Logging

All contributions must adhere to these guidelines.

## Architecture

For details on the Security Architecture, including the "Modular Monolith" approach to security and specific defenses against Symlink attacks, please refer to:

- [System Architecture](ARCHITECTURE.md#security-control-points) (Overview)
- [ADR 001: Symlink Protection](adrs/001-security-symlink-protection.md) (Detailed Decision Record)
