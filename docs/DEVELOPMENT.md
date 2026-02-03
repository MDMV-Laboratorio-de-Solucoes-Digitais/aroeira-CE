# 🪵 Aroeira Development Guide

Welcome to the internal development documentation for **Aroeira**.

This document goes beyond the standard `README`. It is the operational manual for building, testing, debugging, and maintaining the "unbreaking wood." Aroeira is an opinionated, security-hardened Modular Monolith. We optimize for correctness and durability over development speed.

> **The Golden Rule**: If it compiles, it should work. If it runs, it must be secure.

---

## 📋 Table of Contents

1. [Environment Setup](#1-environment-setup)
2. [Project Initialization](#2-project-initialization)
3. [The Development Loop](#3-the-development-loop)
4. [Working with the Modular Monolith](#4-working-with-the-modular-monolith)
5. [Database Management (SQLx)](#5-database-management-sqlx)
6. [Testing Strategy & Commands](#6-testing-strategy--commands)
7. [Security Best Practices](#7-security-best-practices)
8. [Release & CI/CD](#8-release--cicd)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Environment Setup

Aroeira relies on a specific toolchain to ensure cross-platform consistency and security. Ensure your local environment meets these strict requirements.

### 🛠 Core Toolchain

1.  **Rust (Stable)**
    We stay on the latest stable release.

    ```bash
    rustup update stable
    ```

2.  **Node.js (LTS)**
    Required for the Svelte 5 frontend and Tauri CLI.
    - **Minimum**: v20.x
    - **Package Manager**: `npm` (Strictly enforced via lockfile).

3.  **Tauri CLI**
    The bridge between the OS and our code.

    ```bash
    # Install via Cargo (Recommended for backend devs)
    cargo install tauri-cli

    # OR via NPM (Recommended for frontend devs)
    npm install -g @tauri-apps/cli
    ```

4.  **Lefthook**
    We use Lefthook to enforce git hooks. It prevents bad code from ever entering the commit history.
    ```bash
    go install github.com/evilmartians/lefthook@latest
    # Or brew install lefthook / npm install -g @evilmartians/lefthook
    ```

### 🖥️ OS-Specific Build Tools

Since Aroeira compiles to native binaries, you need C++ build chains:

- **Windows**: Install "C++ build tools" via Visual Studio Installer.
- **macOS**: `xcode-select --install`
- **Linux**:
  ```bash
  sudo apt-get update
  sudo apt-get install libwebkit2gtk-4.1-dev build-essential curl wget file libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
  ```

### 🔌 IDE Recommendations

For the best experience (Vertical Slice navigation), use **VS Code** with:

1.  **rust-analyzer**: For the core logic.
2.  **Svelte for VS Code**: For the frontend.
3.  **Tauri**: For `tauri.conf.json` validation.
4.  **Error Lens**: To see errors inline (optional but recommended).

---

## 2. Project Initialization

Follow these steps exactly to bootstrap the workspace.

1.  **Clone the Repository**

    ```bash
    git clone https://github.com/MDMV-Laboratorio-de-Solucoes-Digitais/aroeira-template.git
    cd aroeira-template
    ```

2.  **Install Frontend Dependencies**
    Dependencies are managed inside the `apps/desktop` directory.

    ```bash
    cd apps/desktop
    npm install
    cd ../..
    ```

3.  **Setup Environment Variables**
    Copy the example template. **Never** commit `.env` to git.

    ```bash
    cp .env.example .env
    ```

    _Edit `.env` and fill in necessary secrets (Database URL, OAuth keys)._

4.  **Initialize Git Hooks**
    This activates the quality gates (formatting, linting) locally.
    ```bash
    lefthook install
    ```

---

## 3. The Development Loop

### 🚀 Running the App (Dev Mode)

To start the full stack (Rust Backend + Svelte Frontend) with Hot Module Replacement (HMR):

```bash
npm run tauri dev --prefix apps/desktop
```

> **Note**: The first compile will take time as it builds the entire dependency tree. Subsequent builds are incremental and fast.

### 🔄 The "Vertical Slice" Workflow

When adding a new feature (e.g., `Billing`), do not jump between arbitrary files. Follow the **Inward Dependency Rule**:

1.  **Step 1: The Domain (`libs/domain`)**
    - Create `src/modules/billing/entity.rs`. Define the `Invoice` struct.
    - Define the `InvoiceRepository` trait.
    - Write **pure unit tests** inside the module.
    - _Constraint_: Do NOT import SQLx or Tauri here.

2.  **Step 2: The Infra (`libs/infra`)**
    - Implement `InvoiceRepository` for `SqliteDatabase`.
    - Write the SQL queries using `sqlx::query!`.
    - Handle OS-level file operations if needed.

3.  **Step 3: The Glue (`apps/desktop/src-tauri`)**
    - Create a Tauri Command: `create_invoice`.
    - Inject the repository implementation.
    - Call the Domain service.

4.  **Step 4: The UI (`apps/desktop/src`)**
    - Create the Svelte component.
    - Call `invoke('create_invoice', { ... })`.

---

## 4. Working with the Modular Monolith

Aroeira uses a Rust Workspace to enforce boundaries. Understanding `Cargo.toml` is vital.

### 📦 Workspace Members

| Member            | Path           | Role               | Allowed Dependencies                               |
| ----------------- | -------------- | ------------------ | -------------------------------------------------- |
| **Domain**        | `libs/domain`  | Business Rules     | `serde`, `thiserror`, `uuid`, `chrono`. **NO IO.** |
| **Infra**         | `libs/infra`   | I/O Implementation | `domain`, `sqlx`, `tokio`, `keyring`.              |
| **Multiplatform** | `apps/desktop` | UI & Glue          | `domain`, `infra`, `tauri`, `specta`.              |

### ⚠️ Common Pitfalls

- **Leaking Logic**: Do not write business logic in `apps/desktop`. If you are calculating taxes inside a Tauri command, you are breaking the architecture. Move it to `libs/domain`.
- **Bypassing Interfaces**: `libs/domain` should never instantiate a struct from `libs/infra`. It must rely on Traits (Dependency Inversion).

---

## 5. Database Management (SeaORM)

We use **SeaORM** as our ORM, which sits on top of **SQLx**. This gives us type-safe queries and async support.

### Setting up the Database

1.  Ensure `DATABASE_URL` is set in your `.env`.

    ```bash
    DATABASE_URL=sqlite:aroeira.db
    ```

2.  Run migrations using `sea-orm-cli` (or sqlx if preferred):
    ```bash
    sea-orm-cli migrate up
    ```

### Creating Migrations

When you need to modify the schema (e.g., adding a `users` table):

```bash
sea-orm-cli migrate generate create_users_table
```

This creates a file in `migration/src/m202..._create_users_table.rs`. Write your migration logic there using the SeaORM migration API (or raw SQL).

### ⚠️ The `.sqlx` Directory (Offline Mode)

Even though we use SeaORM, we rely on SQLx for the driver. We commit the `.sqlx` directory to git. This allows CI to build the project without a running database connection.

**If you change a SQL query**, you must update the offline data:

```bash
cargo sqlx prepare --workspace
```

_Lefthook should warn you if you forget this, but it's good practice to run it manually._

---

## 6. Testing Strategy & Commands

Code without tests does not get merged. We employ a "Swiss Cheese" model of testing—each layer covers the holes of the other.

### 1. Unit Tests (Domain)

Tests pure logic. Fast. No I/O.

```bash
cargo test -p domain
```

### 2. Integration/Security Tests (Infra & Glue)

Tests the "unbreaking" nature. Checks rate limits, database integrity, and funds validation.
These tests spin up a real in-memory SQLite instance.

```bash
# Run all security tests (by filtering for 'security_tests' substring)
cargo test --workspace

# Run specific filesystem security tests
cargo test --test filesystem_security_tests
```

### 3. Frontend Unit Tests (Vitest)

Tests Svelte components and utility TS functions.

```bash
cd apps/desktop
npm run test:unit
```

### 4. End-to-End Tests (Playwright)

Tests the compiled binary in a simulated OS environment.

```bash
# First time setup
npx playwright install

# Run E2E
npm run test:e2e
```

---

## 7. Security Best Practices

Aroeira is "Security First". As a developer, you are the first line of defense. The application includes a comprehensive security module at `libs/infra/src/security.rs`.

### 🔒 Secure Coding Practices

1.  **Path Sanitization**: Never use `std::fs` directly with user input. Use the `infra::security::PathValidator` to ensure no directory traversal attacks (`../../`) are possible.
2.  **Atomic File Creation**: Use `infra::security::SecureFileCreator` to prevent race conditions (TOCTOU) and symlink attacks.
3.  **No Plain Text Secrets**: If you need to store a token, use the `infra::services::secure_storage` module. This delegates to Keychain/DPAPI.
4.  **Strict CSP**: Do not modify `tauri.conf.json` CSP settings to allow `unsafe-inline` or remote scripts without a written ADR.

### 🔒 Using Security Modules

#### SecureFileCreator

```rust
use infra::security::SecureFileCreator;

// Good: Atomic creation + restrictive permissions (0o600)
let creator = SecureFileCreator::new();
creator.write_string(&secret_path, "my-secret-key")?;
```

#### PathValidator

```rust
use infra::security::PathValidator;

// Good: Validates path against traversal and symlinks
let validator = PathValidator::new();
let result = validator.validate(&user_input_path)?;
```

### 🕵️ Audit

Before pushing, check for vulnerabilities in the supply chain:

```bash
cargo audit
npm audit --prefix apps/desktop
```

---

## 8. Release & CI/CD

We use **Conventional Commits** to automate releases via `release-plz`.

### Commit Message Format

Your commit messages drive the versioning system.

- `fix(auth): handle null token` -> Bump Patch (v0.1.0 -> v0.1.1)
- `feat(ui): add dark mode` -> Bump Minor (v0.1.0 -> v0.2.0)
- `feat(api)!: breaking change` -> Bump Major (v1.0.0 -> v2.0.0)

### The CI Pipeline

On every PR, GitHub Actions will:

1.  Run `cargo fmt` and `cargo clippy`.
2.  Run `npm run lint`.
3.  Execute the **Security Test Suite**.
4.  Build the binary to ensure compilation.

Only green builds can be merged to `main`.

---

## 9. Troubleshooting

### "Tauri command not found"

- **Cause**: You defined the command in Rust but didn't register it in `main.rs` inside the `generate_handler![]` macro.
- **Fix**: Add the function name to the handler macro in `apps/desktop/src-tauri/src/main.rs`.

### "SQLx verification failed"

- **Cause**: Your `.env` `DATABASE_URL` doesn't match the schema expected by the code, OR you haven't run `cargo sqlx prepare`.
- **Fix**: Run `sqlx migrate run` and then `cargo sqlx prepare --workspace`.

### "Symlink error in tests"

- **Cause**: You might be running tests on Windows without "Developer Mode" enabled, which restricts Symlink creation.
- **Fix**: Enable Developer Mode in Windows Settings or run your terminal as Administrator.

### "Lefthook access denied"

- **Cause**: Script permissions.
- **Fix**: `chmod +x .github/hooks/*` and `chmod +x check_project.sh`.

---

<div align="center">

**Built with resilience.**
_Aroeira Template Team_

</div>
