# Contributing to Aroeira

First of all, thank you for your interest in contributing to Aroeira. ❤️

**Aroeira** is not just a template; it is an opinionated statement on how secure, scalable multiplatform applications should be built. Just as the Aroeira tree produces the hardest wood in the ecosystem, we expect contributions to be solid, durable, and architecturally sound.

This document serves as the comprehensive guide for contributing to the repository. It covers our architectural standards, development workflows, testing requirements, and the strict security protocols we enforce.

## Table of Contents

- [The Aroeira Philosophy](#the-aroeira-philosophy)
- [Development Prerequisites](#development-prerequisites)
- [Architectural Guidelines](#architectural-guidelines)
- [Development Workflow](#development-workflow)
- [Testing Strategy](#testing-strategy)
- [Security Standards](#security-standards)
- [Commit Convention](#commit-convention)
- [Pull Request Process](#pull-request-process)
- [Code of Conduct](#code-of-conduct)

## 🪵 The Aroeira Philosophy

Before writing code, understand the core tenets of this project:

1.  **Hard to Break**: We prefer compile-time safety over runtime checks. If Rust can catch it, let it.
2.  **Security First**: Security is not an afterthought. We actively mitigate risks (Symlinks, ACLs, Memory Safety) at the architectural level.
3.  **Strict Boundaries**: We use a **Modular Monolith** approach. Domain logic never touches the frontend directly; it goes through the interface layers.

## 🛠 Development Prerequisites

Ensure your environment is set up correctly to avoid friction with our automation tools.

### Required Tools

- **Rust**: Latest stable version (`rustup update stable`).
- **Node.js**: LTS version (v20+ recommended).
- **Package Manager**: `npm` (as per the lockfile present in the repo).
- **Tauri CLI**: `npm install -g @tauri-apps/cli` or via cargo `cargo install tauri-cli`.
- **System Dependencies**: Ensure you have the build tools for your OS (C++ build tools for Windows, Xcode Command Line Tools for macOS, generic `build-essential`/`libwebkit2gtk` for Linux).

### Environment Setup

1.  Clone the repository:

    ```bash
    git clone https://github.com/MDMV-Laboratorio-de-Solucoes-Digitais/aroeira-template.git
    cd aroeira-template
    ```

2.  Install dependencies:

    ```bash
    # Frontend dependencies
    cd apps/desktop
    npm install
    cd ../..
    ```

3.  **Initialize Git Hooks (Crucial)**: We use Lefthook to enforce quality checks locally.

    ```bash
    # If you have lefthook installed globally
    lefthook install
    # Or rely on the pre-configured git hooks if installed via npm scripts
    ```

4.  Environment Variables:
    ```bash
    cp .env.example .env
    # Configure your secret keys in .env
    ```

## 🏗 Architectural Guidelines

Aroeira follows a **Vertical Slice** / **Modular Monolith** architecture within a Rust Workspace. You must place your code in the correct location.

### 1. `libs/domain` (The Core)

- **Purpose**: Pure business logic and type definitions.
- **Rules**:
  - NO external side effects (Database, HTTP, File System).
  - NO framework dependencies (Tauri, Svelte).
  - Everything must be testable via unit tests alone.

### 2. `libs/infra` (The Mechanism)

- **Purpose**: Implementation of interfaces defined in the domain.
- **Contains**: Database repositories (SQLx), File System wrappers, OS-level security implementations (Keychains, Windows ACLs).
- **Rules**: This is the only place where `unsafe` operations (IO) should occur.

### 3. `apps/desktop` (The Glue)

- **Purpose**: The entry point.
- **Contains**:
  - **Rust**: Tauri Commands (Controllers) that call into domain or infra.
  - **Svelte**: The UI presentation layer.
- **Rules**: Keep the Rust `main.rs` and commands thin. Delegate logic to the libraries.

## 🔄 Development Workflow

### Branching Strategy

We generally follow a simplified Git Flow:

- `main`: The stable production branch.
- `feature/your-feature-name`: For new capabilities.
- `fix/bug-description`: For repairing issues.

### Running the App

To run the full desktop application in development mode:

```bash
npm run tauri dev --prefix apps/desktop
```

## 🧪 Testing Strategy

We rely on three layers of testing. A PR will not be accepted if these tests fail.

### 1. Unit Tests (Rust)

Test pure domain logic.

```bash
cargo test --workspace --lib
```

### 2. Security & Integration Tests (Rust)

Located in the `tests/` folder at the workspace root. These verify the "unbreaking" nature of the app, checking for regressions in security features (like Rate Limiting or Symlink protection).

**Mandatory for all PRs:**

```bash
cargo test --workspace
```

### 3. Frontend Tests (Vitest)

For Svelte components and utility logic.

```bash
cd apps/desktop
npm run test:unit
```

### 4. End-to-End Tests (Playwright)

Validates the built application logic.

```bash
npx playwright install
npm run test:e2e
```

## 🛡 Security Standards

Aroeira is a security-hardened template. Contributions that weaken the security posture will be rejected.

- **No Unsafe Rust**: Avoid `unsafe` blocks unless absolutely necessary and documented with a `// SAFETY:` comment explaining why the invariant holds.
- **Dependency Auditing**: New dependencies must be justified. Supply chain attacks are a threat; do not add crates that are unmaintained.
- **Strict CSP**: The Content Security Policy is configured in `tauri.conf.json`. Do not relax these settings (e.g., allowing `unsafe-inline` scripts) without a critical architectural reason.
- **Path Sanitization**: All file system operations must use the validated paths provided by the infra layer. Never accept raw strings as paths from the frontend without validation.

### Security Review Checklist

All code changes undergo a security review process. Ensure your contribution covers:

- [ ] Code follows security best practices in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)
- [ ] All security tests pass
- [ ] No new security vulnerabilities introduced
- [ ] Error messages are generic and safe (no internal path leaking)
- [ ] No sensitive data logged
- [ ] Proper input validation implemented
- [ ] Authentication and authorization properly implemented
- [ ] Rate limiting applied where appropriate
- [ ] Security-critical comparisons use constant-time operations to prevent timing attacks

## 📝 Commit Convention

We use **Conventional Commits** to automate our release process using `release-plz`.

**Format**: `<type>(<scope>): <description>`

- `feat`: A new feature (triggers a minor version bump).
- `fix`: A bug fix (triggers a patch version bump).
- `docs`: Documentation only changes.
- `style`: Changes that do not affect the meaning of the code (white-space, formatting).
- `refactor`: A code change that neither fixes a bug nor adds a feature.
- `perf`: A code change that improves performance.
- `test`: Adding missing tests or correcting existing tests.
- `chore`: Changes to the build process or auxiliary tools.

**Example**:
`feat(auth): implement OAuth2 PKCE flow`

> **Note**: `lefthook` will likely check your commit message format before allowing the commit.

## 📥 Pull Request Process

1.  **Self-Review**: Before opening a PR, run the "Compliance Check".

    ```bash
    # This runs formatting, linting, and tests
    ./check_project.sh

    # OR manual checks:
    cargo fmt --all -- --check
    cargo clippy -- -D warnings
    npm run lint --prefix apps/desktop
    ```

2.  **Description**: Fill out the PR template completely. Link to the issue being fixed.

3.  **CI Checks**: Ensure all GitHub Actions pass. We run:
    - `audit`: Checks for security vulnerabilities.
    - `test`: Runs the test suite.
    - `lint`: Checks code style.

4.  **Review**: A maintainer will review your code. Be open to feedback regarding strict type usage and architectural boundaries.

<div align="center">

"Hard to say. Impossible to break."

Thank you for helping us build the toughest multiplatform template.

</div>

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](docs/CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.
