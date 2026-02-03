# 📦 Open Source Template Profile

This profile aims to provide a robust, standard, and accessible foundation for community projects. The focus is on ease of contribution, standard tooling, and clear architecture.

## ✅ Implemented Features (Foundation)

### Architecture & Core

- [x] **Modular Monolith**: Clean separation between `apps`, `libs/domain`, and `libs/infra`.
- [x] **Rust Workspace**: Standard Cargo workspace setup.
- [x] **Tauri v2 + Svelte 5**: Modern, high-performance tech stack.
- [x] **Database Agnosticism (Basic)**: SeaORM with Postgres/SQLite support (essential for running locally vs production).
- [x] **Database Fallback**: SQLite for easy local dev/multiplatform apps, Postgres for scalable web/cloud.

### Quality & DX

- [x] **Lefthook**: Git hooks for standardization without heavy CI dependence.
- [x] **Conventional Commits**: `cocogitto` for standardized history.
- [x] **Linting & Formatting**: Prettier, ESLint, Rustfmt, Clippy.
- [x] **GitHub Actions**: Basic CI for testing and linting.

### UI & UX

- [x] **Tailwind CSS v4 + Shadcn/UI**: Production-ready UI components for rapid UI building.

## 🚀 Features to Implement (Roadmap)

### Documentation & Community

- [x] **Comprehensive README**: Badges, quick start, contribution guide.
- [x] **CONTRIBUTING.md**: Clear guidelines for PRs, issues, and coding standards.
- [x] **Issue Templates**: Bug report and feature request templates.
- [x] **Discussion Board**: Setup GitHub Discussions.

### Core Functionality

- [x] **Basic Auth**: Simple Email/Password authentication.
- [x] **Example CRUD**: A reference "Todo" or "Notes" module to demonstrate architecture.
- [x] **CLI Scaffolding (Basic)**: Simple script to rename project and reset git history.
- [x] **Docker Compose**: Basic setup for spinning up dependencies (Postgres).
- [ ] **Simplified CLI (DX)**: A unified CLI tool to streamline development tasks.
  - **Wrappers**: Abstract complex `cargo` and `npm` commands (e.g., `aroeira dev`, `aroeira build`).
  - **Generators**: Quickly scaffold new entities, resources, or migration files.
  - **Health Checks**: Diagnostic tools to verify environment setup (DB connection, dependencies).

### UI & UX

- [x] **Tailwind CSS v4 + Shadcn/UI**: Production-ready UI components for rapid UI building.
- [ ] **2 Basic Themes**: Pre-configured themes to demonstrate flexibility.
  - **Light & Dark Mode**: Standard OS-aware toggle.
  - **"Vibrant" Theme**: High-contrast, colorful palette for consumer-facing apps.

### Deployment

- [ ] **GitHub Pages**: For documentation or static frontend preview.
- [ ] **Release Automation**: `release-plz` or similar for automating crates.io/npm publishing.

## ❌ Excluded (Out of Scope for Base OSS)

- Advanced Multi-tenancy.
- Enterprise SSO (SAML/LDAP).
- Complex Billing/Subscription logic.
- Cloud-specific infrastructure code (Terraform/AWS CDK) - keep it cloud-agnostic.
