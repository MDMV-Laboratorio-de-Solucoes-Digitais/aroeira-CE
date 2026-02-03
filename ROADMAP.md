# 🗺️ Project Roadmap: Aroeira

This document defines the strategic direction of the **Aroeira** project, a modern full-stack template designed to accelerate production application development.

---

## 🎯 Project Vision

### Purpose and Goals

**Aroeira** is a modern full-stack application template that combines the best technologies and development practices to create a solid foundation for production applications.

**Core Vision:**

- Become the reference template for modern full-stack applications.
- Drastically reduce the time from "Hello World" to "Production Application".
- Provide a productive, scalable, and maintainable architecture from day one.
- Offer an exceptional developer experience (DX).

**Target Audience:**

- Developers looking to verify ideas quickly.
- Teams seeking a consistent and tested architecture.
- Startups needing to go from concept to production fast.
- Companies wanting to standardize their development processes.

**Use Cases:**

- Modern Web Apps (SaaS, dashboards, admin panels).
- Cross-platform Multiplatform Apps (via Tauri).
- Robust RESTful APIs.
- Systems requiring strict quality control (Linting, Testing).

---

## 📊 Current Status

### Overview

The Aroeira project has its **technical foundation established**. The infrastructure, architecture, and quality tooling are fully configured. Functional features (like Auth) are currently in the planning/implementation stage.

**Completed (✅):**

- ✅ **Modular Monolith Architecture**: Workspace configured with `apps/desktop`, `libs/domain`, and `libs/infra`.
- ✅ **Tauri v2 + Svelte 5**: Frontend configured with Runes mode and Tailwind CSS v4.
- ✅ **Infrastructure Logic**: Database connection with automatic fallback (PostgreSQL -> SQLite).
- ✅ **Quality "Aroeira"**: Lefthook (Git Hooks), Cocogitto (SemVer), and GitHub Actions (CI/CD) configured.
- ✅ **UI Components**: Shadcn/UI initialized with Tailwind v4 utilities.

**In Progress (🔄):**

- 🔄 Authentication & Authorization (OAuth2/JWT).
- 🔄 Internationalization (i18n).
- 🔄 CLI for code scaffolding.
- 🔄 Database Migrations setup.

**Ready for:**

- 🚀 Development of core domain business logic (Vertical Slices).
- 🚀 Implementation of specific UI screens.

---

## 🚀 Phased Roadmap

### Phase 1: Foundation (Completed)

**Goal:** Establish the technical base and project infrastructure.

**Status:**

- ✅ **Modular Monolith & Vertical Slice Architecture**
  - Rust Workspace configured.
  - Dependency flow enforced (`infra` depends on `domain`).
- ✅ **CI/CD Pipeline & Quality**
  - **Lefthook**: Pre-commit hooks for formatting and linting.
  - **Cocogitto**: Conventional Commits enforcement.
  - **GitHub Actions**: Automated testing and linting on push/PR.
  - **Release-plz**: Automated release PRs and changelogs.

- ✅ **UI/UX Foundation**
  - **Shadcn/UI**: Integrated.
  - **Tailwind CSS v4**: Configured with Vite plugin.
  - **Svelte 5**: Runes syntax enabled.

- ✅ **Backend Foundation**
  - **Axum**: Web framework setup.
  - **SeaORM**: ORM setup with connection logic.
  - **Resilience**: Automatic fallback to local SQLite if Postgres is unavailable.

- ⏳ **Scaffolding System**
  - _Correction_: Currently manual via `cargo/npm`. A dedicated CLI tool is planned.

- ⏳ **Internationalization**
  - _Correction_: Paraglide-js setup is pending.

---

### Phase 2: Core Features (Current Focus)

**Goal:** Implement essential functionalities for production applications.

**In Progress:**

#### Authentication & Authorization

- [ ] JWT Authentication System
- [ ] Refresh tokens
- [ ] OAuth2 (Google, GitHub)
- [ ] Role-based access control (RBAC)
- [ ] Route protection
- [ ] Auth Middleware

#### User Management

- [ ] Complete User CRUD
- [ ] User Profiles
- [ ] Password Management
- [ ] Password Recovery
- [ ] Email Verification
- [ ] Session Management

#### Database & Data

- [ ] Migration System (SeaORM Migrations)
- [ ] Seeding Scripts

#### Testing Infrastructure

- [x] Unit Testing (Rust backend)
- [ ] Component Testing (Frontend)
- [ ] Integration Testing
- [ ] E2E Testing (Playwright)

**Estimated Timeline:** 4-6 weeks

---

### Phase 3: Enhanced Features

**Goal:** Add advanced functionalities that differentiate the template.

#### Real-Time Features (WebSockets)

- [ ] WebSocket Server (Axum)
- [ ] Communication Channels
- [ ] Real-time Updates

#### File Management

- [ ] File Uploads
- [ ] Local & Cloud Storage (S3)
- [ ] Image Processing

#### Notification System

- [ ] In-app Notifications
- [ ] Email Notifications
- [ ] Push Notifications (Desktop/Web)

#### Background Jobs

- [ ] Queue System
- [ ] Async Processing
- [ ] Job Scheduling

**Estimated Timeline:** 6-8 weeks

---

### Phase 4: Advanced Features

**Goal:** Implement advanced functionalities for production applications.

- [ ] Advanced Analytics
- [ ] Plugin System
- [ ] Advanced Security (Rate limiting, WAF, Auditing)
- [ ] Performance Optimization (Caching, CDN)

**Estimated Timeline:** 8-10 weeks

---

### Phase 5: Expansion

**Goal:** Expand to new platforms and technologies.

- [ ] Mobile Application (React Native or Flutter)
- [ ] GraphQL API
- [ ] Machine Learning Integration
- [ ] Advanced Reporting

**Estimated Timeline:** 10-12 weeks

---

## ⏱️ Timeline and Milestones

| Phase                      | Status             | Notes                                                              |
| -------------------------- | ------------------ | ------------------------------------------------------------------ |
| **Phase 1: Foundation**    | ✅ **Completed**   | Core structure, tooling, CI/CD, and DB fallback logic implemented. |
| **Phase 2: Core Features** | 🔄 **In Progress** | Focus on Auth, Migrations, and basic CRUD.                         |
| **Phase 3: Enhanced**      | ⏳ Planned         | Real-time, Files, Notifications.                                   |
| **Phase 4: Advanced**      | ⏳ Planned         | Security.                                                          |
| **Phase 5: Expansion**     | ⏳ Planned         | Mobile, GraphQL.                                                   |

---

## 🔧 Technical Considerations

### Architecture Decisions

**Backend:**

- **Rust (Axum)**: High performance and safety.
- **SeaORM**: Async ORM with dynamic dispatch for Postgres/SQLite.
- **PostgreSQL**: Primary production database.
- **SQLite**: Fallback/Local database for multiplatform app capabilities.

**Frontend:**

- **Svelte 5**: Using Runes for fine-grained reactivity.
- **Tailwind CSS v4**: High-performance styling engine.
- **Shadcn/UI**: Accessible, customizable component library.
- **Tauri v2**: Backend-frontend bridge for desktop.

**DevOps & Quality:**

- **Lefthook**: Enforces quality _before_ commits (Format, Lint, Test).
- **Cocogitto**: Automates versioning and changelogs.
- **Docker**: Containerized development environment (Postgres).

### Quality Standards

- **Rust**: `cargo clippy --workspace -- -W clippy::pedantic -D warnings` and `cargo fmt` enforced.
- **JS/Svelte**: `eslint` and `prettier` enforced.
- **Commits**: Must follow Conventional Commits specification.
- **CI**: GitHub Actions acts as the source of truth for build verification.

---

## 🔮 Future Features & Detailed Roadmap

This section outlines the strategic vision and detailed technical tasks for the **Aroeira** project.

### 📅 Short Term (Core Features)

#### 🔐 Authentication & Security

- [ ] **OAuth2 Integration**: Implement the `OAuthService` in `infra`.
- [ ] **Deep Linking**: Configure Tauri to handle `aroeira://` protocol for auth callbacks.
- [ ] **Secure Storage**: Integrate `tauri-plugin-store` or system keychain for token storage.

#### 💾 Data Management

- [ ] **Migrations**: Finalize SeaORM migration setup for both Postgres and SQLite.
- [ ] **Sync Engine**: Basic logic to sync local SQLite data with remote Postgres when online.

### 🔮 Medium Term (Enhanced UX)

#### 🔔 Notifications

- [ ] **In-App Toasts**: Using Shadcn/Sonner.
- [ ] **System Notifications**: Using Tauri's notification API.

#### 🌍 Internationalization (i18n)

- [ ] **Paraglide-JS**: Full integration for type-safe translations in Svelte 5.

### 🚀 Long Term (Scale)

#### 📱 Mobile Expansion

- [ ] **Tauri Mobile**: Adapt the `apps/desktop` codebase to run on iOS/Android via Tauri Mobile.

#### 🧠 AI Integration

- [ ] **Local LLM**: Integration with local models (e.g., Llama) via Rust bindings for offline AI features.

---

_Last Updated: January 2026_
