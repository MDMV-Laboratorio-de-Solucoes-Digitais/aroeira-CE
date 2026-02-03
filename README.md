# 🛡️ Aroeira - Modular Monolith Template

<div align="center">

Hard to say. Impossible to break.

**⚠️ Beta Phase Notice**

This project is currently in technical refinement phase. We encourage vulnerability exploration and bug reporting as part of the tool's hardening process.

</div>

## 🪵 What is Aroeira?

**Aroeira** (it's pronounced IPA: `/a.ɾoˈej.ɾa/`) is an opinionated, production-ready template for building secure, scalable, and high-performance multiplatform applications using **Tauri**, **Rust**, and **Svelte**.

### Rust & The Unbreaking Wood

The name comes from the **Aroeira** tree (_Myracrodruon urundeuva_), native to the Brazilian Caatinga and Cerrado. It produces the hardest, densest wood in the country.

Just as **Rust** (the metal oxide) consumes iron, **Rust** (the language) prevents memory corruption. We combined the memory safety of Rust with the structural integrity of Aroeira.

> **The Pronunciation**: It's harder to speak Aroeira than it is to build with it - It requires a rolling "r" and a triple vowel diphthong.
>
> _Ah - roh - ey - rah_

**Aroeira is dense, tough, and enduring.**

## 🏗 Architecture & Features

Aroeira fence posts ("mourões") are known to stand firm in the harsh sun and rain for over 100 years without rotting.

With that in mind, Aroeira template is engineered for longevity and maintainability, employing **Modular Monolith** and **Vertical Slices Architecture** within a **Rust Workspace**.

### The Stack

- **Core**: Rust (_The Aroeira_)
- **Framework**: Tauri v2 (_Security-hardened_)
- **Frontend**: Svelte 5 + TailwindCSS
- **UI Components**: Shadcn-Svelte
- **Build System**: Vite

### Key Features

- **🛡️ Security First**: Pre-configured with rate limiting, secure storage, Windows ACL hardening, and strict CSP. See our Security Checklist.
- **🧠 Clean Architecture**: Logic is separated into a workspace structure:
  - `apps/desktop`: The Tauri frontend/glue layer.
  - `libs/domain`: Pure business logic (framework agnostic).
  - `libs/infra`: Database connections, file systems, and external services.
- **⚡ Developer Experience**:
  - **Lefthook**: Git hooks for formatting and linting before commits.
  - **Release-plz**: Automated changelogs and release management.
  - **CI/CD**: GitHub Actions workflows ready for compliance checks and building.
- **🔒 Authentication Ready**: Includes boilerplates for Login, Registration, and OAuth2 flows.

## 🚀 Getting Started

### Prerequisites

Ensure you have the following installed:

- **Rust & Cargo** (`rustup`)
- **Node.js** & `npm`
- **Tauri CLI**
- **Docker** (Optional, for running infrastructure containers)

### Installation

Clone the repository:

```bash
git clone https://github.com/MDMV-Laboratorio-de-Solucoes-Digitais/aroeira-template.git
cd aroeira-template
```

Install dependencies:

```bash
# Install frontend dependencies
cd apps/desktop
npm install
# Return to root
cd ../..
```

Initialize the environment:

```bash
cp .env.example .env
# Configure your secret keys in .env
```

Run the development server:

```bash
npm run tauri dev --prefix apps/desktop
```

## 📂 Project Structure

```plaintext
aroeira-template/
├── .github/              # CI/CD Workflows (Compliance, Release, Build)
├── apps/
│   └── desktop/          # The Tauri Application (Svelte Frontend + Glue code)
├── libs/
│   ├── domain/           # Pure Rust Business Logic (The Core)
│   └── infra/            # Database Repositories, Services, Security Implementations
├── plans/                # Architecture Decision Records (ADRs) and Features
├── tests/                # Integration and Security Tests
└── Cargo.toml            # Workspace definition
```

## 🛡️ Security & Hardening

Aroeira takes security seriously. We don't just wrap a web view; we harden the binary with multiple protection layers.

### Security Layers

- **Secure Storage**: Sensitive data is stored using OS-level keychains (Keychain on macOS, Data Protection API on Windows, Secret Service API on Linux). See [Security Architecture](docs/ARCHITECTURE.md#4-security-architecture).
- **Rate Limiting**: Built-in mitigation against brute-force attacks on auth endpoints.
- **Filesystem Isolation**: Strict scoping of file access to prevent directory traversal.
- **Memory Safety**: Leveraging Rust's ownership model to prevent buffer overflows.
- **Security-First Testing**: Comprehensive security test suite validating filesystem protection, symlink attacks, and access control.

## 🗺️ Project Status & Roadmap

Aroeira **Community Edition** provides a stable, production-ready foundation for building secure multiplatform applications. The core architecture, security layers, and developer tooling are fully implemented and tested.

### What's Available Now

- ✅ Modular Monolith Architecture with Vertical Slices
- ✅ Complete CI/CD pipelines with compliance checks
- ✅ Security hardening (filesystem isolation, secure storage, rate limiting)
- ✅ Comprehensive testing suite including security tests
- ✅ Developer experience tooling (Lefthook, Cocogitto, Release-plz)

### What's In Progress

Complex features are deliberately staged in the roadmap to ensure quality over speed:

- 🔐 OAuth2 Authentication (planned - see [ROADMAP.md](ROADMAP.md))
- 📊 Database Migrations (in development)
- 🔔 Real-time features (WebSockets)
- 📁 Advanced file management

See the complete [ROADMAP.md](ROADMAP.md) for detailed implementation status. This phased approach ensures that each feature is properly designed, tested, and hardened before release.

### Security Test Verification

Run the security test suite to verify the integrity of the template:

```bash
# Run all tests in the workspace
cargo test --workspace

# Run specific security tests
cargo test --test filesystem_security_tests
```

This demonstrates our commitment to proactive security hardening, not negligence.

```bash
# Run all tests in the workspace
cargo test --workspace

# Or run specific security tests
cargo test --test filesystem_security_tests
```

## 🤝 Contributing

We believe in the strength of the community. If you want to contribute to the "unbreaking wood":

1. Read our `CONTRIBUTING.md` guide.
2. Check the `ROADMAP.md` for planned features.
3. Ensure your code passes all compliance checks (lefthook handles this locally).

## 📜 License

This project is licensed under the MIT License - see the `LICENSE` file for details.

<div align="center">

Built with resilience in Brazil 🇧🇷

</div>
