# 🚀 Deployment & Distribution

This guide covers the distribution of the **Aroeira** Multiplatform Application (Tauri) and the deployment of the backing infrastructure (PostgreSQL).

## 📋 Table of Contents

1. [Desktop App Distribution](#desktop-app-distribution)
2. [Infrastructure Deployment](#infrastructure-deployment)
3. [CI/CD Pipeline](#cicd-pipeline)

---

## 🖥️ Multiplatform App Distribution

We use **Tauri v2** to build cross-platform native applications.

### 1. Build for Production

To build the application for your current OS:

```bash
cd apps/desktop
npm run tauri build
```

This command produces optimized binaries in `apps/desktop/src-tauri/target/release/bundle/`.

### 2. Multi-Platform Building (CI)

We utilize **GitHub Actions** to build for Windows, Linux, and macOS automatically on release.

**Workflow:** `.github/workflows/release-plz.yml` (and potentially a dedicated `release-desktop.yml` in the future).

### 3. Signing

**Windows & macOS:**
Code signing is required for distribution to avoid security warnings.

- **Windows**: Requires a Code Signing Certificate (EV or Standard).
- **macOS**: Requires an Apple Developer ID and Notarization.

_Configuration goes into `apps/desktop/src-tauri/tauri.conf.json` under `bundle` settings._

---

## 🗄️ Infrastructure Deployment

The application is designed to be **Local-First** (SQLite), but it supports a remote **PostgreSQL** for synchronization or multi-user features.

### 1. Docker Deployment (Recommended)

You can deploy the database using the provided `docker-compose.yml` on any server with Docker installed (e.g., Coolify, DigitalOcean, AWS EC2).

```bash
# Production docker-compose example
version: '3.8'
services:
  db:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: app_db
    volumes:
      - db_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
```

### 2. Managed Database

You can also use managed PostgreSQL services (Neon, Supabase, AWS RDS). Just provide the connection string to the application via configuration or environment variables.

---

## 🔄 CI/CD Pipeline

The project relies on **GitHub Actions** for continuous integration and delivery.

### Pipelines

1.  **CI (`ci.yml`)**:
    - Runs on every Push/PR.
    - Executes: `cargo test`, `cargo clippy`, `cargo fmt`, `npm run check` (Svelte).
    - **Goal**: Ensure code quality and preventing regressions.

2.  **Release (`release-plz.yml`)**:
    - Runs on Push to `main`.
    - Uses `release-plz` to automate:
      - Version bumping (Cargo.toml, package.json).
      - Changelog generation.
      - Creating GitHub Releases.
    - **Goal**: Automate SemVer and Release management.

### Quality Gates

We enforce "Aroeira" quality gates:

- **Lefthook**: Runs locally before you can even push.
- **CI**: Blocks merging if tests or linting fails.

---

## 🔒 Security Deployment

### Security Pre-Deployment Checklist

Before deploying any security-related changes, ensure the following items are completed:

- [ ] All security tests pass
- [ ] Code review completed
- [ ] Static analysis completed (cargo-audit, cargo-clippy)
- [ ] Memory safety verified (Miri, Valgrind)
- [ ] Cross-platform testing completed
- [ ] Performance impact assessed
- [ ] Rollback plan prepared
- [ ] Security metrics monitoring configured
- [ ] Incident response procedures documented
- [ ] Key rotation schedule maintained

### Security Monitoring Setup

Configure monitoring for security-relevant metrics:

| Metric                      | Threshold  | Alert Type | Response Time |
| --------------------------- | ---------- | ---------- | ------------- |
| **Failed Auth Attempts**    | > 100/hour | Warning    | Immediate     |
| **Rate Limit Violations**   | > 50/hour  | Warning    | Immediate     |
| **Device ID Regenerations** | > 10/hour  | Warning    | Immediate     |
| **HMAC Key Rotations**      | Any        | Info       | Immediate     |
| **Memory Usage**            | > 90%      | Critical   | Immediate     |
| **Error Rate**              | > 5%       | Critical   | Immediate     |

### Rollback Procedures for Security Issues

If security issues are detected post-deployment:

1. **Immediate Rollback**

   ```bash
   # Rollback to previous version
   git revert <commit_hash>

   # Rebuild and redeploy
   cd apps/desktop
   npm run tauri build
   ```

2. **Investigation**
   - Collect logs and metrics
   - Analyze root cause
   - Document findings
   - Notify security team

3. **Fix and Test**
   - Implement fix in isolated branch
   - Run comprehensive security tests
   - Validate fix resolves issue
   - Update documentation

4. **Re-deploy with Monitoring**
   - Deploy with increased monitoring
   - Monitor for 24 hours
   - Gradual rollout if needed

### Security Incident Response

#### Incident Severity Levels

| Severity     | Response Time | Actions Required                               |
| ------------ | ------------- | ---------------------------------------------- |
| **Critical** | < 1 hour      | Immediate rollback, security team notification |
| **High**     | < 4 hours     | Rollback, investigation, notification          |
| **Medium**   | < 24 hours    | Investigation, mitigation planning             |
| **Low**      | < 72 hours    | Documentation, monitoring                      |

#### Incident Response Process

1. **Detection**
   - Automated monitoring alerts
   - User reports
   - Security audit findings

2. **Assessment**
   - Determine severity level
   - Identify affected systems
   - Assess business impact

3. **Containment**
   - Isolate affected systems if needed
   - Implement temporary mitigations
   - Preserve evidence

4. **Eradication**
   - Remove root cause
   - Apply permanent fix
   - Validate fix effectiveness

5. **Recovery**
   - Restore normal operations
   - Monitor for recurrence
   - Update documentation

6. **Lessons Learned**
   - Document incident
   - Update security procedures
   - Implement preventive measures

### Key Rotation Procedures

#### Automatic Key Rotation

The system implements automatic HMAC key rotation for device identification:

| Configuration             | Default Value | Purpose                            |
| ------------------------- | ------------- | ---------------------------------- |
| **Rotation Interval**     | 90 days       | Limits key exposure window         |
| **Grace Period**          | 30 days       | Allows validation during rotation  |
| **Previous Keys Storage** | Up to 3 keys  | Validates signatures from old keys |

#### Manual Key Rotation

If manual key rotation is required:

```bash
# 1. Generate new key
# 2. Update key store
# 3. Verify old keys still work during grace period
# 4. After grace period, remove old keys
```

### Metrics and Alerting Configuration

#### Security Metrics to Track

```rust
// In apps/desktop/src-tauri/src/commands/auth.rs
pub struct SecurityMetrics {
    pub failed_auth_attempts: AtomicU64,
    pub successful_auth_attempts: AtomicU64,
    pub rate_limit_violations: AtomicU64,
    pub device_id_regenerations: AtomicU64,
    pub hmac_key_rotations: AtomicU64,
    pub symlink_detection_attempts: AtomicU64,
    pub path_traversal_attempts: AtomicU64,
}
```

#### Alerting Configuration

```yaml
# Example alerting configuration
alerts:
  security:
    enabled: true
    channels:
      - email: security-team@example.com
      - slack: #security-alerts
    rules:
      - name: "High failed auth rate"
        condition: "metrics.failed_auth_attempts > 100 per hour"
        severity: "warning"
      - name: "Rate limit violations"
        condition: "metrics.rate_limit_violations > 50 per hour"
        severity: "warning"
      - name: "Memory usage critical"
        condition: "metrics.memory_usage > 90%"
        severity: "critical"
```

### Post-Deployment Security Testing

After deployment, conduct security testing:

1. **Penetration Testing**
   - Test authentication flows
   - Test file system security
   - Test rate limiting effectiveness
   - Test device identification

2. **Load Testing**
   - Test under high load
   - Verify rate limiting works correctly
   - Monitor memory usage
   - Test race conditions

3. **Security Regression Testing**
   - Verify all security fixes still work
   - Test bypass attempts
   - Validate error messages don't leak information

### Security Deployment Best Practices

1. **Gradual Rollout**
   - Phase 1: Canary deployment (5% of users)
   - Phase 2: Expand to 25% after 1 week
   - Phase 3: Expand to 50% after 1 week
   - Phase 4: Full rollout after 2 weeks

2. **Feature Flags**
   - Use feature flags to enable/disable security features
   - Allow quick rollback by disabling features
   - Test in production with small audience first

3. **Monitoring-First Deployment**
   - Deploy with enhanced monitoring
   - Collect baseline metrics
   - Compare with pre-deployment metrics
   - Rollback if significant degradation

4. **Security Hardening**
   - Verify all security features enabled
   - Validate configuration settings
   - Check for security misconfigurations
   - Test incident response procedures
