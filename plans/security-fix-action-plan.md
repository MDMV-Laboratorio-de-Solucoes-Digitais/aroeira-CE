# Aroeira Security Fix Action Plan

## Executive Summary

This comprehensive action plan addresses all security vulnerabilities identified in two PR reviews covering rate limiting/device ID generation and Windows ACL hardening implementations. The plan prioritizes critical issues that enable complete security bypasses, followed by high-severity issues that could lead to privilege escalation or data exposure.

### Key Findings Overview

- **Critical Issues**: 9 total (4 rate limiting, 5 Windows ACL)
- **High Issues**: 2 total (1 rate limiting, 1 Windows ACL)
- **Medium Issues**: 3 total (2 rate limiting, 1 Windows ACL)
- **Low Issues**: 5 total (all rate limiting)

The most severe vulnerabilities allow attackers to:

1. Completely bypass rate limiting by spoofing device IDs
2. Cause undefined behavior and potential memory corruption through unsafe pointer casting
3. Leak token handles leading to resource exhaustion
4. Fail compilation due to missing imports

---

## 1. Risk Assessment Matrix

### Rate Limiting & Device ID Issues

| Issue ID | Issue                                                        | Severity | Business Impact                                           | Likelihood | Risk Score |
| -------- | ------------------------------------------------------------ | -------- | --------------------------------------------------------- | ---------- | ---------- |
| RL-001   | Device ID uses environment variables (HOSTNAME/COMPUTERNAME) | CRITICAL | Complete rate limit bypass, unlimited brute force attacks | HIGH       | 9          |
| RL-002   | Asymmetric rate limit reset logic                            | HIGH     | Legitimate users remain throttled after successful auth   | MEDIUM     | 6          |
| RL-003   | No exponential backoff                                       | MEDIUM   | Attackers can retry exactly after 60 seconds              | HIGH       | 8          |
| RL-004   | No HMAC key rotation mechanism                               | MEDIUM   | Compromised key allows rate limit manipulation            | LOW-MEDIUM | 5          |
| RL-005   | Test code in production file                                 | LOW      | Code bloat, potential confusion                           | LOW        | 2          |
| RL-006   | No request IDs for tracing                                   | LOW      | Difficult debugging, security incident analysis           | MEDIUM     | 4          |
| RL-007   | No metrics for monitoring                                    | LOW      | No visibility into attack patterns                        | MEDIUM     | 4          |
| RL-008   | Potential race condition in rate limit check                 | LOW      | Edge case where rate limit could be exceeded              | LOW        | 2          |

### Windows ACL Issues

| Issue ID | Issue                                                  | Severity | Business Impact                                       | Likelihood | Risk Score |
| -------- | ------------------------------------------------------ | -------- | ----------------------------------------------------- | ---------- | ---------- |
| ACL-001  | Unsafe SID pointer casting (line 903, 915)             | CRITICAL | Undefined behavior, memory corruption, potential RCE  | HIGH       | 9          |
| ACL-002  | Missing error check for GetTokenInformation (line 890) | CRITICAL | Token handle leak, resource exhaustion                | MEDIUM     | 6          |
| ACL-003  | No ACL validation after creation                       | CRITICAL | Cannot confirm restrictive ACLs applied               | MEDIUM     | 6          |
| ACL-004  | Missing SE_FILE_OBJECT import                          | CRITICAL | Code won't compile, blocks deployment                 | CERTAIN    | 10         |
| ACL-005  | Incorrect rights mask (0xF003F)                        | HIGH     | Unclear permissions, potential over-privilege         | MEDIUM     | 6          |
| ACL-006  | Potential privilege escalation if ACLs misconfigured   | HIGH     | Unauthorized access to sensitive data                 | LOW-MEDIUM | 5          |
| ACL-007  | Incorrect inheritance flags for files                  | MEDIUM   | Files inherit directory ACLs unexpectedly             | MEDIUM     | 6          |
| ACL-008  | Unhelpful error messages                               | MEDIUM   | Difficult troubleshooting, security incident response | LOW        | 3          |
| ACL-009  | No file vs directory distinction                       | MEDIUM   | Inappropriate ACLs applied, potential access issues   | MEDIUM     | 6          |

### Risk Scoring Methodology

- **Severity**: CRITICAL (9), HIGH (7), MEDIUM (5), LOW (3)
- **Likelihood**: CERTAIN (10), HIGH (8), MEDIUM (5), LOW (3), VERY LOW (1)
- **Risk Score**: Severity × Likelihood (normalized to 1-10 scale)

---

## 2. Prioritized Fix Roadmap

### Phase 1: Critical Fixes (Week 1-2)

**Goal**: Address vulnerabilities that enable complete security bypasses or prevent compilation

#### Week 1: Compilation and Critical Security Bypass Fixes

**Priority 1: Fix Windows ACL Compilation (ACL-004)**

- **Effort**: 2 hours
- **Dependencies**: None
- **Impact**: Unblocks Windows build and testing

**Priority 2: Fix Device ID Generation (RL-001)**

- **Effort**: 16 hours
- **Dependencies**: None
- **Impact**: Prevents complete rate limit bypass

**Priority 3: Fix Unsafe SID Pointer Casting (ACL-001)**

- **Effort**: 8 hours
- **Dependencies**: ACL-004
- **Impact**: Eliminates undefined behavior and memory corruption risk

#### Week 2: Resource Management and Validation

**Priority 4: Fix Token Handle Leak (ACL-002)**

- **Effort**: 4 hours
- **Dependencies**: ACL-001
- **Impact**: Prevents resource exhaustion

**Priority 5: Add ACL Validation (ACL-003)**

- **Effort**: 12 hours
- **Dependencies**: ACL-001, ACL-002
- **Impact**: Ensures restrictive ACLs are correctly applied

### Phase 2: High Priority Fixes (Week 3-4)

**Goal**: Address issues that could lead to privilege escalation or degraded user experience

#### Week 3: Rate Limiting Improvements

**Priority 6: Fix Asymmetric Rate Limit Reset (RL-002)**

- **Effort**: 12 hours
- **Dependencies**: RL-001
- **Impact**: Improves legitimate user experience

**Priority 7: Add Exponential Backoff (RL-003)**

- **Effort**: 8 hours
- **Dependencies**: RL-002
- **Impact**: Increases attack cost for brute force

**Priority 8: Fix Incorrect Rights Mask (ACL-005)**

- **Effort**: 6 hours
- **Dependencies**: ACL-003
- **Impact**: Clarifies and secures permission model

#### Week 4: ACL Hardening

**Priority 9: Address Privilege Escalation Risk (ACL-006)**

- **Effort**: 16 hours
- **Dependencies**: ACL-005, ACL-003
- **Impact**: Prevents unauthorized access scenarios

**Priority 10: Fix Inheritance Flags (ACL-007)**

- **Effort**: 8 hours
- **Dependencies**: ACL-006
- **Impact**: Ensures appropriate ACL inheritance

### Phase 3: Medium Priority Fixes (Week 5-6)

**Goal**: Improve security posture and operational capabilities

#### Week 5: Key Management and Observability

**Priority 11: Implement HMAC Key Rotation (RL-004)**

- **Effort**: 20 hours
- **Dependencies**: None
- **Impact**: Limits exposure window for compromised keys

**Priority 12: Add Request IDs (RL-006)**

- **Effort**: 8 hours
- **Dependencies**: None
- **Impact**: Improves debugging and incident response

**Priority 13: Add Metrics (RL-007)**

- **Effort**: 16 hours
- **Dependencies**: RL-006
- **Impact**: Enables attack pattern detection

#### Week 6: Error Handling and Distinctions

**Priority 14: Improve Error Messages (ACL-008)**

- **Effort**: 6 hours
- **Dependencies**: None
- **Impact**: Facilitates troubleshooting

**Priority 15: Add File/Directory Distinction (ACL-009)**

- **Effort**: 12 hours
- **Dependencies**: ACL-008
- **Impact**: Ensures appropriate ACLs per type

### Phase 4: Low Priority Cleanup (Week 7)

**Goal**: Code quality and edge case handling

**Priority 16: Remove Test Code (RL-005)**

- **Effort**: 4 hours
- **Dependencies**: None
- **Impact**: Reduces code bloat

**Priority 17: Fix Race Condition (RL-008)**

- **Effort**: 8 hours
- **Dependencies**: None
- **Impact**: Eliminates edge case vulnerability

---

## 3. Detailed Implementation Strategies

### Critical Issue #1: Device ID Generation (RL-001)

#### Current Vulnerability

```rust
// apps/desktop/src-tauri/src/commands/auth.rs:54-71
fn get_device_id() -> String {
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        format!("host_{hostname}")
    } else if let Ok(computername) = std::env::var("COMPUTERNAME") {
        format!("host_{computername}")
    } else {
        format!("proc_{}", std::process::id())
    }
}
```

**Attack Vector**: Attacker can set `HOSTNAME` or `COMPUTERNAME` environment variable to bypass device-based rate limiting entirely.

#### Technical Approach

**Option A: Persistent Device Fingerprint (Recommended)**

1. Generate a unique device ID on first launch
2. Store encrypted in app data directory
3. Use hardware-specific entropy (MAC address, CPU ID, disk serial)
4. Include cryptographic signature to prevent tampering

**Option B: OS-Level Device Binding**

1. Use Windows Machine GUID or macOS IOPlatformUUID
2. Fall back to generated persistent ID
3. Bind to TPM/Secure Enclave where available

#### Architecture Recommendations

```rust
// Proposed structure
pub struct DeviceId {
    id: String,
    signature: String,
    created_at: SystemTime,
    last_validated: SystemTime,
}

impl DeviceId {
    pub fn new_or_load() -> Result<Self, DeviceIdError> {
        // Try to load from secure storage
        if let Some(stored) = Self::load_from_storage()? {
            if stored.validate() {
                return Ok(stored);
            }
        }
        // Generate new ID
        Self::generate()
    }

    fn generate() -> Result<Self, DeviceIdError> {
        let entropy = Self::collect_hardware_entropy()?;
        let id = Self::hash_entropy(entropy)?;
        let signature = Self::sign_id(&id)?;
        Ok(DeviceId { id, signature, created_at: SystemTime::now(), last_validated: SystemTime::now() })
    }
}
```

#### Testing Strategy

1. **Unit Tests**
   - Test ID generation on various platforms
   - Test persistence across application restarts
   - Test tampering detection

2. **Integration Tests**
   - Test rate limiting with spoofed environment variables
   - Test device ID rotation scenarios
   - Test migration from old to new ID format

3. **Security Tests**
   - Attempt to bypass using environment variable injection
   - Test ID tampering detection
   - Test replay attack prevention

#### Rollback Plan

1. Maintain backward compatibility with old device IDs during transition period
2. Feature flag to disable new device ID generation
3. Database migration script to update stored device IDs
4. Monitoring for increased rate limit failures during rollout

#### Success Criteria

- Device IDs cannot be spoofed via environment variables
- Device IDs persist across application restarts
- Rate limiting works correctly with new IDs
- No increase in legitimate user lockouts
- Performance impact < 5% overhead

---

### Critical Issue #2: Unsafe SID Pointer Casting (ACL-001)

#### Current Vulnerability

```rust
// libs/infra/src/database/mod.rs:903, 915
let token_user = &*(token_user_ptr as *const windows_sys::Win32::Security::TOKEN_USER);
trustee.ptstrName = user_sid.cast::<u16>(); // Cast SID pointer to expected type
```

**Attack Vector**: Undefined behavior from incorrect pointer casting could lead to memory corruption, potential RCE.

#### Technical Approach

**Use Proper Type Conversion**

```rust
// Correct approach using proper Windows API types
use windows_sys::Win32::Security::PSID;

let token_user = &*(token_user_ptr as *const windows_sys::Win32::Security::TOKEN_USER);
let user_sid: PSID = token_user.User.Sid; // No cast needed
trustee.ptstrName = user_sid as *mut u16; // Proper conversion
```

**Add Bounds Checking**

```rust
// Validate SID structure before use
if token_user.User.Sid.is_null() {
    return Err(anyhow::anyhow!("Invalid user SID: null pointer"));
}

// Validate SID structure
unsafe {
    if IsValidSid(token_user.User.Sid) == 0 {
        return Err(anyhow::anyhow!("Invalid SID structure"));
    }
}
```

#### Testing Strategy

1. **Unit Tests**
   - Test with various user contexts (admin, standard, guest)
   - Test with invalid SIDs
   - Test memory safety under load

2. **Integration Tests**
   - Test ACL application on different file types
   - Test with various permission scenarios
   - Test error handling paths

3. **Fuzz Testing**
   - Fuzz token information structures
   - Test with malformed SIDs
   - Test boundary conditions

#### Rollback Plan

1. Maintain both old and new implementations
2. Feature flag to switch between implementations
3. Extensive logging for comparison
4. Gradual rollout with monitoring

#### Success Criteria

- No undefined behavior detected by sanitizers
- All ACL tests pass on Windows
- No memory leaks detected
- ACLs applied correctly across scenarios

---

### Critical Issue #3: Token Handle Leak (ACL-002)

#### Current Vulnerability

```rust
// libs/infra/src/database/mod.rs:890-900
if GetTokenInformation(
    token_handle,
    1, // TokenUser
    token_user_ptr,
    token_info_size,
    &mut token_info_size,
) == 0
{
    CloseHandle(token_handle); // Handle closed only on error path
    return Err(anyhow::anyhow!("Failed to get token user information"));
}
// Handle NOT closed on success path - LEAK!
```

**Attack Vector**: Repeated ACL operations exhaust handle pool, causing denial of service.

#### Technical Approach

**Use RAII Pattern**

```rust
use std::ops::Deref;
use std::ops::DerefMut;

struct TokenHandle(HANDLE);

impl TokenHandle {
    fn open() -> Result<Self, anyhow::Error> {
        let mut handle: HANDLE = std::ptr::null_mut();
        let process_handle = unsafe { GetCurrentProcess() };

        if unsafe { OpenProcessToken(process_handle, 0x0008, &mut handle) } == 0 {
            return Err(anyhow::anyhow!("Failed to open process token"));
        }

        Ok(TokenHandle(handle))
    }
}

impl Drop for TokenHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

impl Deref for TokenHandle {
    type Target = HANDLE;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
```

#### Testing Strategy

1. **Unit Tests**
   - Test handle cleanup on all code paths
   - Test error handling scenarios
   - Test resource exhaustion scenarios

2. **Integration Tests**
   - Test repeated ACL operations
   - Test concurrent ACL operations
   - Test with limited handle pools

3. **Resource Monitoring**
   - Monitor handle count during operations
   - Test with handle limits
   - Verify no leaks in production

#### Rollback Plan

1. Maintain old implementation with explicit cleanup
2. Feature flag to enable RAII pattern
3. Monitoring for handle leaks
4. Gradual rollout with validation

#### Success Criteria

- No handle leaks detected in testing
- Handle count returns to baseline after operations
- No resource exhaustion under load
- All error paths properly clean up

---

### Critical Issue #4: Missing SE_FILE_OBJECT Import (ACL-004)

#### Current Vulnerability

```rust
// libs/infra/src/database/mod.rs:21
use windows_sys::Win32::{
    Foundation::{BOOL, CloseHandle, ERROR_SUCCESS, HANDLE, LPCWSTR},
    Security::{
        GetTokenInformation, SE_FILE_OBJECT, SetKernelObjectSecurity, SetSecurityInfo,
        // SE_FILE_OBJECT imported here but...
    },
    // ... later at line 942:
    SE_FILE_OBJECT, // Use of constant that may not be imported correctly
};
```

**Attack Vector**: Code won't compile, blocking Windows deployment entirely.

#### Technical Approach

**Verify Import Structure**

```rust
// Ensure SE_FILE_OBJECT is properly imported
use windows_sys::Win32::Security::SE_FILE_OBJECT;

// Or use fully qualified name
windows_sys::Win32::Security::SE_FILE_OBJECT
```

**Add Compile-Time Validation**

```rust
#[cfg(windows)]
const _: () = assert!(windows_sys::Win32::Security::SE_FILE_OBJECT != 0);
```

#### Testing Strategy

1. **Compilation Tests**
   - Test on Windows with various Rust versions
   - Test with different windows-sys versions
   - Verify no compilation errors

2. **Integration Tests**
   - Test ACL application after fix
   - Verify SE_FILE_OBJECT usage is correct
   - Test with different file types

#### Rollback Plan

1. Use alternative constant if SE_FILE_OBJECT unavailable
2. Fallback to hardcoded value (0x00000001)
3. Feature flag to switch implementations
4. Monitor for runtime issues

#### Success Criteria

- Code compiles successfully on Windows
- ACL operations work correctly
- No warnings about undefined constants
- All tests pass

---

### High Priority Issue #1: Asymmetric Rate Limit Reset (RL-002)

#### Current Vulnerability

```rust
// apps/desktop/src-tauri/src/commands/auth.rs:511-514
{
    let mut attempts = login_attempts.lock().await;
    attempts.remove(email_hash); // Only removes email-specific attempts
}
// Global and device attempts NOT cleared - user remains throttled
```

**Attack Vector**: Legitimate users remain throttled after successful authentication, causing poor UX.

#### Technical Approach

**Clear All Rate Limit Buckets**

```rust
async fn handle_successful_login(
    user_id: Uuid,
    email_hash: &str,
    device_id: &str,
    state: &State<'_, AppState>,
) -> Result<String, String> {
    let token = create_jwt(/* ... */)?;

    // Clear ALL rate limit buckets
    {
        let mut attempts = state.login_attempts.lock().await;
        attempts.remove(email_hash);
    }

    {
        let mut global_attempts = state.global_login_attempts.lock().await;
        global_attempts.clear();
    }

    {
        let mut device_attempts = state.device_login_attempts.lock().await;
        device_attempts.remove(device_id);
    }

    info!(user_id = %user_id, action = "login", outcome = "success");
    Ok(token)
}
```

#### Testing Strategy

1. **Unit Tests**
   - Test clearing all buckets on success
   - Test partial clearing scenarios
   - Test concurrent login attempts

2. **Integration Tests**
   - Test rate limit behavior after successful login
   - Test with multiple devices
   - Test with global limits

3. **UX Testing**
   - Verify users can retry immediately after success
   - Test with throttled then successful login
   - Monitor user complaints

#### Rollback Plan

1. Feature flag to enable symmetric clearing
2. Maintain old clearing logic
3. Monitor for abuse patterns
4. Gradual rollout with A/B testing

#### Success Criteria

- All rate limit buckets cleared on successful auth
- Users can retry immediately after success
- No increase in abuse patterns
- Improved user satisfaction metrics

---

### High Priority Issue #2: Incorrect Rights Mask (ACL-005)

#### Current Vulnerability

```rust
// libs/infra/src/database/mod.rs:918
ea.grfAccessPermissions = 0xF003F; // GENERIC_ALL for files/directories
```

**Attack Vector**: Unclear what permissions are being granted, potential over-privilege.

#### Technical Approach

**Use Specific Rights Instead of GENERIC_ALL**

```rust
// Define specific rights for files and directories
const FILE_ALL_ACCESS: u32 = 0x001F01FF; // Specific file access rights
const DIRECTORY_ALL_ACCESS: u32 = 0x001F000F; // Specific directory access rights

// Determine appropriate rights based on path type
let access_rights = if path.is_dir() {
    DIRECTORY_ALL_ACCESS
} else {
    FILE_ALL_ACCESS
};

ea.grfAccessPermissions = access_rights;
```

**Add Documentation**

```rust
/// Access rights for file objects
///
/// - FILE_ALL_ACCESS: All possible access rights for a file
/// - DELETE: Delete access
/// - READ_CONTROL: Read access to the descriptor
/// - WRITE_DAC: Write access to the DACL
/// - WRITE_OWNER: Change the owner
/// - SYNCHRONIZE: Synchronize access
/// - FILE_GENERIC_READ, FILE_GENERIC_WRITE, etc.
```

#### Testing Strategy

1. **Unit Tests**
   - Test rights applied to files
   - Test rights applied to directories
   - Test with various permission scenarios

2. **Integration Tests**
   - Verify actual permissions with Windows tools
   - Test access control with different users
   - Test permission inheritance

3. **Security Tests**
   - Verify no over-privilege
   - Test with least privilege principle
   - Audit permission sets

#### Rollback Plan

1. Maintain old rights mask as fallback
2. Feature flag to switch implementations
3. Monitor for access issues
4. Gradual rollout with validation

#### Success Criteria

- Clear documentation of rights
- Appropriate permissions per file type
- No over-privilege detected
- All tests pass

---

## 4. Resource Allocation

### Phase 1: Critical Fixes (Week 1-2)

| Task                               | Developer Hours | Required Skills                       | Team Structure      |
| ---------------------------------- | --------------- | ------------------------------------- | ------------------- |
| ACL-004: Fix SE_FILE_OBJECT Import | 2               | Rust, Windows API                     | 1 Senior Dev        |
| RL-001: Fix Device ID Generation   | 16              | Rust, Cryptography, Cross-platform    | 2 Senior Devs       |
| ACL-001: Fix Unsafe SID Casting    | 8               | Rust, Windows Security, Memory Safety | 1 Senior Dev        |
| ACL-002: Fix Token Handle Leak     | 4               | Rust, Windows API, RAII               | 1 Senior Dev        |
| ACL-003: Add ACL Validation        | 12              | Rust, Windows Security, Testing       | 1 Senior Dev + 1 QA |

**Phase 1 Total**: 42 hours
**Team Size**: 2-3 developers
**Duration**: 2 weeks

### Phase 2: High Priority Fixes (Week 3-4)

| Task                                  | Developer Hours | Required Skills                         | Team Structure                     |
| ------------------------------------- | --------------- | --------------------------------------- | ---------------------------------- |
| RL-002: Fix Rate Limit Reset          | 12              | Rust, Concurrency, Testing              | 1 Senior Dev                       |
| RL-003: Add Exponential Backoff       | 8               | Rust, Algorithms, Testing               | 1 Mid-level Dev                    |
| ACL-005: Fix Rights Mask              | 6               | Rust, Windows Security                  | 1 Senior Dev                       |
| ACL-006: Address Privilege Escalation | 16              | Rust, Windows Security, Threat Modeling | 1 Security Engineer + 1 Senior Dev |
| ACL-007: Fix Inheritance Flags        | 8               | Rust, Windows Security                  | 1 Senior Dev                       |

**Phase 2 Total**: 50 hours
**Team Size**: 2-3 developers
**Duration**: 2 weeks

### Phase 3: Medium Priority Fixes (Week 5-6)

| Task                                | Developer Hours | Required Skills                    | Team Structure             |
| ----------------------------------- | --------------- | ---------------------------------- | -------------------------- |
| RL-004: HMAC Key Rotation           | 20              | Rust, Cryptography, Key Management | 1 Security Engineer        |
| RL-006: Add Request IDs             | 8               | Rust, Distributed Tracing          | 1 Mid-level Dev            |
| RL-007: Add Metrics                 | 16              | Rust, Observability, Monitoring    | 1 DevOps Engineer          |
| ACL-008: Improve Error Messages     | 6               | Rust, UX Writing                   | 1 Technical Writer + 1 Dev |
| ACL-009: File/Directory Distinction | 12              | Rust, Windows Security             | 1 Senior Dev               |

**Phase 3 Total**: 62 hours
**Team Size**: 2-3 developers
**Duration**: 2 weeks

### Phase 4: Low Priority Cleanup (Week 7)

| Task                       | Developer Hours | Required Skills            | Team Structure |
| -------------------------- | --------------- | -------------------------- | -------------- |
| RL-005: Remove Test Code   | 4               | Rust, Code Review          | 1 Junior Dev   |
| RL-008: Fix Race Condition | 8               | Rust, Concurrency, Testing | 1 Senior Dev   |

**Phase 4 Total**: 12 hours
**Team Size**: 1-2 developers
**Duration**: 1 week

### Overall Resource Summary

| Phase             | Hours   | Weeks | Team Size | Primary Skills Required                                 |
| ----------------- | ------- | ----- | --------- | ------------------------------------------------------- |
| Phase 1: Critical | 42      | 2     | 2-3       | Rust, Windows Security, Cryptography                    |
| Phase 2: High     | 50      | 2     | 2-3       | Rust, Windows Security, Threat Modeling                 |
| Phase 3: Medium   | 62      | 2     | 2-3       | Rust, Observability, Key Management                     |
| Phase 4: Low      | 12      | 1     | 1-2       | Rust, Code Quality                                      |
| **Total**         | **166** | **7** | **2-3**   | **Rust, Windows Security, Cryptography, Observability** |

### Skill Requirements by Role

**Senior Rust Developer**

- Expert knowledge of Rust memory safety
- Windows API experience
- Security best practices
- Required: 2-3 developers

**Security Engineer**

- Cryptography and key management
- Threat modeling
- Security testing
- Required: 1 engineer

**Mid-level Developer**

- Rust development
- Testing and QA
- Required: 1-2 developers

**DevOps Engineer**

- Observability and monitoring
- Metrics and alerting
- Required: 1 engineer

**Technical Writer**

- Error message UX
- Documentation
- Required: 1 writer

**QA Engineer**

- Security testing
- Integration testing
- Required: 1 engineer

---

## 5. Testing & Validation Plan

### Unit Test Requirements

#### Rate Limiting Tests

```rust
#[cfg(test)]
mod rate_limiting_tests {
    use super::*;

    #[tokio::test]
    async fn test_device_id_cannot_be_spoofed() {
        // Test that environment variables don't affect device ID
        std::env::set_var("HOSTNAME", "attacker_host");
        let device_id = get_device_id();
        assert!(!device_id.contains("attacker_host"));
    }

    #[tokio::test]
    async fn test_all_buckets_cleared_on_success() {
        // Test that email, global, and device limits are cleared
        let state = create_test_state();
        // Add attempts to all buckets
        // Perform successful login
        // Verify all buckets are cleared
    }

    #[tokio::test]
    async fn test_exponential_backoff() {
        // Test that wait time increases with failures
        let state = create_test_state();
        let mut wait_times = Vec::new();
        for i in 0..10 {
            wait_times.push(calculate_backoff(i));
        }
        assert!(wait_times[9] > wait_times[0] * 100);
    }
}
```

#### Windows ACL Tests

```rust
#[cfg(test)]
#[cfg(windows)]
mod acl_tests {
    use super::*;

    #[test]
    fn test_sid_pointer_safety() {
        // Test that SID pointers are handled safely
        let result = set_restrictive_windows_acl(test_path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_cleanup() {
        // Test that handles are properly cleaned up
        let initial_handles = get_handle_count();
        for _ in 0..100 {
            let _ = set_restrictive_windows_acl(test_path());
        }
        let final_handles = get_handle_count();
        assert_eq!(initial_handles, final_handles);
    }

    #[test]
    fn test_acl_validation() {
        // Test that ACLs are validated after creation
        let result = set_restrictive_windows_acl(test_path());
        assert!(result.is_ok());
        let acl = get_acl_for_path(test_path());
        assert!(validate_acl_restrictiveness(&acl));
    }
}
```

### Integration Test Requirements

#### Rate Limiting Integration Tests

1. **End-to-End Authentication Flow**
   - Test complete login flow with rate limiting
   - Test registration flow with rate limiting
   - Test device-based rate limiting

2. **Multi-Device Scenarios**
   - Test rate limiting across multiple devices
   - Test device ID persistence
   - Test device rotation scenarios

3. **Attack Simulation**
   - Simulate brute force attacks
   - Test rate limit bypass attempts
   - Test distributed attack patterns

#### Windows ACL Integration Tests

1. **File and Directory ACLs**
   - Test ACL application on files
   - Test ACL application on directories
   - Test ACL inheritance

2. **Permission Verification**
   - Verify permissions with Windows tools
   - Test access control with different users
   - Test permission inheritance

3. **Error Scenarios**
   - Test with invalid paths
   - Test with permission errors
   - Test with concurrent operations

### Security Testing Approach

#### Penetration Testing

1. **Rate Limiting Penetration Tests**
   - Attempt to bypass rate limiting via environment variables
   - Test for race conditions in rate limit checks
   - Test for timing attacks

2. **Windows ACL Penetration Tests**
   - Attempt to escalate privileges
   - Test for ACL manipulation
   - Test for permission bypass

3. **Fuzz Testing**
   - Fuzz device ID generation
   - Fuzz ACL application
   - Fuzz rate limit inputs

#### Static Analysis

1. **Code Scanning**
   - Run Clippy with all lints
   - Use cargo-audit for dependency vulnerabilities
   - Use cargo-deny for license compliance

2. **Security Scanning**
   - Use cargo-geiger for unsafe code
   - Use cargo-outdated for dependency updates
   - Use cargo-fmt for code formatting

3. **Memory Safety**
   - Run with Miri for undefined behavior
   - Use Valgrind for memory leaks
   - Use AddressSanitizer for memory errors

### Performance Testing Considerations

1. **Rate Limiting Performance**
   - Measure overhead of new device ID generation
   - Test rate limit check performance under load
   - Monitor memory usage

2. **Windows ACL Performance**
   - Measure ACL application time
   - Test with many files/directories
   - Monitor handle usage

3. **Load Testing**
   - Test with concurrent authentications
   - Test with many ACL operations
   - Monitor system resources

---

## 6. Deployment Strategy

### Staging Environment Requirements

#### Infrastructure Setup

1. **Windows Test Environment**
   - Multiple Windows versions (10, 11)
   - Different user privilege levels
   - Various hardware configurations

2. **Rate Limiting Test Environment**
   - Multiple devices for testing
   - Network simulation for latency
   - Load testing infrastructure

3. **Monitoring Setup**
   - Application performance monitoring
   - Security event logging
   - Error tracking and alerting

#### Data Preparation

1. **Test Data**
   - Sample user accounts
   - Test device IDs
   - Test ACL scenarios

2. **Configuration**
   - Rate limit settings
   - Device ID settings
   - ACL settings

3. **Migration Scripts**
   - Database migration for device IDs
   - ACL migration script
   - Configuration migration

### Production Rollout Plan

#### Phase 1: Canary Deployment (Week 1)

1. **Selection Criteria**
   - 5% of user base
   - Geographic distribution
   - Device type diversity

2. **Monitoring**
   - Error rates
   - Performance metrics
   - User feedback

3. **Rollback Criteria**
   - Error rate > 1%
   - Performance degradation > 20%
   - User complaints > threshold

#### Phase 2: Gradual Rollout (Week 2-3)

1. **Expansion Schedule**
   - Week 2: 25% of users
   - Week 3: 50% of users
   - Week 4: 100% of users

2. **Monitoring Intensity**
   - Real-time dashboards
   - Automated alerting
   - Daily health checks

3. **Communication**
   - User notifications
   - Support team training
   - Documentation updates

#### Phase 3: Full Deployment (Week 4)

1. **Final Validation**
   - All metrics within SLA
   - No critical errors
   - User acceptance

2. **Post-Deployment**
   - Extended monitoring (2 weeks)
   - Performance tuning
   - Documentation finalization

### Monitoring and Alerting

#### Metrics to Monitor

1. **Security Metrics**
   - Rate limit bypass attempts
   - Failed authentication attempts
   - ACL application failures

2. **Performance Metrics**
   - Authentication latency
   - ACL application time
   - Memory usage

3. **User Experience Metrics**
   - Login success rate
   - User lockout rate
   - Support ticket volume

#### Alert Thresholds

1. **Critical Alerts**
   - Error rate > 5%
   - Security event > threshold
   - Performance degradation > 50%

2. **Warning Alerts**
   - Error rate > 1%
   - Performance degradation > 20%
   - Unusual patterns detected

3. **Informational Alerts**
   - Configuration changes
   - Deployment events
   - Metric anomalies

### Incident Response Plan

#### Detection

1. **Automated Detection**
   - Real-time monitoring
   - Pattern recognition
   - Anomaly detection

2. **Manual Detection**
   - User reports
   - Security team review
   - Audit logs

#### Response Procedures

1. **Immediate Actions**
   - Rollback deployment
   - Notify stakeholders
   - Document incident

2. **Investigation**
   - Root cause analysis
   - Impact assessment
   - Timeline reconstruction

3. **Remediation**
   - Fix implementation
   - Testing validation
   - Redeployment

4. **Post-Incident**
   - Post-mortem document
   - Process improvement
   - Knowledge sharing

---

## 7. Long-term Improvements

### Architectural Recommendations

#### Rate Limiting Architecture

1. **Distributed Rate Limiting**
   - Move to centralized rate limiting service
   - Use Redis for distributed state
   - Implement hierarchical rate limiting

2. **Advanced Device Fingerprinting**
   - Multi-factor device identification
   - Machine learning for anomaly detection
   - Behavioral analysis

3. **Adaptive Rate Limiting**
   - Dynamic threshold adjustment
   - Risk-based rate limiting
   - Context-aware throttling

#### Windows ACL Architecture

1. **Security Service**
   - Dedicated ACL management service
   - Centralized policy enforcement
   - Audit logging

2. **Policy as Code**
   - Declarative ACL policies
   - Version-controlled policies
   - Automated policy validation

3. **Defense in Depth**
   - Multiple security layers
   - Encryption at rest
   - Secure boot verification

### Process Improvements

#### Security Development Lifecycle

1. **Threat Modeling**
   - Regular threat modeling sessions
   - Architecture review board
   - Security requirements documentation

2. **Code Review Process**
   - Mandatory security review
   - Automated security scanning
   - Peer review checklist

3. **Testing Requirements**
   - Security test coverage
   - Penetration testing
   - Fuzz testing

#### Incident Management

1. **Security Incident Response**
   - Dedicated response team
   - Playbook development
   - Regular drills

2. **Vulnerability Management**
   - Dependency scanning
   - Patch management
   - CVE monitoring

3. **Compliance Monitoring**
   - Regular audits
   - Compliance reporting
   - Risk assessment

### Tooling Suggestions

#### Development Tools

1. **Security Tools**
   - cargo-audit: Dependency vulnerability scanning
   - cargo-deny: License compliance
   - cargo-geiger: Unsafe code detection

2. **Testing Tools**
   - cargo-nextest: Faster test execution
   - cargo-tarpaulin: Code coverage
   - proptest: Property-based testing

3. **Code Quality Tools**
   - cargo-clippy: Linting
   - cargo-fmt: Formatting
   - cargo-doc: Documentation

#### Monitoring Tools

1. **Application Monitoring**
   - Sentry: Error tracking
   - Prometheus: Metrics collection
   - Grafana: Visualization

2. **Security Monitoring**
   - Wazuh: Security monitoring
   - OSQuery: System monitoring
   - ELK Stack: Log analysis

3. **Performance Monitoring**
   - Datadog: APM
   - New Relic: Performance
   - AppDynamics: Monitoring

#### Documentation Tools

1. **Documentation**
   - MkDocs: Documentation site
   - Mermaid: Diagrams
   - Swagger: API documentation

2. **Knowledge Management**
   - Confluence: Wiki
   - Notion: Knowledge base
   - GitHub: Code documentation

### Documentation Needs

#### Security Documentation

1. **Architecture Documentation**
   - Security architecture overview
   - Threat model documentation
   - Security design patterns

2. **Operational Documentation**
   - Security procedures
   - Incident response playbooks
   - Configuration guides

3. **Developer Documentation**
   - Security coding guidelines
   - Testing requirements
   - Code review checklist

#### User Documentation

1. **Security Guides**
   - Best practices
   - Security features
   - Privacy information

2. **Troubleshooting**
   - Common issues
   - Error explanations
   - Support procedures

3. **Release Notes**
   - Security updates
   - Feature changes
   - Migration guides

---

## 8. Implementation Checklist

### Phase 1: Critical Fixes (Week 1-2)

- [ ] ACL-004: Fix SE_FILE_OBJECT import
  - [ ] Verify import structure
  - [ ] Add compile-time validation
  - [ ] Test compilation on Windows
  - [ ] Update documentation

- [ ] RL-001: Fix Device ID generation
  - [ ] Design device ID architecture
  - [ ] Implement persistent storage
  - [ ] Add hardware entropy collection
  - [ ] Add cryptographic signing
  - [ ] Implement tampering detection
  - [ ] Write unit tests
  - [ ] Write integration tests
  - [ ] Write security tests
  - [ ] Update documentation

- [ ] ACL-001: Fix unsafe SID casting
  - [ ] Use proper type conversion
  - [ ] Add bounds checking
  - [ ] Add SID validation
  - [ ] Write unit tests
  - [ ] Write integration tests
  - [ ] Run fuzz testing
  - [ ] Update documentation

- [ ] ACL-002: Fix token handle leak
  - [ ] Implement RAII pattern
  - [ ] Add handle wrapper
  - [ ] Test all code paths
  - [ ] Test error handling
  - [ ] Monitor handle usage
  - [ ] Update documentation

- [ ] ACL-003: Add ACL validation
  - [ ] Design validation logic
  - [ ] Implement ACL verification
  - [ ] Add validation tests
  - [ ] Add integration tests
  - [ ] Update documentation

### Phase 2: High Priority Fixes (Week 3-4)

- [ ] RL-002: Fix asymmetric rate limit reset
  - [ ] Clear all rate limit buckets
  - [ ] Update handle_successful_login signature
  - [ ] Write unit tests
  - [ ] Write integration tests
  - [ ] Test UX improvements
  - [ ] Update documentation

- [ ] RL-003: Add exponential backoff
  - [ ] Design backoff algorithm
  - [ ] Implement backoff logic
  - [ ] Add backoff tests
  - [ ] Test attack scenarios
  - [ ] Update documentation

- [ ] ACL-005: Fix incorrect rights mask
  - [ ] Define specific rights
  - [ ] Add file/directory distinction
  - [ ] Add documentation
  - [ ] Write unit tests
  - [ ] Verify permissions
  - [ ] Update documentation

- [ ] ACL-006: Address privilege escalation
  - [ ] Threat modeling
  - [ ] Design security controls
  - [ ] Implement controls
  - [ ] Write security tests
  - [ ] Penetration testing
  - [ ] Update documentation

- [ ] ACL-007: Fix inheritance flags
  - [ ] Design inheritance logic
  - [ ] Implement file/directory distinction
  - [ ] Add inheritance tests
  - [ ] Verify ACL inheritance
  - [ ] Update documentation

### Phase 3: Medium Priority Fixes (Week 5-6)

- [ ] RL-004: Implement HMAC key rotation
  - [ ] Design key rotation strategy
  - [ ] Implement key generation
  - [ ] Implement key storage
  - [ ] Implement key rotation
  - [ ] Add migration logic
  - [ ] Write tests
  - [ ] Update documentation

- [ ] RL-006: Add request IDs
  - [ ] Design request ID format
  - [ ] Implement ID generation
  - [ ] Add to logging
  - [ ] Add to tracing
  - [ ] Update documentation

- [ ] RL-007: Add metrics
  - [ ] Design metrics schema
  - [ ] Implement metrics collection
  - [ ] Add to monitoring
  - [ ] Create dashboards
  - [ ] Set up alerting
  - [ ] Update documentation

- [ ] ACL-008: Improve error messages
  - [ ] Review all error messages
  - [ ] Write helpful messages
  - [ ] Add context to errors
  - [ ] Test error scenarios
  - [ ] Update documentation

- [ ] ACL-009: Add file/directory distinction
  - [ ] Implement type detection
  - [ ] Add conditional logic
  - [ ] Write tests
  - [ ] Update documentation

### Phase 4: Low Priority Cleanup (Week 7)

- [ ] RL-005: Remove test code
  - [ ] Identify test code
  - [ ] Move to test files
  - [ ] Update imports
  - [ ] Run tests

- [ ] RL-008: Fix race condition
  - [ ] Analyze race condition
  - [ ] Design fix
  - [ ] Implement fix
  - [ ] Write tests
  - [ ] Update documentation

---

## 9. Success Metrics

### Security Metrics

- [ ] Zero critical vulnerabilities remaining
- [ ] Zero high vulnerabilities remaining
- [ ] Rate limit bypass attempts reduced by 95%
- [ ] ACL application success rate > 99.9%
- [ ] No privilege escalation incidents

### Performance Metrics

- [ ] Authentication latency < 500ms (p95)
- [ ] ACL application time < 100ms (p95)
- [ ] Memory usage increase < 10%
- [ ] CPU usage increase < 5%

### User Experience Metrics

- [ ] Login success rate > 99%
- [ ] User lockout rate < 0.1%
- [ ] Support ticket volume for auth issues < 5/week
- [ ] User satisfaction score > 4.5/5

### Code Quality Metrics

- [ ] Test coverage > 80%
- [ ] Zero unsafe code warnings
- [ ] Zero clippy warnings
- [ ] Zero memory leaks detected

---

## 10. Conclusion

This comprehensive action plan addresses all 17 security vulnerabilities identified in the Aroeira PR reviews. The plan prioritizes critical issues that enable complete security bypasses or prevent compilation, followed by high-priority issues that could lead to privilege escalation or degraded user experience.

### Key Recommendations

1. **Immediate Action**: Begin Phase 1 critical fixes immediately, as these vulnerabilities are actively exploitable
2. **Resource Allocation**: Assign 2-3 senior developers with Rust and Windows security expertise
3. **Testing Focus**: Invest heavily in security testing, including fuzz testing and penetration testing
4. **Monitoring**: Implement comprehensive monitoring before deployment to detect issues early
5. **Documentation**: Maintain detailed documentation throughout the process for knowledge transfer

### Expected Outcomes

- All critical and high vulnerabilities resolved within 4 weeks
- Medium vulnerabilities resolved within 6 weeks
- Low vulnerabilities resolved within 7 weeks
- Improved security posture with defense in depth
- Enhanced user experience with better rate limiting
- Maintainable codebase with clear documentation

### Next Steps

1. Review and approve this action plan
2. Assign team members to each phase
3. Set up staging environment
4. Begin Phase 1 implementation
5. Establish monitoring and alerting
6. Execute deployment strategy
7. Monitor and iterate based on feedback

---

**Document Version**: 1.0  
**Last Updated**: 2026-01-18  
**Author**: Security Review Team  
**Status**: Draft for Review
