# Module 3: Authentication & Authorization - Phase 2 Enhancements

## Current Status
- ✅ 2,199 lines of code
- ✅ Compiles successfully
- ✅ Basic mTLS authentication
- ✅ RBAC authorization framework

## Performance Enhancements

### 1. Certificate Validation Caching (Priority: CRITICAL)
**Goal**: < 1ms for cached certificate validation

**Tasks**:
- [ ] Implement LRU cache for validated certificates
- [ ] Cache certificate chains and validation results
- [ ] Add cache invalidation on revocation
- [ ] Profile validation performance
- [ ] Benchmark with/without caching

**Optimization**:
```rust
use lru::LruCache;

pub struct CertValidator {
    // Cache validated certificates (cert fingerprint -> validation result)
    validation_cache: Arc<Mutex<LruCache<CertFingerprint, ValidationResult>>>,
    // Cache cert chains
    chain_cache: Arc<Mutex<LruCache<CertFingerprint, Vec<Certificate>>>>,
}

impl CertValidator {
    pub fn validate(&self, cert: &Certificate) -> Result<ValidationResult> {
        let fingerprint = cert.fingerprint();

        // Check cache first
        if let Some(cached) = self.validation_cache.lock().get(&fingerprint) {
            return Ok(cached.clone());
        }

        // Validate and cache
        let result = self.validate_full(cert)?;
        self.validation_cache.lock().put(fingerprint, result.clone());
        Ok(result)
    }
}
```

**Target**: < 100μs for cached validations, < 5ms for full validation

### 2. Permission Check Optimization (Priority: HIGH)
**Goal**: < 100μs for permission checks

**Tasks**:
- [ ] Pre-compute permission sets per role
- [ ] Use bitflags for fast permission checks
- [ ] Cache role → permissions mapping
- [ ] Optimize permission tree traversal
- [ ] Benchmark permission checks under load

**Pattern**:
```rust
use bitflags::bitflags;

bitflags! {
    pub struct Permissions: u64 {
        const KEY_GENERATE = 1 << 0;
        const KEY_READ     = 1 << 1;
        const KEY_DELETE   = 1 << 2;
        const KEY_ROTATE   = 1 << 3;
        const SIGN         = 1 << 4;
        const VERIFY       = 1 << 5;
        const ENCRYPT      = 1 << 6;
        const DECRYPT      = 1 << 7;
        // ... up to 64 permissions
    }
}

pub struct RoleCache {
    // Role name -> pre-computed permission bitflags
    permissions: Arc<DashMap<String, Permissions>>,
}

impl AuthZEngine {
    pub fn check_permission(&self, identity: &Identity, perm: Permissions) -> bool {
        let role_perms = self.role_cache.permissions.get(&identity.role)?;
        role_perms.contains(perm)  // O(1) bitwise check
    }
}
```

### 3. Session Management (Priority: HIGH)
**Goal**: Support 10,000+ concurrent sessions

**Tasks**:
- [ ] Implement session pooling
- [ ] Use DashMap for concurrent session access
- [ ] Add session expiration background task
- [ ] Profile session creation/lookup
- [ ] Add session metrics

**Expected gain**: 5-10x improvement in session throughput

### 4. Namespace Lookup Optimization (Priority: MEDIUM)
**Goal**: < 50μs for namespace resolution

**Tasks**:
- [ ] Cache namespace metadata
- [ ] Use radix tree for namespace hierarchy
- [ ] Pre-load namespace permissions
- [ ] Optimize namespace isolation checks
- [ ] Benchmark namespace operations

## Security Enhancements

### 1. mTLS Hardening (Priority: CRITICAL)
**Goal**: Zero certificate validation bypasses

**Tasks**:
- [ ] Enforce certificate revocation checking (OCSP/CRL)
- [ ] Add certificate pinning for known clients
- [ ] Verify certificate key usage extensions
- [ ] Add certificate transparency verification
- [ ] Fuzz test certificate validation

**Critical checks**:
```rust
pub fn validate_client_cert(&self, cert: &Certificate) -> Result<()> {
    // 1. Check certificate is not expired
    if cert.not_after() < SystemTime::now() {
        return Err(AuthError::CertificateExpired);
    }

    // 2. Verify certificate chain
    self.verify_chain(cert)?;

    // 3. Check revocation status (CRITICAL)
    if self.is_revoked(cert)? {
        return Err(AuthError::CertificateRevoked);
    }

    // 4. Verify key usage allows client authentication
    if !cert.key_usage().contains(KeyUsage::CLIENT_AUTH) {
        return Err(AuthError::InvalidKeyUsage);
    }

    // 5. Check certificate pinning (if configured)
    if let Some(expected_pin) = self.pinned_certs.get(&cert.subject()) {
        if cert.fingerprint() != *expected_pin {
            return Err(AuthError::CertificatePinningFailed);
        }
    }

    Ok(())
}
```

### 2. RBAC Policy Enforcement (Priority: CRITICAL)
**Goal**: 100% policy enforcement, zero bypasses

**Tasks**:
- [ ] Audit all API endpoints for authorization checks
- [ ] Verify namespace isolation in all operations
- [ ] Add policy evaluation tests
- [ ] Implement policy versioning
- [ ] Add policy audit trail

**Enforcement pattern**:
```rust
pub async fn handle_request(&self, req: Request) -> Result<Response> {
    // 1. Authenticate (mTLS)
    let identity = self.authenticate(req.peer_cert())?;

    // 2. Authorize (RBAC)
    let required_perm = self.get_required_permission(&req.operation);
    if !self.authz.check_permission(&identity, required_perm) {
        audit::log(AuditEvent::AuthorizationDenied {
            identity: identity.clone(),
            operation: req.operation.clone(),
            reason: "insufficient permissions",
        });
        return Err(Error::PermissionDenied);
    }

    // 3. Verify namespace isolation
    if let Some(namespace) = req.namespace() {
        if !identity.can_access_namespace(namespace) {
            audit::log(AuditEvent::NamespaceViolation {
                identity: identity.clone(),
                requested_namespace: namespace.clone(),
            });
            return Err(Error::NamespaceAccessDenied);
        }
    }

    // 4. Execute request
    self.execute(req, &identity).await
}
```

### 3. Rate Limiting (Priority: HIGH)
**Goal**: Prevent DoS attacks

**Tasks**:
- [ ] Implement per-identity rate limiting
- [ ] Add per-namespace rate limiting
- [ ] Use token bucket algorithm
- [ ] Add adaptive rate limiting
- [ ] Test under attack scenarios

**Implementation**:
```rust
use governor::{Quota, RateLimiter};

pub struct RateLimitConfig {
    // Per identity limits
    per_identity: RateLimiter<IdentityKey>,
    // Per namespace limits
    per_namespace: RateLimiter<Namespace>,
    // Global limits
    global: RateLimiter<()>,
}

impl AuthMiddleware {
    pub fn check_rate_limit(&self, identity: &Identity, namespace: &str) -> Result<()> {
        // Check global limit
        if self.rate_limits.global.check().is_err() {
            return Err(AuthError::RateLimitExceeded("global"));
        }

        // Check per-identity limit
        if self.rate_limits.per_identity.check_key(&identity.id).is_err() {
            audit::log(AuditEvent::RateLimitExceeded {
                identity: identity.clone(),
                limit_type: "per_identity",
            });
            return Err(AuthError::RateLimitExceeded("identity"));
        }

        // Check per-namespace limit
        if self.rate_limits.per_namespace.check_key(&namespace).is_err() {
            return Err(AuthError::RateLimitExceeded("namespace"));
        }

        Ok(())
    }
}
```

### 4. Session Security (Priority: HIGH)
**Goal**: Secure session management

**Tasks**:
- [ ] Implement secure session token generation
- [ ] Add session token rotation
- [ ] Enforce session timeouts
- [ ] Add session hijacking detection
- [ ] Test session security

**Secure sessions**:
```rust
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

pub struct SessionManager {
    sessions: Arc<DashMap<SessionId, Session>>,
}

impl SessionManager {
    pub fn create_session(&self, identity: Identity) -> Result<SessionToken> {
        // Generate cryptographically secure session ID
        let mut session_id_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut session_id_bytes);
        let session_id = SessionId(session_id_bytes);

        // Create session with metadata for hijacking detection
        let session = Session {
            id: session_id,
            identity,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            client_ip: peer_addr,
            user_agent: user_agent.clone(),
        };

        self.sessions.insert(session_id, session);

        // Return opaque session token (hashed)
        let token = self.generate_token(&session_id)?;
        Ok(token)
    }

    pub fn validate_session(&self, token: &SessionToken) -> Result<&Session> {
        let session_id = self.verify_token(token)?;

        let session = self.sessions.get(&session_id)
            .ok_or(AuthError::InvalidSession)?;

        // Check expiration
        if session.last_activity.elapsed() > SESSION_TIMEOUT {
            self.sessions.remove(&session_id);
            return Err(AuthError::SessionExpired);
        }

        // Update last activity (touch session)
        session.last_activity = Instant::now();

        Ok(session)
    }
}
```

### 5. Audit All Auth Events (Priority: HIGH)
**Goal**: Complete auth audit trail

**Tasks**:
- [ ] Log all authentication attempts
- [ ] Log all authorization decisions
- [ ] Log rate limit violations
- [ ] Log session lifecycle events
- [ ] Integrate with audit module

## Reliability Enhancements

### 1. Certificate Renewal (Priority: HIGH)
**Goal**: Automatic certificate renewal

**Tasks**:
- [ ] Implement certificate expiration monitoring
- [ ] Add automatic renewal workflow
- [ ] Add certificate rotation support
- [ ] Test renewal under load
- [ ] Document renewal procedures

### 2. Policy Hot Reload (Priority: MEDIUM)
**Goal**: Update policies without restart

**Tasks**:
- [ ] Implement policy file watching
- [ ] Add policy validation before reload
- [ ] Test hot reload functionality
- [ ] Add rollback on invalid policy
- [ ] Log policy changes

### 3. Error Recovery (Priority: HIGH)
**Goal**: Graceful degradation

**Tasks**:
- [ ] Add fallback authentication methods
- [ ] Implement circuit breakers
- [ ] Add health checks
- [ ] Test failure scenarios
- [ ] Document recovery procedures

## Testing Enhancements

### 1. Security Tests (Priority: CRITICAL)
**Goal**: Prove security properties

**Tasks**:
- [ ] Add bypass attempt tests
- [ ] Test namespace isolation
- [ ] Test rate limiting effectiveness
- [ ] Add session security tests
- [ ] Fuzz test certificate validation

### 2. Load Tests (Priority: HIGH)
**Goal**: Verify performance under load

**Tasks**:
- [ ] Test 10,000+ concurrent sessions
- [ ] Benchmark authentication throughput
- [ ] Test authorization performance
- [ ] Verify rate limiting accuracy
- [ ] Test under attack scenarios

### 3. Integration Tests (Priority: HIGH)
**Goal**: End-to-end auth flows

**Tasks**:
- [ ] Test full mTLS flow
- [ ] Test RBAC policy enforcement
- [ ] Test multi-namespace scenarios
- [ ] Test session lifecycle
- [ ] Test certificate renewal

## Success Metrics

**Performance**:
- ✅ Certificate validation: < 5ms p99 (< 100μs cached)
- ✅ Permission checks: < 100μs p99
- ✅ Session lookup: < 50μs p99
- ✅ Concurrent sessions: > 10,000

**Security**:
- ✅ Zero auth bypasses in tests
- ✅ 100% RBAC policy enforcement
- ✅ All certificates validated with revocation check
- ✅ Rate limiting prevents DoS
- ✅ Complete audit trail

**Reliability**:
- ✅ Automatic certificate renewal
- ✅ Hot reload of policies
- ✅ Graceful degradation on failures
- ✅ > 95% test coverage

## Claude Agent Instructions

1. Read this enhancement plan
2. Run existing tests to verify baseline
3. Implement certificate validation caching
4. Add comprehensive security tests
5. Implement rate limiting
6. Add permission check optimization
7. Verify all security properties
8. Achieve performance targets
9. Run security audit and verify no bypasses
