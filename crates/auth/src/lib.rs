//! Authentication and Authorization Module for HSM.
//!
//! This module provides comprehensive security through mutual TLS (mTLS) authentication
//! and Role-Based Access Control (RBAC) with multi-layered authorization.
//!
//! # Architecture Overview
//!
//! The authentication system uses a defense-in-depth approach with three security layers:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Authentication Flow                           │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                   │
//! │  1. mTLS Authentication                                           │
//! │     ┌──────────┐                         ┌──────────┐            │
//! │     │  Client  │──── TLS Handshake ─────▶│   HSM    │            │
//! │     │   Cert   │                         │  Server  │            │
//! │     └──────────┘                         └──────────┘            │
//! │          │                                      │                │
//! │          ├── Present certificate                │                │
//! │          │                                      ▼                │
//! │          │                          Validate against CA cert     │
//! │          │                          Extract identity fields      │
//! │          │                          - Common Name (CN)           │
//! │          │                          - Organization              │
//! │          │                          - Organizational Unit (OU)  │
//! │          │                          - Serial Number             │
//! │          │                                      │                │
//! │          ▼                                      ▼                │
//! │    ┌──────────────────────────────────────────────┐             │
//! │    │         ClientIdentity Created               │             │
//! │    │  - CN, Organization, Namespace, Roles        │             │
//! │    └──────────────────────────────────────────────┘             │
//! │                         │                                        │
//! │                         ▼                                        │
//! │  2. Session Creation                                             │
//! │     ┌────────────────────────────────────────┐                  │
//! │     │   SessionManager (DashMap-backed)      │                  │
//! │     │   - Generate secure session ID         │                  │
//! │     │   - Store identity + metadata          │                  │
//! │     │   - Set expiration (TTL)               │                  │
//! │     │   - Track client IP for hijack detect  │                  │
//! │     └────────────────────────────────────────┘                  │
//! │                         │                                        │
//! │                         ▼                                        │
//! │  3. Multi-Layer Authorization                                    │
//! │     ┌────────────────────────────────────────┐                  │
//! │     │  Layer 1: Namespace Isolation          │                  │
//! │     │  └─▶ Check namespace membership        │                  │
//! │     ├────────────────────────────────────────┤                  │
//! │     │  Layer 2: RBAC Policy                  │                  │
//! │     │  └─▶ Check role permissions            │                  │
//! │     ├────────────────────────────────────────┤                  │
//! │     │  Layer 3: Key-Level ACL                │                  │
//! │     │  └─▶ Check key access list             │                  │
//! │     └────────────────────────────────────────┘                  │
//! │                         │                                        │
//! │                         ▼                                        │
//! │              ✓ Authorization Success                             │
//! │              or                                                  │
//! │              ✗ PermissionDenied Error                            │
//! │                                                                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # mTLS Certificate Validation
//!
//! The mTLS authentication process validates client certificates against a trusted CA:
//!
//! 1. **Certificate Chain Verification**: Client cert must be signed by trusted CA
//! 2. **Validity Period Check**: Current time must be within cert's valid period
//! 3. **Identity Extraction**: Parse X.509 fields to extract client identity:
//!    - **CN (Common Name)**: Primary client identifier
//!    - **Organization**: Client's organizational affiliation
//!    - **Organizational Unit (OU)**: Maps to namespace (default: "default")
//!    - **Serial Number**: Unique certificate identifier for revocation
//! 4. **Role Assignment**: Roles derived from CN pattern or cert extensions
//!    - `admin` in CN → Admin role
//!    - `operator` in CN → Operator role
//!    - `auditor` in CN → Auditor role
//!    - Default → User role
//!
//! # RBAC Model
//!
//! The system implements a hierarchical role-based access control model with four predefined roles:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         RBAC Permission Matrix                           │
//! ├────────────┬──────────┬───────────┬──────────┬──────────────────────────┤
//! │ Permission │  Admin   │ Operator  │   User   │  Auditor                 │
//! ├────────────┼──────────┼───────────┼──────────┼──────────────────────────┤
//! │ GenerateKey│    ✓     │     ✓     │    ✗     │    ✗                     │
//! │ ImportKey  │    ✓     │     ✓     │    ✗     │    ✗                     │
//! │ DeleteKey  │    ✓     │     ✗     │    ✗     │    ✗    (privileged)     │
//! │ Sign       │    ✓     │     ✓     │    ✓     │    ✗                     │
//! │ Encrypt    │    ✓     │     ✓     │    ✓     │    ✗                     │
//! │ Decrypt    │    ✓     │     ✓     │    ✓     │    ✗                     │
//! │ RotateKey  │    ✓     │     ✓     │    ✗     │    ✗                     │
//! │ ViewMetadata│   ✓     │     ✓     │    ✓     │    ✓                     │
//! │ ViewAuditLog│   ✓     │     ✗     │    ✗     │    ✓                     │
//! │ ExportKey  │    ✓     │     ✗     │    ✗     │    ✗    (privileged)     │
//! │ ManageNS   │    ✓     │     ✗     │    ✗     │    ✗    (privileged)     │
//! │ ManageACLs │    ✓     │     ✓     │    ✗     │    ✗                     │
//! │ ManageRoles│    ✓     │     ✗     │    ✗     │    ✗    (privileged)     │
//! │ BackupKeys │    ✓     │     ✓     │    ✗     │    ✗                     │
//! │ RestoreKeys│    ✓     │     ✗     │    ✗     │    ✗    (privileged)     │
//! └────────────┴──────────┴───────────┴──────────┴──────────────────────────┘
//!
//! Role Descriptions:
//!   • Admin:    Full system control, all permissions
//!   • Operator: Day-to-day operations (generate, rotate, backup, crypto ops)
//!   • User:     Basic cryptographic operations only (sign, encrypt, decrypt)
//!   • Auditor:  Read-only access (view metadata and audit logs)
//! ```
//!
//! # Session Lifecycle
//!
//! Sessions provide secure, stateful authentication with automatic expiration:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Session Lifecycle                             │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                   │
//! │  [mTLS Auth] ──▶ [Create Session]                                │
//! │                        │                                         │
//! │                        ├─ Generate secure session ID (SHA256)    │
//! │                        ├─ Generate session token (32 bytes)      │
//! │                        ├─ Store ClientIdentity                   │
//! │                        ├─ Set expiration (created_at + TTL)      │
//! │                        └─ Optional: Store client IP, User-Agent  │
//! │                        │                                         │
//! │                        ▼                                         │
//! │                  [Active Session]                                │
//! │                        │                                         │
//! │                        ├─ On each request: validate_session()    │
//! │                        ├─ Check expiration                       │
//! │                        ├─ Detect hijacking (IP mismatch)         │
//! │                        ├─ Update last_accessed timestamp         │
//! │                        │                                         │
//! │                        ├─ Optional: extend() for longer TTL      │
//! │                        ├─ Optional: rotate_token() for security  │
//! │                        │                                         │
//! │                        ▼                                         │
//! │                  [Expiration]                                    │
//! │                        │                                         │
//! │                        ├─ Automatic: cleanup_expired()           │
//! │                        │  (runs periodically)                    │
//! │                        └─ Manual: delete_session()               │
//! │                        │                                         │
//! │                        ▼                                         │
//! │                  [Session Removed]                               │
//! │                                                                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Namespace Isolation
//!
//! Namespaces provide logical separation of keys and resources:
//!
//! - Extracted from certificate's Organizational Unit (OU) field
//! - Default namespace: `"default"`
//! - Clients can only access keys in authorized namespaces
//! - Namespace access is explicitly granted via `NamespaceManager`
//! - Prevents cross-tenant data access in multi-tenant deployments
//!
//! # Key-Level ACLs
//!
//! Fine-grained access control at the individual key level:
//!
//! - **Unrestricted ACLs**: Key accessible by any authenticated client in namespace
//! - **Restricted ACLs**: Key accessible only by explicitly allowed clients (allowlist)
//! - ACL checks run after RBAC checks for defense-in-depth
//! - Useful for sensitive keys requiring additional access controls
//!
//! # Security Features
//!
//! ## Session Hijacking Detection
//! - Stores client IP address and User-Agent at session creation
//! - Validates IP consistency on each request (optional)
//! - Increments `auth.session.hijacking_attempt` metric on mismatch
//!
//! ## Concurrent Session Management
//! - Uses `DashMap` for lock-free concurrent access
//! - Target: >10,000 concurrent sessions
//! - Target: <50μs session lookup latency
//!
//! ## Token Rotation
//! - Session tokens can be rotated without invalidating session
//! - Mitigates token theft and replay attacks
//!
//! ## Automatic Cleanup
//! - Expired sessions automatically removed via `cleanup_expired()`
//! - Prevents memory leaks from abandoned sessions
//!
//! # Examples
//!
//! ## Basic authentication and authorization
//!
//! ```rust,no_run
//! use hsm_auth::{AuthService, Permission};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize auth service with certificates
//! let ca_cert = std::fs::read("ca.pem")?;
//! let server_cert = std::fs::read("server.pem")?;
//! let server_key = std::fs::read("server.key")?;
//!
//! let auth_service = AuthService::new(&ca_cert, &server_cert, &server_key, 3600)?; // 1 hour session TTL
//!
//! // Authenticate client and create session
//! let client_cert_der = std::fs::read("client.der")?;
//! let result = auth_service.authenticate_and_create_session(&client_cert_der)?;
//! // result.token should be sent to client once (never stored server-side)
//!
//! println!("Session created: {}", result.session.id);
//! println!("Client: {}", result.session.identity.common_name);
//! println!("Roles: {:?}", result.session.identity.roles);
//!
//! // Later: authorize key access
//! auth_service.authorize_session(
//!     &result.session.id,
//!     "key-123",
//!     "default",
//!     &Permission::Sign,
//! )?;
//!
//! println!("Authorization successful!");
//! # Ok(())
//! # }
//! ```
//!
//! ## Multi-layer authorization
//!
//! ```rust,no_run
//! use hsm_auth::{AuthService, Permission};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let ca_cert = std::fs::read("ca.pem")?;
//! # let server_cert = std::fs::read("server.pem")?;
//! # let server_key = std::fs::read("server.key")?;
//! # let auth_service = AuthService::new(&ca_cert, &server_cert, &server_key, 3600)?;
//! # let client_cert_der = std::fs::read("client.der")?;
//! # let result = auth_service.authenticate_and_create_session(&client_cert_der)?;
//! # let identity = &result.session.identity;
//! # let key_id = "key-123";
//! # let namespace = "production";
//!
//! // Layer 1: Namespace check
//! auth_service.namespaces().require_access(identity, namespace)?;
//!
//! // Layer 2: RBAC check
//! auth_service.rbac().require_any(&identity.roles, &Permission::Sign)?;
//!
//! // Layer 3: Key ACL check
//! auth_service.acls().require_access(key_id, identity)?;
//!
//! // All layers passed - operation authorized
//! # Ok(())
//! # }
//! ```
//!
//! ## Session management
//!
//! ```rust
//! use hsm_auth::{SessionManager, ClientIdentity, Role};
//!
//! let session_manager = SessionManager::new(3600); // 1 hour TTL
//!
//! let identity = ClientIdentity::new(
//!     "client-1".to_string(),
//!     Some("Acme Corp".to_string()),
//!     "default".to_string(),
//!     vec![Role::User],
//!     "serial-123".to_string(),
//! );
//!
//! // Create session - returns session + token
//! let result = session_manager.create_session(identity);
//! // result.token should be sent to client once
//!
//! // Validate session by ID (updates last_accessed timestamp)
//! let validated = session_manager.validate_session(&result.session.id).unwrap();
//! assert_eq!(validated.id, result.session.id);
//!
//! // Or validate with token (more secure)
//! let validated = session_manager.validate_session_with_token(&result.session.id, &result.token).unwrap();
//!
//! // Extend session
//! session_manager.extend_session(&result.session.id, 1800).unwrap(); // +30 minutes
//!
//! // Cleanup expired sessions
//! let removed_count = session_manager.cleanup_expired();
//! ```
//!
//! # Performance Characteristics
//!
//! - **Session Lookup**: <50μs (DashMap-backed)
//! - **Permission Check**: <100μs (bitflags-based)
//! - **Concurrent Sessions**: >10,000 simultaneous sessions
//! - **Certificate Validation**: <5ms (P99 latency)
//!
//! # Security Considerations
//!
//! ## Certificate Management
//! - Rotate CA and server certificates regularly
//! - Use strong key sizes (RSA ≥2048 bits, ECDSA ≥256 bits)
//! - Implement certificate revocation checking (CRL/OCSP) in production
//!
//! ## Session Security
//! - Use appropriate TTLs (shorter for sensitive operations)
//! - Enable IP-based hijacking detection for critical environments
//! - Rotate session tokens periodically
//! - Clear sessions on logout or explicit revocation
//!
//! ## RBAC Best Practices
//! - Follow principle of least privilege
//! - Assign roles based on job function
//! - Use ACLs for sensitive keys requiring additional restrictions
//! - Audit role assignments and permission grants regularly
//!
//! ## Namespace Isolation
//! - Use namespaces to separate environments (dev, staging, production)
//! - Use namespaces for multi-tenant isolation
//! - Validate namespace access before key operations

pub mod acl;
pub mod audit;
pub mod error;
pub mod mtls;
pub mod namespace;
pub mod rate_limit;
pub mod rbac;
pub mod session;

// Re-export main types
pub use acl::{AclManager, KeyAcl, KeyId};
pub use audit::{AuditEvent, AuditEventType, AuditLogger, AuditSeverity};
pub use error::{AuthError, Result};
pub use mtls::{CertificateValidator, ClientIdentity, MtlsAuthenticator};
pub use namespace::NamespaceManager;
pub use rate_limit::{RateLimitConfig, RateLimiter};
pub use rbac::{Permission, PermissionFlags, RbacPolicy, Role};
pub use session::{HashedToken, Session, SessionCreationResult, SessionId, SessionManager, SessionToken};

use std::sync::Arc;

/// Main authentication and authorization service
/// Combines mTLS, RBAC, namespaces, sessions, and ACLs
pub struct AuthService {
    /// mTLS authenticator
    authenticator: Arc<MtlsAuthenticator>,

    /// RBAC policy engine
    rbac: Arc<RbacPolicy>,

    /// Namespace manager
    namespaces: Arc<NamespaceManager>,

    /// Session manager
    sessions: Arc<SessionManager>,

    /// ACL manager
    acls: Arc<AclManager>,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(
        ca_cert: &[u8],
        server_cert: &[u8],
        server_key: &[u8],
        session_ttl_seconds: i64,
    ) -> Result<Self> {
        let authenticator = Arc::new(MtlsAuthenticator::new(ca_cert, server_cert, server_key)?);
        let rbac = Arc::new(RbacPolicy::new());
        let namespaces = Arc::new(NamespaceManager::new());
        let sessions = Arc::new(SessionManager::new(session_ttl_seconds));
        let acls = Arc::new(AclManager::new());

        Ok(Self {
            authenticator,
            rbac,
            namespaces,
            sessions,
            acls,
        })
    }

    /// Get the mTLS authenticator
    pub fn authenticator(&self) -> Arc<MtlsAuthenticator> {
        self.authenticator.clone()
    }

    /// Get the RBAC policy
    pub fn rbac(&self) -> Arc<RbacPolicy> {
        self.rbac.clone()
    }

    /// Get the namespace manager
    pub fn namespaces(&self) -> Arc<NamespaceManager> {
        self.namespaces.clone()
    }

    /// Get the session manager
    pub fn sessions(&self) -> Arc<SessionManager> {
        self.sessions.clone()
    }

    /// Get the ACL manager
    pub fn acls(&self) -> Arc<AclManager> {
        self.acls.clone()
    }

    /// Authenticate a client and create a session
    ///
    /// Returns a SessionCreationResult containing the session and the plaintext token.
    /// The token should be returned to the client once and never stored server-side.
    pub fn authenticate_and_create_session(&self, cert_der: &[u8]) -> Result<SessionCreationResult> {
        let identity = self.authenticator.authenticate(cert_der)?;
        let result = self.sessions.create_session(identity);
        Ok(result)
    }

    /// Validate a session and return the identity
    pub fn validate_session(&self, session_id: &str) -> Result<ClientIdentity> {
        let session = self.sessions.validate_session(session_id)?;
        Ok(session.identity)
    }

    /// Check if a client can perform an operation on a key
    pub fn authorize_key_access(
        &self,
        identity: &ClientIdentity,
        key_id: &str,
        namespace: &str,
        permission: &Permission,
    ) -> Result<()> {
        // 1. Check namespace access
        self.namespaces.require_access(identity, namespace)?;

        // 2. Check RBAC permission
        self.rbac.require_any(&identity.roles, permission)?;

        // 3. Check key-level ACL
        self.acls.require_access(key_id, identity)?;

        Ok(())
    }

    /// Full authorization check for a session
    pub fn authorize_session(
        &self,
        session_id: &str,
        key_id: &str,
        namespace: &str,
        permission: &Permission,
    ) -> Result<ClientIdentity> {
        // Validate session and get identity
        let identity = self.validate_session(session_id)?;

        // Authorize access
        self.authorize_key_access(&identity, key_id, namespace, permission)?;

        Ok(identity)
    }

    /// Create a namespace
    pub fn create_namespace(&self, namespace: &str) -> Result<()> {
        self.namespaces.create_namespace(namespace)
    }

    /// Grant namespace access to a client
    pub fn grant_namespace_access(&self, namespace: &str, client_cn: &str) -> Result<()> {
        self.namespaces.grant_access(namespace, client_cn)
    }

    /// Create a key ACL
    pub fn create_key_acl(&self, key_id: KeyId, restricted: bool) -> KeyAcl {
        self.acls.create_acl(key_id, restricted)
    }

    /// Allow a client to access a key
    pub fn allow_key_access(&self, key_id: &str, client_cn: &str) -> Result<()> {
        self.acls.allow_client(key_id, client_cn)
    }

    /// Cleanup expired sessions
    pub fn cleanup_expired_sessions(&self) -> usize {
        self.sessions.cleanup_expired()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_auth_service_creation() {
        // This test would require valid certificates
        // Will be tested in integration tests
    }
}
