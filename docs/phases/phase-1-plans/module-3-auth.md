# Module 3: Authentication & Authorization - Implementation Plan

## Agent Mission
Build a secure authentication and authorization system using mTLS for client authentication and RBAC for fine-grained access control with complete namespace isolation.

## Critical Success Factors
1. All client connections must use mutual TLS
2. Certificate validation must be strict and secure
3. RBAC policies must be enforced before every operation
4. Namespace isolation must be cryptographically guaranteed
5. Session management must be secure and performant
6. Zero privilege escalation vulnerabilities

## File Structure
```
crates/auth/
├── Cargo.toml
├── src/
│   ├── lib.rs                 # Public API
│   ├── error.rs               # Error types
│   ├── mtls/
│   │   ├── mod.rs
│   │   ├── authenticator.rs   # mTLS authentication
│   │   ├── cert_validator.rs  # Certificate validation
│   │   └── identity.rs        # Client identity extraction
│   ├── rbac/
│   │   ├── mod.rs
│   │   ├── policy.rs          # RBAC policies
│   │   ├── role.rs            # Role definitions
│   │   └── permission.rs      # Permission checks
│   ├── namespace.rs           # Namespace access control
│   ├── session.rs             # Session management
│   └── acl.rs                 # Per-key ACLs
├── tests/
│   ├── mtls_tests.rs
│   ├── rbac_tests.rs
│   ├── namespace_tests.rs
│   └── integration_tests.rs
└── test-certs/                # Test certificates
    ├── ca.crt
    ├── server.crt
    └── client.crt
```

## Dependencies
```toml
[package]
name = "hsm-auth"
version = "0.1.0"
edition = "2021"

[dependencies]
# TLS
rustls = "0.22"
rustls-pemfile = "2.0"
tokio-rustls = "0.25"
x509-parser = "0.16"
webpki = "0.22"

# Async
tokio = { version = "1.35", features = ["sync", "rt"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Time
chrono = "0.4"

# Utilities
thiserror = "1.0"
parking_lot = "0.12"

[dev-dependencies]
rcgen = "0.12"  # For generating test certificates
```

## Key Implementation Details

### mTLS Authenticator
```rust
// src/mtls/authenticator.rs
use rustls::ServerConfig;
use x509_parser::prelude::*;

pub struct MtlsAuthenticator {
    tls_config: Arc<ServerConfig>,
}

impl MtlsAuthenticator {
    pub fn new(ca_cert: &[u8], server_cert: &[u8], server_key: &[u8]) -> Result<Self> {
        // Configure mutual TLS with client certificate validation
        // Extract client identity from certificate Common Name or SAN
    }

    pub fn authenticate(&self, cert_chain: &[Certificate]) -> Result<ClientIdentity> {
        // Validate certificate chain
        // Extract identity from certificate
        // Verify certificate is not expired/revoked
    }
}

#[derive(Debug, Clone)]
pub struct ClientIdentity {
    pub common_name: String,
    pub organization: Option<String>,
    pub namespace: String,
    pub roles: Vec<String>,
}
```

### RBAC Engine
```rust
// src/rbac/policy.rs
#[derive(Debug, Clone)]
pub enum Role {
    Admin,
    Operator,
    User,
    Auditor,
}

#[derive(Debug, Clone)]
pub enum Permission {
    GenerateKey,
    ImportKey,
    DeleteKey,
    Sign,
    Encrypt,
    Decrypt,
    RotateKey,
    ViewMetadata,
    ViewAuditLogs,
}

pub struct RbacPolicy {
    role_permissions: HashMap<Role, HashSet<Permission>>,
}

impl RbacPolicy {
    pub fn can(&self, role: &Role, permission: &Permission) -> bool {
        self.role_permissions
            .get(role)
            .map(|perms| perms.contains(permission))
            .unwrap_or(false)
    }
}
```

## Timeline
- Day 1: mTLS setup + certificate validation
- Day 2: RBAC implementation
- Day 3: Namespace isolation + ACLs
- Day 4: Testing + security audit
