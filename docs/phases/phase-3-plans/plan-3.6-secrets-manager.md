# Plan 3.6: Secrets Manager Mode

## Overview

Add secrets management capabilities to store, version, rotate, and access arbitrary secrets (API keys, passwords, certificates, connection strings). This brings functionality similar to HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault.

## Goals

- Store arbitrary key-value secrets with encryption at rest
- Automatic versioning with configurable retention
- Automatic rotation with pluggable rotation functions
- Lease-based access with automatic revocation
- Secret templating and dynamic generation
- Audit trail for all secret access
- Kubernetes integration (CSI driver, External Secrets Operator)

## Dependencies

Modify `crates/key-manager/Cargo.toml` or create new crate:

```toml
[package]
name = "hsm-secrets"
version.workspace = true
edition.workspace = true

[dependencies]
# Core HSM
hsm-crypto-engine = { path = "../crypto-engine" }
hsm-storage = { path = "../storage" }
hsm-auth = { path = "../auth" }
hsm-audit = { path = "../audit" }

# Async
tokio = { workspace = true, features = ["time", "sync"] }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }

# Time
chrono = { workspace = true }

# Templating
handlebars = "5.1"

# Scheduling (for rotation)
tokio-cron-scheduler = "0.10"

# Error handling
thiserror = { workspace = true }

# Utilities
uuid = { version = "1.7", features = ["v4"] }
```

## File Structure

```
crates/secrets/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Public API
│   ├── secret.rs           # Secret types and operations
│   ├── version.rs          # Version management
│   ├── rotation.rs         # Rotation engine
│   ├── lease.rs            # Lease management
│   ├── template.rs         # Secret templating
│   ├── store.rs            # Storage backend
│   ├── path.rs             # Path-based access
│   ├── policy.rs           # Access policies
│   └── engines/
│       ├── mod.rs          # Engine traits
│       ├── kv.rs           # Key-value engine
│       ├── database.rs     # Database credentials
│       ├── aws.rs          # AWS credentials
│       └── pki.rs          # PKI certificates
└── tests/
    └── integration.rs
```

## Implementation Steps

### Step 1: Define Secret Types

Create `crates/secrets/src/secret.rs`:

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret stored in the secrets manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    /// Unique identifier
    pub id: SecretId,
    /// Path for hierarchical organization
    pub path: SecretPath,
    /// Current version number
    pub current_version: u32,
    /// Metadata (not encrypted)
    pub metadata: SecretMetadata,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub updated_at: DateTime<Utc>,
}

/// Secret identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretId(pub String);

impl SecretId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

/// Path for organizing secrets hierarchically
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretPath(pub String);

impl SecretPath {
    pub fn new(path: impl Into<String>) -> Result<Self, SecretError> {
        let path = path.into();

        // Validate path format
        if path.is_empty() {
            return Err(SecretError::InvalidPath("Path cannot be empty".into()));
        }
        if !path.starts_with('/') {
            return Err(SecretError::InvalidPath("Path must start with /".into()));
        }
        if path.contains("//") {
            return Err(SecretError::InvalidPath("Path cannot contain //".into()));
        }

        Ok(Self(path))
    }

    pub fn join(&self, segment: &str) -> Result<Self, SecretError> {
        let new_path = if self.0.ends_with('/') {
            format!("{}{}", self.0, segment)
        } else {
            format!("{}/{}", self.0, segment)
        };
        Self::new(new_path)
    }

    pub fn parent(&self) -> Option<Self> {
        let path = self.0.trim_end_matches('/');
        path.rfind('/').map(|i| Self(path[..i].to_string()))
    }

    pub fn name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }
}

/// Metadata for a secret (stored unencrypted for querying)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretMetadata {
    /// Custom labels
    pub labels: HashMap<String, String>,
    /// Description
    pub description: Option<String>,
    /// Rotation configuration
    pub rotation: Option<RotationConfig>,
    /// Expiration time
    pub expires_at: Option<DateTime<Utc>>,
    /// Owner identity
    pub owner: Option<String>,
}

/// The actual secret data (encrypted at rest)
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretData {
    /// Key-value pairs
    #[zeroize(skip)]  // HashMap doesn't implement Zeroize
    pub data: HashMap<String, SecretValue>,
}

impl SecretData {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: impl Into<String>, value: SecretValue) {
        self.data.insert(key.into(), value);
    }

    pub fn get(&self, key: &str) -> Option<&SecretValue> {
        self.data.get(key)
    }
}

/// A single secret value
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecretValue {
    String(String),
    Binary(Vec<u8>),
    Json(serde_json::Value),
}

impl SecretValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            SecretValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            SecretValue::String(s) => s.as_bytes().to_vec(),
            SecretValue::Binary(b) => b.clone(),
            SecretValue::Json(j) => j.to_string().into_bytes(),
        }
    }
}

/// Rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    /// Rotation interval
    pub interval: RotationInterval,
    /// Rotation function/engine
    pub engine: String,
    /// Engine-specific configuration
    pub config: serde_json::Value,
    /// Last rotation time
    pub last_rotated_at: Option<DateTime<Utc>>,
    /// Next scheduled rotation
    pub next_rotation_at: Option<DateTime<Utc>>,
}

/// Rotation interval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationInterval {
    /// Rotate every N seconds
    Seconds(u64),
    /// Rotate every N days
    Days(u32),
    /// Cron expression
    Cron(String),
    /// Manual rotation only
    Manual,
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Secret not found: {0}")]
    NotFound(String),

    #[error("Version not found: {0}")]
    VersionNotFound(u32),

    #[error("Access denied")]
    AccessDenied,

    #[error("Lease expired")]
    LeaseExpired,

    #[error("Rotation failed: {0}")]
    RotationFailed(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),
}
```

### Step 2: Implement Version Management

Create `crates/secrets/src/version.rs`:

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::secret::{SecretData, SecretId};

/// A specific version of a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    /// The secret this version belongs to
    pub secret_id: SecretId,
    /// Version number (1-indexed)
    pub version: u32,
    /// The encrypted secret data
    pub data: EncryptedSecretData,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Who created this version
    pub created_by: Option<String>,
    /// Whether this version has been destroyed
    pub destroyed: bool,
    /// Destruction timestamp
    pub destroyed_at: Option<DateTime<Utc>>,
}

/// Encrypted secret data (stored at rest)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecretData {
    /// Encryption algorithm used
    pub algorithm: String,
    /// Key ID used for encryption
    pub key_id: String,
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// Nonce/IV
    pub nonce: Vec<u8>,
}

/// Version retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionPolicy {
    /// Maximum number of versions to keep
    pub max_versions: Option<u32>,
    /// Minimum time to keep versions
    pub min_retention: Option<chrono::Duration>,
    /// Whether to auto-destroy old versions
    pub auto_destroy: bool,
}

impl Default for VersionPolicy {
    fn default() -> Self {
        Self {
            max_versions: Some(10),
            min_retention: Some(chrono::Duration::days(7)),
            auto_destroy: false,
        }
    }
}

/// Version manager for a secret
pub struct VersionManager {
    policy: VersionPolicy,
}

impl VersionManager {
    pub fn new(policy: VersionPolicy) -> Self {
        Self { policy }
    }

    /// Determine which versions should be cleaned up
    pub fn versions_to_cleanup(&self, versions: &[SecretVersion]) -> Vec<u32> {
        let mut to_cleanup = Vec::new();
        let now = Utc::now();

        // Sort by version descending
        let mut sorted: Vec<_> = versions.iter().collect();
        sorted.sort_by(|a, b| b.version.cmp(&a.version));

        for (i, version) in sorted.iter().enumerate() {
            if version.destroyed {
                continue;
            }

            let should_cleanup = match self.policy.max_versions {
                Some(max) if i >= max as usize => {
                    // Check minimum retention
                    match self.policy.min_retention {
                        Some(min_ret) => {
                            now.signed_duration_since(version.created_at) > min_ret
                        }
                        None => true,
                    }
                }
                _ => false,
            };

            if should_cleanup && self.policy.auto_destroy {
                to_cleanup.push(version.version);
            }
        }

        to_cleanup
    }
}
```

### Step 3: Implement Lease Management

Create `crates/secrets/src/lease.rs`:

```rust
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use uuid::Uuid;

use super::secret::SecretId;

/// A lease granting temporary access to a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    /// Unique lease ID
    pub id: LeaseId,
    /// Secret being accessed
    pub secret_id: SecretId,
    /// Secret version
    pub version: u32,
    /// Client identity
    pub client_id: String,
    /// When the lease was created
    pub created_at: DateTime<Utc>,
    /// When the lease expires
    pub expires_at: DateTime<Utc>,
    /// Whether the lease has been revoked
    pub revoked: bool,
    /// Whether the lease is renewable
    pub renewable: bool,
    /// Maximum total TTL
    pub max_ttl: Option<Duration>,
}

/// Lease identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LeaseId(pub String);

impl LeaseId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

/// Lease configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseConfig {
    /// Default TTL for new leases
    pub default_ttl: Duration,
    /// Maximum TTL allowed
    pub max_ttl: Duration,
    /// Whether leases are renewable
    pub renewable: bool,
}

impl Default for LeaseConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::hours(1),
            max_ttl: Duration::hours(24),
            renewable: true,
        }
    }
}

/// Event when a lease expires or is revoked
#[derive(Debug, Clone)]
pub enum LeaseEvent {
    Expired(LeaseId),
    Revoked(LeaseId),
    Renewed(LeaseId, DateTime<Utc>),
}

/// Manages active leases
pub struct LeaseManager {
    leases: Arc<RwLock<HashMap<LeaseId, Lease>>>,
    config: LeaseConfig,
    event_tx: mpsc::Sender<LeaseEvent>,
}

impl LeaseManager {
    pub fn new(config: LeaseConfig) -> (Self, mpsc::Receiver<LeaseEvent>) {
        let (tx, rx) = mpsc::channel(1000);
        (
            Self {
                leases: Arc::new(RwLock::new(HashMap::new())),
                config,
                event_tx: tx,
            },
            rx,
        )
    }

    /// Create a new lease
    pub fn create_lease(
        &self,
        secret_id: SecretId,
        version: u32,
        client_id: String,
        ttl: Option<Duration>,
    ) -> Lease {
        let now = Utc::now();
        let ttl = ttl.unwrap_or(self.config.default_ttl);
        let ttl = std::cmp::min(ttl, self.config.max_ttl);

        let lease = Lease {
            id: LeaseId::new(),
            secret_id,
            version,
            client_id,
            created_at: now,
            expires_at: now + ttl,
            revoked: false,
            renewable: self.config.renewable,
            max_ttl: Some(self.config.max_ttl),
        };

        self.leases.write().insert(lease.id.clone(), lease.clone());

        // Schedule expiration
        let lease_id = lease.id.clone();
        let leases = self.leases.clone();
        let event_tx = self.event_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(ttl.to_std().unwrap_or_default()).await;
            let mut leases = leases.write();
            if let Some(lease) = leases.get_mut(&lease_id) {
                if !lease.revoked && Utc::now() >= lease.expires_at {
                    lease.revoked = true;
                    let _ = event_tx.send(LeaseEvent::Expired(lease_id)).await;
                }
            }
        });

        lease
    }

    /// Renew a lease
    pub fn renew_lease(
        &self,
        lease_id: &LeaseId,
        increment: Option<Duration>,
    ) -> Result<Lease, LeaseError> {
        let mut leases = self.leases.write();
        let lease = leases.get_mut(lease_id)
            .ok_or(LeaseError::NotFound)?;

        if lease.revoked {
            return Err(LeaseError::Revoked);
        }
        if !lease.renewable {
            return Err(LeaseError::NotRenewable);
        }

        let now = Utc::now();
        let increment = increment.unwrap_or(self.config.default_ttl);

        // Check max TTL
        let new_expires = now + increment;
        let max_expires = lease.created_at + lease.max_ttl.unwrap_or(self.config.max_ttl);

        lease.expires_at = std::cmp::min(new_expires, max_expires);

        Ok(lease.clone())
    }

    /// Revoke a lease
    pub fn revoke_lease(&self, lease_id: &LeaseId) -> Result<(), LeaseError> {
        let mut leases = self.leases.write();
        let lease = leases.get_mut(lease_id)
            .ok_or(LeaseError::NotFound)?;

        lease.revoked = true;
        let _ = self.event_tx.try_send(LeaseEvent::Revoked(lease_id.clone()));

        Ok(())
    }

    /// Revoke all leases for a secret
    pub fn revoke_all(&self, secret_id: &SecretId) {
        let mut leases = self.leases.write();
        for lease in leases.values_mut() {
            if &lease.secret_id == secret_id && !lease.revoked {
                lease.revoked = true;
                let _ = self.event_tx.try_send(LeaseEvent::Revoked(lease.id.clone()));
            }
        }
    }

    /// Check if a lease is valid
    pub fn validate_lease(&self, lease_id: &LeaseId) -> Result<&Lease, LeaseError> {
        let leases = self.leases.read();
        let lease = leases.get(lease_id)
            .ok_or(LeaseError::NotFound)?;

        if lease.revoked {
            return Err(LeaseError::Revoked);
        }
        if Utc::now() >= lease.expires_at {
            return Err(LeaseError::Expired);
        }

        // Return reference - need to restructure for this to work
        // For now, return owned clone
        drop(leases);
        Ok(self.leases.read().get(lease_id).unwrap())
    }

    /// List all active leases for a client
    pub fn list_client_leases(&self, client_id: &str) -> Vec<Lease> {
        self.leases
            .read()
            .values()
            .filter(|l| l.client_id == client_id && !l.revoked && Utc::now() < l.expires_at)
            .cloned()
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("Lease not found")]
    NotFound,

    #[error("Lease has been revoked")]
    Revoked,

    #[error("Lease has expired")]
    Expired,

    #[error("Lease is not renewable")]
    NotRenewable,
}
```

### Step 4: Implement Secret Store

Create `crates/secrets/src/store.rs`:

```rust
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;

use super::secret::*;
use super::version::*;
use super::lease::*;

/// Secret store operations
#[async_trait::async_trait]
pub trait SecretStore: Send + Sync {
    /// Create a new secret
    async fn create(
        &self,
        path: SecretPath,
        data: SecretData,
        metadata: SecretMetadata,
    ) -> Result<Secret, SecretError>;

    /// Get a secret (latest version)
    async fn get(&self, path: &SecretPath) -> Result<(Secret, SecretData), SecretError>;

    /// Get a specific version
    async fn get_version(
        &self,
        path: &SecretPath,
        version: u32,
    ) -> Result<(Secret, SecretData), SecretError>;

    /// Update a secret (creates new version)
    async fn update(
        &self,
        path: &SecretPath,
        data: SecretData,
    ) -> Result<Secret, SecretError>;

    /// Delete a secret (all versions)
    async fn delete(&self, path: &SecretPath) -> Result<(), SecretError>;

    /// Destroy a specific version (soft delete)
    async fn destroy_version(&self, path: &SecretPath, version: u32) -> Result<(), SecretError>;

    /// List secrets under a path prefix
    async fn list(&self, prefix: &SecretPath) -> Result<Vec<SecretPath>, SecretError>;

    /// Get metadata without decrypting
    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata, SecretError>;

    /// Update metadata
    async fn update_metadata(
        &self,
        path: &SecretPath,
        metadata: SecretMetadata,
    ) -> Result<(), SecretError>;
}

/// Secrets manager combining store, leases, and encryption
pub struct SecretsManager {
    store: Arc<dyn SecretStore>,
    lease_manager: LeaseManager,
    encryption_key_id: String,
}

impl SecretsManager {
    pub fn new(
        store: Arc<dyn SecretStore>,
        encryption_key_id: String,
    ) -> (Self, tokio::sync::mpsc::Receiver<LeaseEvent>) {
        let (lease_manager, lease_rx) = LeaseManager::new(LeaseConfig::default());

        (
            Self {
                store,
                lease_manager,
                encryption_key_id,
            },
            lease_rx,
        )
    }

    /// Create a secret with lease
    pub async fn create_secret(
        &self,
        path: SecretPath,
        data: SecretData,
        metadata: SecretMetadata,
        client_id: String,
        ttl: Option<chrono::Duration>,
    ) -> Result<(Secret, Lease), SecretError> {
        let secret = self.store.create(path, data, metadata).await?;

        let lease = self.lease_manager.create_lease(
            secret.id.clone(),
            secret.current_version,
            client_id,
            ttl,
        );

        Ok((secret, lease))
    }

    /// Read a secret with lease
    pub async fn read_secret(
        &self,
        path: &SecretPath,
        version: Option<u32>,
        client_id: String,
        ttl: Option<chrono::Duration>,
    ) -> Result<(SecretData, Lease), SecretError> {
        let (secret, data) = match version {
            Some(v) => self.store.get_version(path, v).await?,
            None => self.store.get(path).await?,
        };

        let lease = self.lease_manager.create_lease(
            secret.id.clone(),
            version.unwrap_or(secret.current_version),
            client_id,
            ttl,
        );

        Ok((data, lease))
    }

    /// Renew a lease
    pub fn renew_lease(
        &self,
        lease_id: &LeaseId,
        increment: Option<chrono::Duration>,
    ) -> Result<Lease, LeaseError> {
        self.lease_manager.renew_lease(lease_id, increment)
    }

    /// Revoke a lease
    pub fn revoke_lease(&self, lease_id: &LeaseId) -> Result<(), LeaseError> {
        self.lease_manager.revoke_lease(lease_id)
    }

    /// Revoke all leases for a secret
    pub fn revoke_secret_leases(&self, secret_id: &SecretId) {
        self.lease_manager.revoke_all(secret_id);
    }
}

/// In-memory implementation for testing
pub struct InMemorySecretStore {
    secrets: RwLock<HashMap<SecretPath, Secret>>,
    versions: RwLock<HashMap<(SecretId, u32), SecretVersion>>,
    data: RwLock<HashMap<(SecretId, u32), SecretData>>,
}

impl InMemorySecretStore {
    pub fn new() -> Self {
        Self {
            secrets: RwLock::new(HashMap::new()),
            versions: RwLock::new(HashMap::new()),
            data: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl SecretStore for InMemorySecretStore {
    async fn create(
        &self,
        path: SecretPath,
        data: SecretData,
        metadata: SecretMetadata,
    ) -> Result<Secret, SecretError> {
        let now = chrono::Utc::now();
        let secret = Secret {
            id: SecretId::new(),
            path: path.clone(),
            current_version: 1,
            metadata,
            created_at: now,
            updated_at: now,
        };

        self.secrets.write().insert(path, secret.clone());
        self.data.write().insert((secret.id.clone(), 1), data);

        Ok(secret)
    }

    async fn get(&self, path: &SecretPath) -> Result<(Secret, SecretData), SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets.get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?
            .clone();

        let data = self.data.read();
        let secret_data = data.get(&(secret.id.clone(), secret.current_version))
            .ok_or_else(|| SecretError::VersionNotFound(secret.current_version))?
            .clone();

        Ok((secret, secret_data))
    }

    async fn get_version(
        &self,
        path: &SecretPath,
        version: u32,
    ) -> Result<(Secret, SecretData), SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets.get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?
            .clone();

        let data = self.data.read();
        let secret_data = data.get(&(secret.id.clone(), version))
            .ok_or_else(|| SecretError::VersionNotFound(version))?
            .clone();

        Ok((secret, secret_data))
    }

    async fn update(
        &self,
        path: &SecretPath,
        data: SecretData,
    ) -> Result<Secret, SecretError> {
        let mut secrets = self.secrets.write();
        let secret = secrets.get_mut(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;

        secret.current_version += 1;
        secret.updated_at = chrono::Utc::now();

        let new_version = secret.current_version;
        let secret_clone = secret.clone();

        drop(secrets);

        self.data.write().insert((secret_clone.id.clone(), new_version), data);

        Ok(secret_clone)
    }

    async fn delete(&self, path: &SecretPath) -> Result<(), SecretError> {
        let secret = self.secrets.write().remove(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;

        // Remove all versions
        let mut data = self.data.write();
        for v in 1..=secret.current_version {
            data.remove(&(secret.id.clone(), v));
        }

        Ok(())
    }

    async fn destroy_version(&self, path: &SecretPath, version: u32) -> Result<(), SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets.get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;

        let mut data = self.data.write();
        data.remove(&(secret.id.clone(), version))
            .ok_or(SecretError::VersionNotFound(version))?;

        Ok(())
    }

    async fn list(&self, prefix: &SecretPath) -> Result<Vec<SecretPath>, SecretError> {
        let secrets = self.secrets.read();
        let paths: Vec<_> = secrets
            .keys()
            .filter(|p| p.0.starts_with(&prefix.0))
            .cloned()
            .collect();
        Ok(paths)
    }

    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata, SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets.get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;
        Ok(secret.metadata.clone())
    }

    async fn update_metadata(
        &self,
        path: &SecretPath,
        metadata: SecretMetadata,
    ) -> Result<(), SecretError> {
        let mut secrets = self.secrets.write();
        let secret = secrets.get_mut(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;
        secret.metadata = metadata;
        secret.updated_at = chrono::Utc::now();
        Ok(())
    }
}
```

### Step 5: Add gRPC/REST API

Add to `proto/secrets.proto`:

```protobuf
syntax = "proto3";
package hsm.secrets;

service SecretsService {
    // Secret CRUD
    rpc CreateSecret(CreateSecretRequest) returns (CreateSecretResponse);
    rpc ReadSecret(ReadSecretRequest) returns (ReadSecretResponse);
    rpc UpdateSecret(UpdateSecretRequest) returns (UpdateSecretResponse);
    rpc DeleteSecret(DeleteSecretRequest) returns (DeleteSecretResponse);
    rpc ListSecrets(ListSecretsRequest) returns (ListSecretsResponse);

    // Version management
    rpc ListVersions(ListVersionsRequest) returns (ListVersionsResponse);
    rpc DestroyVersion(DestroyVersionRequest) returns (DestroyVersionResponse);

    // Lease management
    rpc RenewLease(RenewLeaseRequest) returns (RenewLeaseResponse);
    rpc RevokeLease(RevokeLeaseRequest) returns (RevokeLeaseResponse);
}

message CreateSecretRequest {
    string path = 1;
    map<string, bytes> data = 2;
    SecretMetadata metadata = 3;
}

message CreateSecretResponse {
    string secret_id = 1;
    uint32 version = 2;
    LeaseInfo lease = 3;
}

message ReadSecretRequest {
    string path = 1;
    optional uint32 version = 2;
    optional int64 ttl_seconds = 3;
}

message ReadSecretResponse {
    map<string, bytes> data = 1;
    uint32 version = 2;
    LeaseInfo lease = 3;
}

message LeaseInfo {
    string lease_id = 1;
    int64 expires_at = 2;  // Unix timestamp
    bool renewable = 3;
}

message SecretMetadata {
    map<string, string> labels = 1;
    optional string description = 2;
    optional RotationConfig rotation = 3;
}

message RotationConfig {
    string interval = 1;  // "24h", "7d", or cron expression
    string engine = 2;
    bytes config = 3;  // JSON
}
```

### Step 6: Add REST Endpoints

Add to `crates/rest-api/src/routes/secrets.rs`:

```rust
use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
    Json, Router,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/secrets/*path", post(create_secret))
        .route("/secrets/*path", get(read_secret))
        .route("/secrets/*path", put(update_secret))
        .route("/secrets/*path", delete(delete_secret))
        .route("/secrets", get(list_secrets))
        .route("/leases/:lease_id/renew", post(renew_lease))
        .route("/leases/:lease_id", delete(revoke_lease))
}

#[derive(Debug, Deserialize)]
pub struct CreateSecretRequest {
    pub data: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub metadata: SecretMetadataInput,
}

#[derive(Debug, Serialize)]
pub struct SecretResponse {
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: i64,
    pub data: HashMap<String, serde_json::Value>,
}

async fn create_secret(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Json(request): Json<CreateSecretRequest>,
) -> Result<Json<SecretResponse>, ApiError> {
    // Implementation
    todo!()
}

async fn read_secret(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(params): Query<ReadParams>,
) -> Result<Json<SecretResponse>, ApiError> {
    // Implementation
    todo!()
}
```

## Testing Requirements

### Unit Tests

```rust
#[tokio::test]
async fn test_secret_create_read_roundtrip() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".into());

    let path = SecretPath::new("/app/database").unwrap();
    let mut data = SecretData::new();
    data.insert("username", SecretValue::String("admin".into()));
    data.insert("password", SecretValue::String("secret123".into()));

    let (secret, lease) = manager.create_secret(
        path.clone(),
        data,
        SecretMetadata::default(),
        "test-client".into(),
        None,
    ).await.unwrap();

    let (read_data, _) = manager.read_secret(
        &path,
        None,
        "test-client".into(),
        None,
    ).await.unwrap();

    assert_eq!(
        read_data.get("username").unwrap().as_str(),
        Some("admin")
    );
}

#[tokio::test]
async fn test_secret_versioning() {
    let store = Arc::new(InMemorySecretStore::new());

    // Create initial version
    let path = SecretPath::new("/app/api-key").unwrap();
    let mut data1 = SecretData::new();
    data1.insert("key", SecretValue::String("key-v1".into()));
    let secret = store.create(path.clone(), data1, SecretMetadata::default()).await.unwrap();
    assert_eq!(secret.current_version, 1);

    // Update to v2
    let mut data2 = SecretData::new();
    data2.insert("key", SecretValue::String("key-v2".into()));
    let secret = store.update(&path, data2).await.unwrap();
    assert_eq!(secret.current_version, 2);

    // Read v1
    let (_, v1_data) = store.get_version(&path, 1).await.unwrap();
    assert_eq!(v1_data.get("key").unwrap().as_str(), Some("key-v1"));

    // Read latest (v2)
    let (_, latest_data) = store.get(&path).await.unwrap();
    assert_eq!(latest_data.get("key").unwrap().as_str(), Some("key-v2"));
}

#[tokio::test]
async fn test_lease_expiration() {
    let (manager, mut rx) = LeaseManager::new(LeaseConfig {
        default_ttl: chrono::Duration::milliseconds(100),
        max_ttl: chrono::Duration::seconds(1),
        renewable: true,
    });

    let lease = manager.create_lease(
        SecretId::new(),
        1,
        "test-client".into(),
        None,
    );

    // Wait for expiration
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Should receive expiration event
    let event = rx.try_recv().unwrap();
    assert!(matches!(event, LeaseEvent::Expired(_)));
}
```

## Success Metrics

- [ ] Create/Read/Update/Delete secrets work
- [ ] Version history maintained correctly
- [ ] Leases expire and revoke properly
- [ ] Secret data encrypted at rest
- [ ] Path-based organization works
- [ ] Audit logging for all access
- [ ] REST API matches Vault-like interface

## Kubernetes Integration (Future)

```yaml
# ExternalSecret for external-secrets operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: hsm-secrets
    kind: ClusterSecretStore
  target:
    name: db-creds
  data:
    - secretKey: username
      remoteRef:
        key: /prod/database
        property: username
    - secretKey: password
      remoteRef:
        key: /prod/database
        property: password
```
