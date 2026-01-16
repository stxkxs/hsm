# Module 2: Key Management Module - Implementation Plan

## Agent Mission
Build a comprehensive key lifecycle management system that handles key generation, storage, rotation, metadata tracking, and secure deletion with complete namespace isolation for multi-tenancy.

## Critical Success Factors
1. Keys must never be exposed in plaintext outside the module boundary
2. Complete namespace isolation - zero cross-tenant leakage
3. Atomic operations for all state changes
4. Proper key material zeroization on deletion
5. Concurrent access must be thread-safe
6. Audit trail for all key lifecycle events

## File Structure
```
crates/key-manager/
├── Cargo.toml
├── src/
│   ├── lib.rs                 # Public API and traits
│   ├── error.rs               # Error types
│   ├── key.rs                 # Key types and structures
│   ├── metadata.rs            # Key metadata
│   ├── lifecycle.rs           # Key lifecycle management
│   ├── store.rs               # In-memory key store
│   ├── namespace.rs           # Namespace isolation
│   ├── rotation.rs            # Key rotation logic
│   └── policy.rs              # Key usage policies
├── tests/
│   ├── lifecycle_tests.rs
│   ├── namespace_tests.rs
│   ├── concurrent_tests.rs
│   └── integration_tests.rs
└── benches/
    └── key_manager_benches.rs
```

## Dependencies (Cargo.toml)
```toml
[package]
name = "hsm-key-manager"
version = "0.1.0"
edition = "2021"

[dependencies]
# Crypto engine (our module)
hsm-crypto-engine = { path = "../crypto-engine" }

# Security
zeroize = { version = "1.7", features = ["derive"] }
secrecy = "0.8"

# Concurrency
tokio = { version = "1.35", features = ["sync", "rt", "macros"] }
parking_lot = "0.12"

# Serialization
serde = { version = "1.0", features = ["derive"] }
bincode = "1.3"

# Time handling
chrono = { version = "0.4", features = ["serde"] }

# UUID for key IDs
uuid = { version = "1.6", features = ["v4", "serde"] }

# Error handling
thiserror = "1.0"
anyhow = "1.0"

[dev-dependencies]
tokio = { version = "1.35", features = ["full", "test-util"] }
proptest = "1.4"
criterion = "0.5"
```

## Implementation Steps

### Phase 1: Core Data Structures (Day 1)

**Step 1.1: Define Key Types (src/key.rs)**
```rust
use hsm_crypto_engine::{KeyMaterial, SignAlgorithm, EncryptAlgorithm};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use zeroize::Zeroizing;
use std::fmt;

/// Unique key identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(Uuid);

impl KeyId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_string(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }

    pub fn as_string(&self) -> String {
        self.0.to_string()
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Key type specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
    Ed448,
    Aes128,
    Aes256,
}

impl KeyType {
    pub fn is_asymmetric(&self) -> bool {
        matches!(self,
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 |
            KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 |
            KeyType::Ed25519 | KeyType::Ed448
        )
    }

    pub fn is_symmetric(&self) -> bool {
        !self.is_asymmetric()
    }
}

/// Key lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Key is being created
    Pending,
    /// Key is active and can be used
    Active,
    /// Key is deactivated but not deleted
    Deactivated,
    /// Key is compromised and should not be used
    Compromised,
    /// Key is scheduled for destruction
    Destroyed,
}

/// Key usage policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyUsagePolicy {
    /// Can be used for signing
    pub can_sign: bool,
    /// Can be used for encryption
    pub can_encrypt: bool,
    /// Can be used for key derivation
    pub can_derive: bool,
    /// Can be exported (encrypted only)
    pub can_export: bool,
    /// Maximum number of operations (None = unlimited)
    pub max_operations: Option<u64>,
    /// Expiration time (None = no expiration)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for KeyUsagePolicy {
    fn default() -> Self {
        Self {
            can_sign: true,
            can_encrypt: true,
            can_derive: false,
            can_export: false,
            max_operations: None,
            expires_at: None,
        }
    }
}

/// Complete key structure
pub struct Key {
    pub id: KeyId,
    pub key_type: KeyType,
    pub private_material: Option<KeyMaterial>,  // None for public-only keys
    pub public_material: Option<Vec<u8>>,       // None for symmetric keys
    pub state: KeyState,
    pub namespace: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub policy: KeyUsagePolicy,
    pub version: u32,
    pub previous_version: Option<KeyId>,  // For rotation tracking
    pub operation_count: u64,
}

impl Key {
    pub fn can_use(&self) -> bool {
        self.state == KeyState::Active && !self.is_expired()
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.policy.expires_at {
            chrono::Utc::now() > expires_at
        } else {
            false
        }
    }

    pub fn increment_operations(&mut self) {
        self.operation_count += 1;
    }

    pub fn has_reached_max_operations(&self) -> bool {
        if let Some(max) = self.policy.max_operations {
            self.operation_count >= max
        } else {
            false
        }
    }
}

/// Key specification for generation
#[derive(Debug, Clone)]
pub struct KeySpec {
    pub key_type: KeyType,
    pub namespace: String,
    pub policy: KeyUsagePolicy,
    pub labels: std::collections::HashMap<String, String>,
}
```

**Step 1.2: Define Metadata (src/metadata.rs)**
```rust
use super::key::{KeyId, KeyType, KeyState};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Key metadata (everything except the key material itself)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub id: KeyId,
    pub key_type: KeyType,
    pub state: KeyState,
    pub namespace: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: u32,
    pub previous_version: Option<KeyId>,
    pub operation_count: u64,
    pub labels: HashMap<String, String>,
    pub fingerprint: String,  // SHA-256 of public key or key ID
}

impl KeyMetadata {
    pub fn from_key(key: &super::key::Key) -> Self {
        Self {
            id: key.id,
            key_type: key.key_type,
            state: key.state,
            namespace: key.namespace.clone(),
            created_at: key.created_at,
            updated_at: Utc::now(),
            version: key.version,
            previous_version: key.previous_version,
            operation_count: key.operation_count,
            labels: HashMap::new(),
            fingerprint: Self::compute_fingerprint(&key.id),
        }
    }

    fn compute_fingerprint(key_id: &KeyId) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(key_id.as_string().as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Filter for querying keys
#[derive(Debug, Clone, Default)]
pub struct KeyFilter {
    pub key_type: Option<KeyType>,
    pub state: Option<KeyState>,
    pub labels: HashMap<String, String>,
}
```

### Phase 2: In-Memory Key Store (Day 1-2)

**Step 2.1: Implement Thread-Safe Key Store (src/store.rs)**
```rust
use super::key::{Key, KeyId, KeyState};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Thread-safe in-memory key store
pub struct KeyStore {
    // Namespace -> (KeyId -> Key)
    keys: Arc<RwLock<HashMap<String, HashMap<KeyId, Key>>>>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store a key in the given namespace
    pub fn insert(&self, namespace: &str, key: Key) -> Result<(), crate::Error> {
        let mut store = self.keys.write();

        let namespace_keys = store
            .entry(namespace.to_string())
            .or_insert_with(HashMap::new);

        if namespace_keys.contains_key(&key.id) {
            return Err(crate::Error::KeyAlreadyExists(key.id));
        }

        namespace_keys.insert(key.id, key);
        Ok(())
    }

    /// Get a key from the store
    pub fn get(&self, namespace: &str, key_id: &KeyId) -> Result<Key, crate::Error> {
        let store = self.keys.read();

        let namespace_keys = store
            .get(namespace)
            .ok_or(crate::Error::NamespaceNotFound(namespace.to_string()))?;

        namespace_keys
            .get(key_id)
            .cloned()
            .ok_or(crate::Error::KeyNotFound(*key_id))
    }

    /// Update a key in the store
    pub fn update<F>(&self, namespace: &str, key_id: &KeyId, updater: F) -> Result<(), crate::Error>
    where
        F: FnOnce(&mut Key),
    {
        let mut store = self.keys.write();

        let namespace_keys = store
            .get_mut(namespace)
            .ok_or(crate::Error::NamespaceNotFound(namespace.to_string()))?;

        let key = namespace_keys
            .get_mut(key_id)
            .ok_or(crate::Error::KeyNotFound(*key_id))?;

        updater(key);
        Ok(())
    }

    /// Delete a key from the store
    pub fn delete(&self, namespace: &str, key_id: &KeyId) -> Result<Key, crate::Error> {
        let mut store = self.keys.write();

        let namespace_keys = store
            .get_mut(namespace)
            .ok_or(crate::Error::NamespaceNotFound(namespace.to_string()))?;

        namespace_keys
            .remove(key_id)
            .ok_or(crate::Error::KeyNotFound(*key_id))
    }

    /// List all keys in a namespace
    pub fn list(&self, namespace: &str) -> Result<Vec<KeyId>, crate::Error> {
        let store = self.keys.read();

        match store.get(namespace) {
            Some(namespace_keys) => Ok(namespace_keys.keys().copied().collect()),
            None => Ok(Vec::new()),
        }
    }

    /// Count keys in a namespace
    pub fn count(&self, namespace: &str) -> usize {
        let store = self.keys.read();
        store.get(namespace).map(|keys| keys.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{KeyType, KeyState};

    #[test]
    fn test_key_store_basic_operations() {
        let store = KeyStore::new();
        let namespace = "test-namespace";

        let key = create_test_key(namespace);
        let key_id = key.id;

        // Insert
        store.insert(namespace, key).unwrap();

        // Get
        let retrieved = store.get(namespace, &key_id).unwrap();
        assert_eq!(retrieved.id, key_id);

        // Update
        store.update(namespace, &key_id, |k| {
            k.state = KeyState::Deactivated;
        }).unwrap();

        let updated = store.get(namespace, &key_id).unwrap();
        assert_eq!(updated.state, KeyState::Deactivated);

        // Delete
        let deleted = store.delete(namespace, &key_id).unwrap();
        assert_eq!(deleted.id, key_id);

        // Verify deletion
        assert!(store.get(namespace, &key_id).is_err());
    }

    fn create_test_key(namespace: &str) -> Key {
        use chrono::Utc;
        use crate::key::KeyUsagePolicy;

        Key {
            id: KeyId::new(),
            key_type: KeyType::Ed25519,
            private_material: None,
            public_material: None,
            state: KeyState::Active,
            namespace: namespace.to_string(),
            created_at: Utc::now(),
            policy: KeyUsagePolicy::default(),
            version: 1,
            previous_version: None,
            operation_count: 0,
        }
    }
}
```

### Phase 3: Key Manager Implementation (Day 2-3)

**Step 3.1: Main Key Manager (src/lib.rs)**
```rust
//! Key Management Module
//!
//! Handles complete key lifecycle: generation, storage, rotation, and deletion

use hsm_crypto_engine::{CryptoEngine, DefaultCryptoEngine};
use std::sync::Arc;
use chrono::Utc;

pub mod error;
pub mod key;
pub mod metadata;
pub mod lifecycle;
pub mod store;
pub mod namespace;
pub mod rotation;
pub mod policy;

pub use error::{Error, Result};
pub use key::{Key, KeyId, KeyType, KeyState, KeySpec, KeyUsagePolicy};
pub use metadata::{KeyMetadata, KeyFilter};
use store::KeyStore;

/// Main key manager trait
pub trait KeyManager: Send + Sync {
    /// Generate a new key
    fn generate_key(&self, spec: KeySpec) -> Result<KeyId>;

    /// Import an existing key
    fn import_key(&self, key_data: Vec<u8>, spec: KeySpec) -> Result<KeyId>;

    /// Get a key by ID (for cryptographic operations)
    fn get_key(&self, key_id: &KeyId, namespace: &str) -> Result<Key>;

    /// Get key metadata (without key material)
    fn get_metadata(&self, key_id: &KeyId, namespace: &str) -> Result<KeyMetadata>;

    /// List keys in a namespace
    fn list_keys(&self, namespace: &str, filter: KeyFilter) -> Result<Vec<KeyMetadata>>;

    /// Rotate a key (create new version)
    fn rotate_key(&self, key_id: &KeyId, namespace: &str) -> Result<KeyId>;

    /// Update key state
    fn update_state(&self, key_id: &KeyId, namespace: &str, state: KeyState) -> Result<()>;

    /// Delete a key (marks as destroyed and wipes material)
    fn delete_key(&self, key_id: &KeyId, namespace: &str) -> Result<()>;

    /// Increment operation counter
    fn increment_operations(&self, key_id: &KeyId, namespace: &str) -> Result<()>;
}

/// Default implementation of KeyManager
pub struct DefaultKeyManager {
    store: KeyStore,
    crypto_engine: Arc<dyn CryptoEngine>,
}

impl DefaultKeyManager {
    pub fn new() -> Self {
        Self {
            store: KeyStore::new(),
            crypto_engine: Arc::new(DefaultCryptoEngine),
        }
    }

    pub fn with_crypto_engine(crypto_engine: Arc<dyn CryptoEngine>) -> Self {
        Self {
            store: KeyStore::new(),
            crypto_engine,
        }
    }
}

impl KeyManager for DefaultKeyManager {
    fn generate_key(&self, spec: KeySpec) -> Result<KeyId> {
        use hsm_crypto_engine::asymmetric::{ed25519, ecdsa, rsa};

        // Generate key material using crypto engine
        let (private_material, public_material) = match spec.key_type {
            KeyType::Ed25519 => {
                let (priv_key, pub_key) = ed25519::Ed25519Engine::generate_keypair()
                    .map_err(|e| Error::KeyGenerationFailed(e.to_string()))?;
                (Some(priv_key), Some(pub_key))
            }
            KeyType::EcdsaP256 => {
                let (priv_key, pub_key) = ecdsa::EcdsaEngine::generate_p256_keypair()
                    .map_err(|e| Error::KeyGenerationFailed(e.to_string()))?;
                (Some(priv_key), Some(pub_key))
            }
            KeyType::Rsa2048 => {
                let (priv_key, pub_key) = rsa::RsaEngine::generate_keypair(2048)
                    .map_err(|e| Error::KeyGenerationFailed(e.to_string()))?;
                (Some(priv_key), Some(pub_key))
            }
            _ => return Err(Error::UnsupportedKeyType(spec.key_type)),
        };

        // Create key object
        let key = Key {
            id: KeyId::new(),
            key_type: spec.key_type,
            private_material,
            public_material,
            state: KeyState::Active,
            namespace: spec.namespace.clone(),
            created_at: Utc::now(),
            policy: spec.policy,
            version: 1,
            previous_version: None,
            operation_count: 0,
        };

        let key_id = key.id;

        // Store key
        self.store.insert(&spec.namespace, key)?;

        Ok(key_id)
    }

    fn get_key(&self, key_id: &KeyId, namespace: &str) -> Result<Key> {
        let key = self.store.get(namespace, key_id)?;

        // Verify key can be used
        if !key.can_use() {
            return Err(Error::KeyNotUsable(*key_id));
        }

        if key.has_reached_max_operations() {
            return Err(Error::MaxOperationsReached(*key_id));
        }

        Ok(key)
    }

    fn get_metadata(&self, key_id: &KeyId, namespace: &str) -> Result<KeyMetadata> {
        let key = self.store.get(namespace, key_id)?;
        Ok(KeyMetadata::from_key(&key))
    }

    fn list_keys(&self, namespace: &str, filter: KeyFilter) -> Result<Vec<KeyMetadata>> {
        let key_ids = self.store.list(namespace)?;

        let mut metadata_list = Vec::new();
        for key_id in key_ids {
            if let Ok(key) = self.store.get(namespace, &key_id) {
                // Apply filters
                if let Some(key_type) = filter.key_type {
                    if key.key_type != key_type {
                        continue;
                    }
                }

                if let Some(state) = filter.state {
                    if key.state != state {
                        continue;
                    }
                }

                metadata_list.push(KeyMetadata::from_key(&key));
            }
        }

        Ok(metadata_list)
    }

    fn rotate_key(&self, key_id: &KeyId, namespace: &str) -> Result<KeyId> {
        // Get existing key
        let old_key = self.store.get(namespace, key_id)?;

        // Create new key spec with same properties
        let spec = KeySpec {
            key_type: old_key.key_type,
            namespace: namespace.to_string(),
            policy: old_key.policy.clone(),
            labels: std::collections::HashMap::new(),
        };

        // Generate new key
        let new_key_id = self.generate_key(spec)?;

        // Update new key to reference old key
        self.store.update(namespace, &new_key_id, |key| {
            key.previous_version = Some(*key_id);
            key.version = old_key.version + 1;
        })?;

        // Deactivate old key
        self.update_state(key_id, namespace, KeyState::Deactivated)?;

        Ok(new_key_id)
    }

    fn update_state(&self, key_id: &KeyId, namespace: &str, state: KeyState) -> Result<()> {
        self.store.update(namespace, key_id, |key| {
            key.state = state;
        })
    }

    fn delete_key(&self, key_id: &KeyId, namespace: &str) -> Result<()> {
        // Mark as destroyed first
        self.update_state(key_id, namespace, KeyState::Destroyed)?;

        // Remove from store (this will zeroize the key material on drop)
        let _deleted_key = self.store.delete(namespace, key_id)?;

        // Key material is automatically zeroized due to Drop implementation

        Ok(())
    }

    fn increment_operations(&self, key_id: &KeyId, namespace: &str) -> Result<()> {
        self.store.update(namespace, key_id, |key| {
            key.increment_operations();
        })
    }

    fn import_key(&self, _key_data: Vec<u8>, _spec: KeySpec) -> Result<KeyId> {
        // TODO: Implement key import
        Err(Error::NotImplemented("Key import not yet implemented".into()))
    }
}
```

**Step 3.2: Error Handling (src/error.rs)**
```rust
use thiserror::Error;
use crate::key::{KeyId, KeyType};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Key not found: {0}")]
    KeyNotFound(KeyId),

    #[error("Key already exists: {0}")]
    KeyAlreadyExists(KeyId),

    #[error("Namespace not found: {0}")]
    NamespaceNotFound(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Key is not in a usable state: {0}")]
    KeyNotUsable(KeyId),

    #[error("Key has reached maximum operations: {0}")]
    MaxOperationsReached(KeyId),

    #[error("Unsupported key type: {0:?}")]
    UnsupportedKeyType(KeyType),

    #[error("Invalid key data: {0}")]
    InvalidKeyData(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Crypto engine error: {0}")]
    CryptoEngine(#[from] hsm_crypto_engine::CryptoError),
}

pub type Result<T> = std::result::Result<T, Error>;
```

### Phase 4: Namespace Isolation (Day 3)

**Step 4.1: Namespace Management (src/namespace.rs)**
```rust
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;

/// Namespace configuration
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub name: String,
    pub max_keys: usize,
    pub allowed_key_types: Vec<crate::KeyType>,
}

/// Namespace manager for multi-tenancy
pub struct NamespaceManager {
    configs: Arc<RwLock<HashMap<String, NamespaceConfig>>>,
}

impl NamespaceManager {
    pub fn new() -> Self {
        Self {
            configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn create_namespace(&self, config: NamespaceConfig) -> Result<(), crate::Error> {
        let mut configs = self.configs.write();

        if configs.contains_key(&config.name) {
            return Err(crate::Error::NamespaceNotFound(
                format!("Namespace already exists: {}", config.name)
            ));
        }

        configs.insert(config.name.clone(), config);
        Ok(())
    }

    pub fn get_config(&self, namespace: &str) -> Result<NamespaceConfig, crate::Error> {
        let configs = self.configs.read();
        configs.get(namespace)
            .cloned()
            .ok_or_else(|| crate::Error::NamespaceNotFound(namespace.to_string()))
    }

    pub fn validate_key_type(&self, namespace: &str, key_type: crate::KeyType) -> Result<(), crate::Error> {
        let config = self.get_config(namespace)?;

        if !config.allowed_key_types.contains(&key_type) {
            return Err(crate::Error::UnsupportedKeyType(key_type));
        }

        Ok(())
    }
}
```

### Phase 5: Testing (Day 4)

**Step 5.1: Comprehensive Tests**
```rust
// tests/lifecycle_tests.rs
use hsm_key_manager::*;

#[test]
fn test_key_lifecycle() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    // Generate
    let key_id = manager.generate_key(spec).unwrap();

    // Retrieve
    let key = manager.get_key(&key_id, "test").unwrap();
    assert_eq!(key.state, KeyState::Active);

    // Rotate
    let new_key_id = manager.rotate_key(&key_id, "test").unwrap();
    assert_ne!(key_id, new_key_id);

    // Verify old key is deactivated
    let old_key = manager.get_key(&key_id, "test");
    assert!(old_key.is_err());

    // Delete
    manager.delete_key(&new_key_id, "test").unwrap();
}

// tests/namespace_tests.rs
#[test]
fn test_namespace_isolation() {
    let manager = DefaultKeyManager::new();

    let spec1 = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "namespace1".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let spec2 = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "namespace2".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id1 = manager.generate_key(spec1).unwrap();
    let key_id2 = manager.generate_key(spec2).unwrap();

    // Key from namespace1 should not be accessible from namespace2
    assert!(manager.get_key(&key_id1, "namespace2").is_err());
    assert!(manager.get_key(&key_id2, "namespace1").is_err());

    // But should be accessible from their own namespaces
    assert!(manager.get_key(&key_id1, "namespace1").is_ok());
    assert!(manager.get_key(&key_id2, "namespace2").is_ok());
}
```

## Integration Points

### Depends On
- `hsm-crypto-engine` - for key generation

### Provides To
- `hsm-grpc-api` - key management operations
- `hsm-storage` - keys to persist
- `hsm-audit` - lifecycle events to audit

## Success Criteria
1. ✅ All key types supported (RSA, ECDSA, Ed25519, AES)
2. ✅ Complete namespace isolation (zero leakage)
3. ✅ Thread-safe concurrent operations
4. ✅ Proper key material zeroization
5. ✅ All tests pass (unit, integration, concurrent)
6. ✅ Code coverage > 80%

## Timeline
- Day 1: Data structures + In-memory store
- Day 2-3: Key manager implementation
- Day 3: Namespace isolation
- Day 4: Testing
