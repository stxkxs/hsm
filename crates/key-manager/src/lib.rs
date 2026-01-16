//! Key Management Module
//!
//! Provides comprehensive key lifecycle management for the HSM, including generation,
//! storage, rotation, and secure deletion of cryptographic keys.
//!
//! # Key Lifecycle States
//!
//! Keys progress through the following states during their lifetime:
//!
//! ```text
//! ┌──────────────┐
//! │  Generation  │  ◄─── New key created
//! └──────┬───────┘
//!        │
//!        ▼
//! ┌──────────────┐
//! │    Active    │  ◄─── Key can be used for crypto operations
//! └──────┬───────┘
//!        │
//!        ├─────► rotate_key() ─────► New Active key (version n+1)
//!        │                          Old key → Deactivated
//!        │
//!        ▼
//! ┌──────────────┐
//! │ Deactivated  │  ◄─── Key can decrypt/verify old data, but not sign/encrypt new data
//! └──────┬───────┘
//!        │
//!        ▼
//! ┌──────────────┐
//! │  Destroyed   │  ◄─── Key material wiped, only metadata remains
//! └──────────────┘
//! ```
//!
//! ## State Transitions
//!
//! - **Active → Deactivated**: Manual via `update_state()` or automatic via `rotate_key()`
//! - **Deactivated → Destroyed**: Manual via `delete_key()`
//! - **Active → Destroyed**: Direct deletion via `delete_key()`
//!
//! See [`KeyState`] for detailed state documentation.
//!
//! # Key Rotation Design
//!
//! Key rotation creates a new key version while preserving the old key for decryption/verification.
//!
//! ## Rotation Process
//!
//! 1. **Generate New Key**: Create new key with same type and policy
//! 2. **Link Versions**: New key references old key via `previous_version`
//! 3. **Increment Version**: New key gets `version = old_version + 1`
//! 4. **Deactivate Old Key**: Old key transitions to `Deactivated` state
//! 5. **Activate New Key**: New key is `Active` for new operations
//!
//! ## Version Chain
//!
//! Keys maintain a version chain for audit and rollback:
//!
//! ```text
//! key_v1 (Deactivated) ◄─── key_v2 (Deactivated) ◄─── key_v3 (Active)
//!   └─ previous_version: None    └─ previous_version: key_v1   └─ previous_version: key_v2
//! ```
//!
//! ## Use Cases
//!
//! - **Scheduled Rotation**: Rotate keys on a fixed schedule (e.g., every 90 days)
//! - **Compromise Recovery**: Rotate immediately if key may be compromised
//! - **Compliance**: Meet regulatory requirements for key rotation
//! - **Cryptoperiod Limits**: Limit amount of data encrypted with a single key
//!
//! ## Future Implementation
//!
//! The rotation module ([`rotation`]) will provide:
//! - Automatic rotation policies (time-based, operation-count-based)
//! - Rotation scheduling and execution
//! - Rotation history and audit logs
//!
//! # Namespace Isolation
//!
//! Keys are isolated by namespace to provide multi-tenancy:
//!
//! - **Isolation**: Keys in namespace "A" cannot be accessed from namespace "B"
//! - **Organization**: Group keys by environment (prod/dev), service, or tenant
//! - **Access Control**: Integrate with RBAC for namespace-level permissions
//!
//! # Examples
//!
//! ## Basic Key Generation
//!
//! ```
//! use key_manager::{DefaultKeyManager, KeyManager, KeySpec, KeyType, KeyUsagePolicy};
//! use std::collections::HashMap;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let manager = DefaultKeyManager::new();
//!
//! // Create a key specification
//! let spec = KeySpec {
//!     key_type: KeyType::Ed25519,
//!     namespace: "production".to_string(),
//!     policy: KeyUsagePolicy {
//!         allowed_operations: vec!["sign".to_string(), "verify".to_string()],
//!         max_operations: Some(1_000_000),
//!         expires_at: None,
//!     },
//!     labels: HashMap::new(),
//! };
//!
//! // Generate the key
//! let key_id = manager.generate_key(spec)?;
//! println!("Generated key: {:?}", key_id);
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Rotation
//!
//! ```
//! use key_manager::{DefaultKeyManager, KeyManager, KeySpec, KeyType, KeyUsagePolicy};
//! use std::collections::HashMap;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let manager = DefaultKeyManager::new();
//!
//! // Generate initial key
//! let spec = KeySpec {
//!     key_type: KeyType::Rsa2048,
//!     namespace: "production".to_string(),
//!     policy: KeyUsagePolicy {
//!         allowed_operations: vec!["sign".to_string()],
//!         max_operations: None,
//!         expires_at: None,
//!     },
//!     labels: HashMap::new(),
//! };
//! let old_key_id = manager.generate_key(spec)?;
//!
//! // Rotate the key (creates new version, deactivates old)
//! let new_key_id = manager.rotate_key(&old_key_id, "production")?;
//!
//! // Old key is now deactivated but can still verify old signatures
//! let old_key = manager.get_key(&old_key_id, "production")?;
//! // ^ This will fail because deactivated keys cannot be used
//!
//! // New key is active and should be used for new signatures
//! let new_key = manager.get_key(&new_key_id, "production")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Listing Keys with Filters
//!
//! ```
//! use key_manager::{DefaultKeyManager, KeyManager, KeyFilter, KeyState};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let manager = DefaultKeyManager::new();
//!
//! // List all active keys in a namespace
//! let filter = KeyFilter {
//!     key_type: None,
//!     state: Some(KeyState::Active),
//! };
//!
//! let keys = manager.list_keys("production", filter)?;
//! println!("Found {} active keys", keys.len());
//! # Ok(())
//! # }
//! ```

use chrono::Utc;
use hsm_crypto_engine::{CryptoEngine, DefaultCryptoEngine};
use std::sync::Arc;

pub mod error;
pub mod key;
pub mod lifecycle;
pub mod metadata;
pub mod namespace;
pub mod policy;
pub mod rotation;
pub mod store;

pub use error::{Error, Result};
pub use key::{Key, KeyId, KeySpec, KeyState, KeyType, KeyUsagePolicy};
pub use metadata::{KeyFilter, KeyMetadata};
use store::KeyStore;

/// Main key manager trait
pub trait KeyManager: Send + Sync {
    /// Generate a new key
    fn generate_key(&self, spec: KeySpec) -> Result<KeyId>;

    /// Import an existing key
    fn import_key(&self, key_data: Vec<u8>, spec: KeySpec) -> Result<KeyId>;

    /// Get a key by ID (for cryptographic operations)
    fn get_key(&self, key_id: &KeyId, namespace: &str) -> Result<Arc<Key>>;

    /// Get key metadata (without key material)
    fn get_metadata(&self, key_id: &KeyId, namespace: &str) -> Result<KeyMetadata>;

    /// List keys in a namespace
    fn list_keys(&self, namespace: &str, filter: KeyFilter) -> Result<Vec<KeyMetadata>>;

    /// List keys with pagination (batch operation)
    fn list_keys_batch(
        &self,
        namespace: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<KeyMetadata>>;

    /// Generate multiple keys in batch
    fn generate_keys_batch(&self, specs: Vec<KeySpec>) -> Result<Vec<KeyId>>;

    /// Delete multiple keys in batch
    fn delete_keys_batch(&self, key_ids: Vec<(KeyId, String)>) -> Result<()>;

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
    #[allow(dead_code)]
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

impl Default for DefaultKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyManager for DefaultKeyManager {
    fn generate_key(&self, spec: KeySpec) -> Result<KeyId> {
        use hsm_crypto_engine::asymmetric::{ecdsa, ed25519, rsa};

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
            KeyType::EcdsaP384 => {
                let (priv_key, pub_key) = ecdsa::EcdsaEngine::generate_p384_keypair()
                    .map_err(|e| Error::KeyGenerationFailed(e.to_string()))?;
                (Some(priv_key), Some(pub_key))
            }
            KeyType::Rsa2048 => {
                let (priv_key, pub_key) = rsa::RsaEngine::generate_keypair(2048)
                    .map_err(|e| Error::KeyGenerationFailed(e.to_string()))?;
                (Some(priv_key), Some(pub_key))
            }
            KeyType::Rsa3072 => {
                let (priv_key, pub_key) = rsa::RsaEngine::generate_keypair(3072)
                    .map_err(|e| Error::KeyGenerationFailed(e.to_string()))?;
                (Some(priv_key), Some(pub_key))
            }
            KeyType::Rsa4096 => {
                let (priv_key, pub_key) = rsa::RsaEngine::generate_keypair(4096)
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

    fn get_key(&self, key_id: &KeyId, namespace: &str) -> Result<Arc<Key>> {
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
        Err(Error::NotImplemented(
            "Key import not yet implemented".into(),
        ))
    }

    fn list_keys_batch(
        &self,
        namespace: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<KeyMetadata>> {
        let key_ids = self.store.list_batch(namespace, offset, limit)?;

        let mut metadata_list = Vec::new();
        for key_id in key_ids {
            if let Ok(key) = self.store.get(namespace, &key_id) {
                metadata_list.push(KeyMetadata::from_key(&key));
            }
        }

        Ok(metadata_list)
    }

    fn generate_keys_batch(&self, specs: Vec<KeySpec>) -> Result<Vec<KeyId>> {
        let mut key_ids = Vec::new();

        for spec in specs {
            let key_id = self.generate_key(spec)?;
            key_ids.push(key_id);
        }

        Ok(key_ids)
    }

    fn delete_keys_batch(&self, key_ids: Vec<(KeyId, String)>) -> Result<()> {
        for (key_id, namespace) in key_ids {
            self.delete_key(&key_id, &namespace)?;
        }

        Ok(())
    }
}
