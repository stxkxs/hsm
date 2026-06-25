#![deny(unsafe_code)]

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
//! │  Destroyed   │  ◄─── Key material zeroized and entry removed (terminal)
//! └──────────────┘
//! ```
//!
//! ## State Transitions
//!
//! - **Active → Deactivated**: Manual via `update_state()` or automatic via `rotate_key()`
//! - **Deactivated → Destroyed**: Terminal deletion via `delete_key()`
//! - **Active → Destroyed**: Terminal deletion via `delete_key()`
//!
//! Reaching `Destroyed` via [`KeyManager::delete_key`] zeroizes the private key
//! material and removes the store entry; a subsequent `get_key` therefore
//! returns [`Error::KeyNotFound`]. (`KeyState::Destroyed` itself remains a valid
//! metadata state for backends, such as the hardware manager, that retain a
//! destroyed-key tombstone.)
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
//! use hsm_key_manager::{DefaultKeyManager, KeyManager, KeySpec, KeyType, KeyUsagePolicy};
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
//!         can_sign: true,
//!         can_encrypt: false,
//!         can_derive: false,
//!         can_export: false,
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
//! ```no_run
//! use hsm_key_manager::{DefaultKeyManager, KeyManager, KeySpec, KeyType, KeyUsagePolicy};
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
//!         can_sign: true,
//!         can_encrypt: false,
//!         can_derive: false,
//!         can_export: false,
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
//! use hsm_key_manager::{DefaultKeyManager, KeyManager, KeyFilter, KeyState};
//! use std::collections::HashMap;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let manager = DefaultKeyManager::new();
//!
//! // List all active keys in a namespace
//! let filter = KeyFilter {
//!     key_type: None,
//!     state: Some(KeyState::Active),
//!     labels: HashMap::new(),
//! };
//!
//! let keys = manager.list_keys("production", filter)?;
//! println!("Found {} active keys", keys.len());
//! # Ok(())
//! # }
//! ```

use chrono::Utc;
use hsm_crypto_engine::{CryptoEngine, DefaultCryptoEngine};
use hsm_storage::StorageBackend;
use std::sync::{Arc, Mutex};

pub mod error;
pub mod hd;
pub mod key;
pub mod lifecycle;
pub mod metadata;
pub mod namespace;
pub mod policy;
pub mod rotation;
pub mod store;

#[cfg(feature = "hardware")]
pub mod hardware;

#[cfg(feature = "hardware")]
pub mod config;

pub use error::{Error, Result};
pub use hd::{HdKeyManager, MasterKeyResult, MnemonicStrength};
pub use key::{HdKeyInfo, Key, KeyId, KeySpec, KeyState, KeyType, KeyUsagePolicy};
pub use metadata::{KeyFilter, KeyMetadata};
use store::KeyStore;

#[cfg(feature = "hardware")]
pub use hardware::{AsyncKeyManager, HardwareKeyManager};

#[cfg(feature = "hardware")]
pub use config::{
    create_hardware_backend, create_hardware_key_manager, HardwareBackendConfig,
    KeyManagerBackendType, KeyManagerConfig, NitroConfig, SevConfig, SgxConfig,
};

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
    /// Crypto engine retained for dependency injection. Key operations currently
    /// call the crypto-engine functions directly; this handle lets an alternative
    /// engine be supplied via `with_crypto_engine`.
    #[allow(dead_code)]
    crypto_engine: Arc<dyn CryptoEngine>,
    /// Optional durable, encrypted backing store.
    ///
    /// When present, key-lifecycle mutations (generate, import, rotate, state
    /// changes, delete) are written through to encrypted persistent storage and
    /// the in-memory working set is rehydrated from it on startup via
    /// [`DefaultKeyManager::hydrate`], so keys survive process restarts. When
    /// absent the manager is purely in-memory (suitable for tests).
    ///
    /// The hot path ([`KeyManager::increment_operations`], called on every crypto
    /// operation) is intentionally NOT persisted — that would mean a disk write
    /// per signature — so the operation counter is best-effort across restarts.
    storage: Option<Arc<Mutex<dyn StorageBackend>>>,
}

impl DefaultKeyManager {
    pub fn new() -> Self {
        Self {
            store: KeyStore::new(),
            crypto_engine: Arc::new(DefaultCryptoEngine),
            storage: None,
        }
    }

    pub fn with_crypto_engine(crypto_engine: Arc<dyn CryptoEngine>) -> Self {
        Self {
            store: KeyStore::new(),
            crypto_engine,
            storage: None,
        }
    }

    /// Create a key manager backed by a durable, encrypted storage backend.
    ///
    /// Lifecycle mutations are written through to `storage`. Call
    /// [`DefaultKeyManager::hydrate`] once after construction to load any
    /// previously persisted keys into the in-memory working set.
    pub fn with_storage(storage: Arc<Mutex<dyn StorageBackend>>) -> Self {
        Self {
            store: KeyStore::new(),
            crypto_engine: Arc::new(DefaultCryptoEngine),
            storage: Some(storage),
        }
    }

    /// Load all persisted keys from the durable backing store into the in-memory
    /// working set. No-op when no storage backend is configured. Returns the
    /// number of keys loaded.
    pub fn hydrate(&self) -> Result<usize> {
        let Some(storage) = &self.storage else {
            return Ok(0);
        };
        let storage = storage
            .lock()
            .map_err(|_| Error::StorageError("storage mutex poisoned during hydrate".into()))?;
        let mut loaded = 0;
        for namespace in storage
            .list_namespaces()
            .map_err(|e| Error::StorageError(e.to_string()))?
        {
            for key_id in storage
                .list_keys(&namespace)
                .map_err(|e| Error::StorageError(e.to_string()))?
            {
                let bytes = storage
                    .load_key(&key_id, &namespace)
                    .map_err(|e| Error::StorageError(e.to_string()))?;
                let key: Key = postcard::from_bytes(&bytes).map_err(|e| {
                    Error::StorageError(format!("failed to deserialize persisted key: {e}"))
                })?;
                self.store.insert(&namespace, key)?;
                loaded += 1;
            }
        }
        Ok(loaded)
    }

    /// Write a key through to the durable backing store (no-op if none).
    fn persist_key(&self, namespace: &str, key: &Key) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let bytes = postcard::to_allocvec(key)
            .map_err(|e| Error::StorageError(format!("failed to serialize key: {e}")))?;
        let mut storage = storage
            .lock()
            .map_err(|_| Error::StorageError("storage mutex poisoned".into()))?;
        // Create the namespace lazily and idempotently before the first write.
        let exists = storage
            .list_namespaces()
            .map_err(|e| Error::StorageError(e.to_string()))?
            .iter()
            .any(|n| n == namespace);
        if !exists {
            storage
                .create_namespace(namespace)
                .map_err(|e| Error::StorageError(e.to_string()))?;
        }
        storage
            .store_key(&storage_key_id(&key.id), &bytes, namespace)
            .map_err(|e| Error::StorageError(e.to_string()))
    }

    /// Re-persist the current in-memory state of an existing key (no-op if no
    /// storage backend is configured).
    fn persist_existing(&self, namespace: &str, key_id: &KeyId) -> Result<()> {
        if self.storage.is_none() {
            return Ok(());
        }
        let key = self.store.get(namespace, key_id)?;
        self.persist_key(namespace, key.as_ref())
    }

    /// Remove a key from the durable backing store (no-op if none). Removing a
    /// key that was never persisted is not treated as an error.
    fn remove_persisted(&self, namespace: &str, key_id: &KeyId) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let mut storage = storage
            .lock()
            .map_err(|_| Error::StorageError("storage mutex poisoned".into()))?;
        let _ = storage.delete_key(&storage_key_id(key_id), namespace);
        Ok(())
    }
}

/// Map a key-manager [`KeyId`] (a UUID) to the storage layer's string-typed
/// `KeyId`, which is the durable lookup handle in the encrypted store.
fn storage_key_id(key_id: &KeyId) -> hsm_storage::KeyId {
    hsm_storage::KeyId::new(key_id.to_string())
}

impl Default for DefaultKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyManager for DefaultKeyManager {
    fn generate_key(&self, spec: KeySpec) -> Result<KeyId> {
        use hsm_crypto_engine::asymmetric::{bls, ecdsa, ed25519, rsa, secp256k1};

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
            KeyType::Secp256k1 => {
                let (priv_key, pub_key) = secp256k1::Secp256k1Engine::generate_keypair()
                    .map_err(|e| Error::KeyGenerationFailed(e.to_string()))?;
                (Some(priv_key), Some(pub_key))
            }
            KeyType::Bls12381 => {
                let (priv_key, pub_key) = bls::BlsEngine::generate_keypair()
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
            hd_info: None, // Non-HD keys don't have HD info
        };

        let key_id = key.id;

        // Persist to durable storage first so a generated key is always
        // recoverable on restart, then publish it to the in-memory working set.
        self.persist_key(&spec.namespace, &key)?;
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
        // generate_key persisted the new key at version 1; re-persist now that
        // its version/previous_version link has been set.
        self.persist_existing(namespace, &new_key_id)?;

        // Deactivate old key (update_state writes the new state through to storage)
        self.update_state(key_id, namespace, KeyState::Deactivated)?;

        Ok(new_key_id)
    }

    fn update_state(&self, key_id: &KeyId, namespace: &str, state: KeyState) -> Result<()> {
        self.store.update(namespace, key_id, |key| {
            key.state = state;
        })?;
        self.persist_existing(namespace, key_id)
    }

    fn delete_key(&self, key_id: &KeyId, namespace: &str) -> Result<()> {
        // For the in-memory key manager, deletion is the terminal "Destroyed"
        // transition: removing the entry from the store drops the last `Arc`
        // reference to the `Key`, which zeroizes the private key material via
        // its `Drop`/`ZeroizeOnDrop` impl. No metadata tombstone is retained,
        // so a subsequent `get_key` correctly returns `KeyNotFound`.
        //
        // We must NOT follow this with `update_state(.., Destroyed)`: the entry
        // is already gone, so that call would always fail with `KeyNotFound`
        // and error-log on every successful delete (the bug this replaces).
        let _deleted_key = self.store.delete(namespace, key_id)?;
        // Drop the durable copy too, so a destroyed key does not reappear on
        // restart. Removing a key that was never persisted is not an error.
        self.remove_persisted(namespace, key_id)?;
        Ok(())
    }

    fn increment_operations(&self, key_id: &KeyId, namespace: &str) -> Result<()> {
        self.store.update(namespace, key_id, |key| {
            key.increment_operations();
        })
    }

    fn import_key(&self, key_data: Vec<u8>, spec: KeySpec) -> Result<KeyId> {
        use hsm_crypto_engine::KeyMaterial;

        // Parse and validate key data based on key type
        let (private_material, public_material) = match spec.key_type {
            KeyType::Ed25519 => {
                // Ed25519 private key is 32 bytes
                if key_data.len() != 32 {
                    return Err(Error::InvalidKeyData(format!(
                        "Ed25519 private key must be 32 bytes, got {}",
                        key_data.len()
                    )));
                }

                // Derive public key from private key
                use ed25519_dalek::{SigningKey, VerifyingKey};
                let signing_key =
                    SigningKey::from_bytes(key_data.as_slice().try_into().map_err(|_| {
                        Error::InvalidKeyData("Invalid Ed25519 key bytes".to_string())
                    })?);
                let verifying_key: VerifyingKey = (&signing_key).into();

                (
                    Some(KeyMaterial::from_bytes(key_data)),
                    Some(verifying_key.to_bytes().to_vec()),
                )
            }

            KeyType::EcdsaP256 => {
                // ECDSA P-256 private key is typically 32 bytes (scalar)
                if key_data.len() != 32 {
                    return Err(Error::InvalidKeyData(format!(
                        "ECDSA P-256 private key must be 32 bytes, got {}",
                        key_data.len()
                    )));
                }

                // Derive public key from private key
                use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};

                let signing_key = P256SigningKey::from_slice(&key_data)
                    .map_err(|e| Error::InvalidKeyData(format!("Invalid P-256 key: {}", e)))?;
                let verifying_key: P256VerifyingKey = *signing_key.verifying_key();
                let public_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

                (Some(KeyMaterial::from_bytes(key_data)), Some(public_bytes))
            }

            KeyType::EcdsaP384 => {
                // ECDSA P-384 private key is typically 48 bytes (scalar)
                if key_data.len() != 48 {
                    return Err(Error::InvalidKeyData(format!(
                        "ECDSA P-384 private key must be 48 bytes, got {}",
                        key_data.len()
                    )));
                }

                // Derive public key from private key
                use p384::ecdsa::{SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey};

                let signing_key = P384SigningKey::from_slice(&key_data)
                    .map_err(|e| Error::InvalidKeyData(format!("Invalid P-384 key: {}", e)))?;
                let verifying_key: P384VerifyingKey = *signing_key.verifying_key();
                let public_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

                (Some(KeyMaterial::from_bytes(key_data)), Some(public_bytes))
            }

            KeyType::Secp256k1 => {
                // secp256k1 private key is 32 bytes
                if key_data.len() != 32 {
                    return Err(Error::InvalidKeyData(format!(
                        "secp256k1 private key must be 32 bytes, got {}",
                        key_data.len()
                    )));
                }

                // Derive public key from private key
                use k256::ecdsa::{SigningKey, VerifyingKey};

                let signing_key = SigningKey::from_slice(&key_data)
                    .map_err(|e| Error::InvalidKeyData(format!("Invalid secp256k1 key: {}", e)))?;
                let verifying_key: VerifyingKey = *signing_key.verifying_key();
                let public_bytes = verifying_key.to_sec1_bytes().to_vec();

                (Some(KeyMaterial::from_bytes(key_data)), Some(public_bytes))
            }

            KeyType::Bls12381 => {
                // BLS private key is 32 bytes
                if key_data.len() != 32 {
                    return Err(Error::InvalidKeyData(format!(
                        "BLS private key must be 32 bytes, got {}",
                        key_data.len()
                    )));
                }

                // Derive public key from private key
                use blst::min_pk::SecretKey;

                let secret_key = SecretKey::from_bytes(&key_data)
                    .map_err(|e| Error::InvalidKeyData(format!("Invalid BLS key: {:?}", e)))?;
                let public_key = secret_key.sk_to_pk();
                let public_bytes = public_key.compress().to_vec();

                (Some(KeyMaterial::from_bytes(key_data)), Some(public_bytes))
            }

            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
                // RSA private key is in PKCS#1 DER format
                // We'll store the raw bytes and derive the public key
                use rsa::{
                    pkcs1::DecodeRsaPrivateKey, pkcs1::EncodeRsaPublicKey, traits::PublicKeyParts,
                    RsaPrivateKey, RsaPublicKey,
                };

                let private_key = RsaPrivateKey::from_pkcs1_der(&key_data)
                    .map_err(|e| Error::InvalidKeyData(format!("Invalid RSA key: {}", e)))?;

                // Validate key size matches expected type
                let key_bits = private_key.size() * 8;
                let expected_bits = match spec.key_type {
                    KeyType::Rsa2048 => 2048,
                    KeyType::Rsa3072 => 3072,
                    KeyType::Rsa4096 => 4096,
                    _ => unreachable!(),
                };

                if key_bits != expected_bits {
                    return Err(Error::InvalidKeyData(format!(
                        "RSA key size mismatch: expected {} bits, got {}",
                        expected_bits, key_bits
                    )));
                }

                let public_key = RsaPublicKey::from(&private_key);
                let public_bytes = public_key
                    .to_pkcs1_der()
                    .map_err(|e| {
                        Error::InvalidKeyData(format!("Failed to encode public key: {}", e))
                    })?
                    .as_bytes()
                    .to_vec();

                (Some(KeyMaterial::from_bytes(key_data)), Some(public_bytes))
            }

            _ => {
                return Err(Error::UnsupportedKeyType(spec.key_type));
            }
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
            hd_info: None, // Imported keys don't have HD info (unless explicitly imported as HD)
        };

        let key_id = key.id;

        // Persist before publishing to the in-memory store (durable-first).
        self.persist_key(&spec.namespace, &key)?;
        self.store.insert(&spec.namespace, key)?;

        Ok(key_id)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tracing::level_filters::LevelFilter;
    use tracing::subscriber::DefaultGuard;
    use tracing::{Event, Level, Metadata, Subscriber};
    use tracing_subscriber::layer::{Context, SubscriberExt};
    use tracing_subscriber::registry::LookupSpan;
    use tracing_subscriber::Layer;

    /// A minimal tracing layer that counts ERROR-level events. Used to prove
    /// that `delete_key` no longer emits `tracing::error!` on the happy path.
    #[derive(Clone, Default)]
    struct ErrorCounter(Arc<AtomicUsize>);

    impl<S> Layer<S> for ErrorCounter
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn enabled(&self, metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
            *metadata.level() == Level::ERROR
        }

        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            if *event.metadata().level() == Level::ERROR {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn install_error_counter() -> (Arc<AtomicUsize>, DefaultGuard) {
        let counter = Arc::new(AtomicUsize::new(0));
        let layer = ErrorCounter(Arc::clone(&counter));
        let subscriber = tracing_subscriber::registry()
            .with(LevelFilter::ERROR)
            .with(layer);
        let guard = tracing::subscriber::set_default(subscriber);
        (counter, guard)
    }

    fn ed25519_spec(namespace: &str) -> KeySpec {
        KeySpec {
            key_type: KeyType::Ed25519,
            namespace: namespace.to_string(),
            policy: KeyUsagePolicy {
                can_sign: true,
                can_encrypt: false,
                can_derive: false,
                can_export: false,
                max_operations: None,
                expires_at: None,
            },
            labels: HashMap::new(),
        }
    }

    /// MEDIUM #20 regression: a successful `delete_key` must NOT emit any
    /// `tracing::error!` event.
    ///
    /// Before the fix, `delete_key` removed the entry and then called
    /// `update_state(.., Destroyed)`, which failed with `KeyNotFound` and
    /// logged an ERROR on EVERY delete. This test captures ERROR-level tracing
    /// events around the delete and asserts the count is zero — it FAILS on the
    /// old code (count == 1) and PASSES after the fix (count == 0).
    #[test]
    fn test_delete_key_does_not_error_log_on_happy_path() {
        let manager = DefaultKeyManager::new();
        let key_id = manager
            .generate_key(ed25519_spec("test"))
            .expect("generate");

        let (error_count, _guard) = install_error_counter();

        let result = manager.delete_key(&key_id, "test");

        let errors = error_count.load(Ordering::SeqCst);
        assert!(result.is_ok(), "delete_key should succeed");
        assert_eq!(
            errors, 0,
            "successful delete_key must not emit any tracing::error! events (got {})",
            errors
        );
    }

    /// The documented terminal lifecycle: after `delete_key`, the key is gone
    /// (zeroized + removed) and `get_key` returns `KeyNotFound`.
    #[test]
    fn test_delete_key_lifecycle_is_terminal() {
        let manager = DefaultKeyManager::new();
        let key_id = manager
            .generate_key(ed25519_spec("test"))
            .expect("generate");

        // Key exists and is Active before deletion.
        assert!(manager.get_key(&key_id, "test").is_ok());

        manager.delete_key(&key_id, "test").expect("delete");

        // After deletion the entry is removed; lookups fail with KeyNotFound.
        match manager.get_key(&key_id, "test") {
            Err(Error::KeyNotFound(missing)) => assert_eq!(missing, key_id),
            other => panic!("expected KeyNotFound after delete, got {:?}", other),
        }
    }

    /// Deleting a non-existent key still surfaces the error to the caller
    /// (the store's `KeyNotFound`), rather than swallowing it.
    #[test]
    fn test_delete_missing_key_returns_error() {
        let manager = DefaultKeyManager::new();
        let missing = KeyId::new();
        assert!(matches!(
            manager.delete_key(&missing, "test"),
            Err(Error::KeyNotFound(_))
        ));
    }

    /// A storage-backed manager persists generated keys so a fresh manager
    /// (simulating a process restart) recovers them via `hydrate`. This is the
    /// guarantee the in-memory-only server lacked: keys surviving a restart.
    #[test]
    fn test_keys_persist_across_restart() {
        use hsm_storage::{EncryptedFileStorage, MasterKey};

        let dir = tempfile::tempdir().expect("tempdir");
        let mk = || MasterKey::from_bytes(vec![0x11u8; 32]).expect("master key");

        // First boot: generate a key through the persistent manager.
        let key_id = {
            let storage =
                EncryptedFileStorage::new(dir.path().to_path_buf(), mk()).expect("storage");
            let manager = DefaultKeyManager::with_storage(Arc::new(Mutex::new(storage)));
            let key_id = manager
                .generate_key(ed25519_spec("prod"))
                .expect("generate");
            assert!(manager.get_metadata(&key_id, "prod").is_ok());
            key_id
        };

        // Second boot: a brand-new manager + fresh storage handle over the same
        // directory recovers the key after hydrate().
        let storage = EncryptedFileStorage::new(dir.path().to_path_buf(), mk()).expect("storage");
        let manager = DefaultKeyManager::with_storage(Arc::new(Mutex::new(storage)));
        let loaded = manager.hydrate().expect("hydrate");
        assert_eq!(loaded, 1, "exactly one persisted key should be recovered");
        assert!(
            manager.get_metadata(&key_id, "prod").is_ok(),
            "recovered key must be retrievable after restart"
        );
    }

    /// A key deleted before "restart" must not reappear after hydrate — the
    /// durable copy is removed on delete, not merely the in-memory entry.
    #[test]
    fn test_deleted_key_does_not_resurrect_after_restart() {
        use hsm_storage::{EncryptedFileStorage, MasterKey};

        let dir = tempfile::tempdir().expect("tempdir");
        let mk = || MasterKey::from_bytes(vec![0x22u8; 32]).expect("master key");

        let key_id = {
            let storage =
                EncryptedFileStorage::new(dir.path().to_path_buf(), mk()).expect("storage");
            let manager = DefaultKeyManager::with_storage(Arc::new(Mutex::new(storage)));
            let key_id = manager
                .generate_key(ed25519_spec("prod"))
                .expect("generate");
            manager.delete_key(&key_id, "prod").expect("delete");
            key_id
        };

        let storage = EncryptedFileStorage::new(dir.path().to_path_buf(), mk()).expect("storage");
        let manager = DefaultKeyManager::with_storage(Arc::new(Mutex::new(storage)));
        let loaded = manager.hydrate().expect("hydrate");
        assert_eq!(loaded, 0, "a deleted key must not be recovered on restart");
        assert!(manager.get_key(&key_id, "prod").is_err());
    }
}
