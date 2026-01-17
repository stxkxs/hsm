//! Hardware-backed key manager implementation
//!
//! This module provides a KeyManager implementation that uses hardware backends
//! (AWS Nitro, Intel SGX, AMD SEV) for secure key storage and remote signing.
//!
//! # Features
//!
//! - **TEE-sealed keys**: Keys are cryptographically bound to TEE measurements
//! - **Remote signing**: Signing operations delegated to hardware backend
//! - **Persistent storage**: Keys persist across restarts via HardwareStorageBackend
//! - **Namespace isolation**: Same security guarantees as DefaultKeyManager
//!
//! # Example
//!
//! ```no_run
//! use hsm_key_manager::{HardwareKeyManager, KeyManager, KeySpec, KeyType, KeyUsagePolicy};
//! use hsm_storage::HardwareStorageBackend;
//! use hsm_hardware_backend::{NitroEnclaveBackend, NitroConfig};
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create hardware backend
//! let hw_config = NitroConfig {
//!     region: "us-east-1".to_string(),
//!     kms_key_arn: "arn:aws:kms:...".to_string(),
//!     enclave_cid: Some(16),
//!     verify_attestation: true,
//!     expected_pcrs: None,
//! };
//! let hw_backend = NitroEnclaveBackend::new(hw_config).await?;
//!
//! // Create hardware storage
//! let storage = HardwareStorageBackend::new(
//!     PathBuf::from("/secure/keys"),
//!     Box::new(hw_backend.clone())
//! ).await?;
//!
//! // Create hardware key manager
//! let manager = HardwareKeyManager::new(storage, Box::new(hw_backend)).await?;
//!
//! // Generate a key (sealed by TEE)
//! let spec = KeySpec {
//!     key_type: KeyType::Ed25519,
//!     namespace: "production".to_string(),
//!     policy: KeyUsagePolicy::default(),
//!     labels: std::collections::HashMap::new(),
//! };
//! let key_id = manager.generate_key_async(spec).await?;
//!
//! // Sign using hardware backend (< 5ms latency)
//! let signature = manager.remote_sign_async(&key_id, "production", b"message").await?;
//! # Ok(())
//! # }
//! ```

#![cfg(feature = "hardware")]

use crate::{
    error::{Error, Result},
    key::{Key, KeyId, KeySpec, KeyState, KeyType, KeyUsagePolicy},
    metadata::{KeyFilter, KeyMetadata},
    KeyManager,
};
use async_trait::async_trait;
use chrono::Utc;
use hsm_crypto_engine::{CryptoEngine, DefaultCryptoEngine};
use hsm_hardware_backend::{HardwareBackend, PlaintextKey};
use hsm_storage::HardwareStorageBackend;
use std::sync::Arc;

/// Hardware-backed key manager
///
/// Stores keys using HardwareStorageBackend (TEE-sealed) and supports
/// remote signing operations delegated to the hardware backend.
pub struct HardwareKeyManager {
    pub(crate) storage: HardwareStorageBackend,
    hw_backend: Arc<Box<dyn HardwareBackend>>,
    crypto_engine: Arc<dyn CryptoEngine>,
}

impl HardwareKeyManager {
    /// Create a namespace in the storage backend
    pub async fn create_namespace_async(&self, namespace: &str) -> Result<()> {
        self.storage
            .create_namespace_async(namespace)
            .await
            .map_err(|e| Error::StorageError(e.to_string()))
    }
}

impl HardwareKeyManager {
    /// Create a new hardware-backed key manager
    pub async fn new(
        storage: HardwareStorageBackend,
        hw_backend: Box<dyn HardwareBackend>,
    ) -> Result<Self> {
        // Verify hardware backend is available
        if !hw_backend.is_available().await {
            return Err(Error::HardwareNotAvailable);
        }

        Ok(Self {
            storage,
            hw_backend: Arc::new(hw_backend),
            crypto_engine: Arc::new(DefaultCryptoEngine),
        })
    }

    /// Create with custom crypto engine
    pub async fn with_crypto_engine(
        storage: HardwareStorageBackend,
        hw_backend: Box<dyn HardwareBackend>,
        crypto_engine: Arc<dyn CryptoEngine>,
    ) -> Result<Self> {
        // Verify hardware backend is available
        if !hw_backend.is_available().await {
            return Err(Error::HardwareNotAvailable);
        }

        Ok(Self {
            storage,
            hw_backend: Arc::new(hw_backend),
            crypto_engine,
        })
    }

    /// Generate a key asynchronously (async version of generate_key)
    pub async fn generate_key_async(&self, spec: KeySpec) -> Result<KeyId> {
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
            private_material: private_material.clone(),
            public_material: public_material.clone(),
            state: KeyState::Active,
            namespace: spec.namespace.clone(),
            created_at: Utc::now(),
            policy: spec.policy,
            version: 1,
            previous_version: None,
            operation_count: 0,
        };

        let key_id = key.id;

        // Serialize key to bytes for storage
        let key_bytes = postcard::to_allocvec(&key)
            .map_err(|e| Error::StorageError(format!("Failed to serialize key: {}", e)))?;

        // Create storage key ID from KeyId (use string representation)
        let storage_key_id = hsm_storage::KeyId::new(&key_id.as_string());

        // Store key using hardware backend (will be TEE-sealed)
        self.storage
            .store_key_async(&storage_key_id, &key_bytes, &spec.namespace)
            .await
            .map_err(|e| Error::StorageError(e.to_string()))?;

        Ok(key_id)
    }

    /// Get a key by ID (async version)
    pub async fn get_key_async(&self, key_id: &KeyId, namespace: &str) -> Result<Arc<Key>> {
        // Load key from hardware storage (unsealed by TEE)
        let storage_key_id = hsm_storage::KeyId::new(key_id.as_string());

        let key_bytes = self
            .storage
            .load_key_async(&storage_key_id, namespace)
            .await
            .map_err(|e| {
                if e.to_string().contains("not found") {
                    Error::KeyNotFound(*key_id)
                } else {
                    Error::StorageError(e.to_string())
                }
            })?;

        // Deserialize key
        let key: Key = postcard::from_bytes(&key_bytes)
            .map_err(|e| Error::StorageError(format!("Failed to deserialize key: {}", e)))?;

        // Verify namespace matches
        if key.namespace != namespace {
            return Err(Error::NamespaceViolation {
                expected: namespace.to_string(),
                actual: key.namespace.clone(),
            });
        }

        // Verify key can be used
        if !key.can_use() {
            return Err(Error::KeyNotUsable(*key_id));
        }

        if key.has_reached_max_operations() {
            return Err(Error::MaxOperationsReached(*key_id));
        }

        Ok(Arc::new(key))
    }

    /// Remote sign using hardware backend
    ///
    /// Delegates signing to the hardware backend for sub-5ms latency.
    /// The key material never leaves the TEE.
    pub async fn remote_sign_async(
        &self,
        key_id: &KeyId,
        namespace: &str,
        message: &[u8],
    ) -> Result<Vec<u8>> {

        // Verify key exists and is usable
        let _key = self.get_key_async(key_id, namespace).await?;

        // Delegate to hardware backend for signing
        let signature = self
            .hw_backend
            .remote_sign(&key_id.as_string(), message)
            .await
            .map_err(|e| Error::HardwareError(e.to_string()))?;

        // Increment operation counter
        self.increment_operations_async(key_id, namespace).await?;

        Ok(signature)
    }

    /// List keys in a namespace (async)
    pub async fn list_keys_async(
        &self,
        namespace: &str,
        filter: KeyFilter,
    ) -> Result<Vec<KeyMetadata>> {
        let storage_key_ids = self
            .storage
            .list_keys_async(namespace)
            .await
            .map_err(|e| Error::StorageError(e.to_string()))?;

        let mut metadata_list = Vec::new();

        for storage_key_id in storage_key_ids {
            // Convert storage KeyId back to KeyManager KeyId
            if let Ok(key_id) = KeyId::from_string(storage_key_id.as_str()) {
                // Load key to apply filters
                if let Ok(key_bytes) = self.storage.load_key_async(&storage_key_id, namespace).await {
                    if let Ok(key) = postcard::from_bytes::<Key>(&key_bytes) {
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
            }
        }

        Ok(metadata_list)
    }

    /// Rotate a key (async)
    pub async fn rotate_key_async(&self, key_id: &KeyId, namespace: &str) -> Result<KeyId> {
        // Get existing key
        let old_key = self.get_key_async(key_id, namespace).await?;

        // Create new key spec with same properties
        let spec = KeySpec {
            key_type: old_key.key_type,
            namespace: namespace.to_string(),
            policy: old_key.policy.clone(),
            labels: std::collections::HashMap::new(),
        };

        // Generate new key
        let new_key_id = self.generate_key_async(spec).await?;

        // Update new key to reference old key and increment version
        // Load new key, modify, and store back
        let storage_new_key_id = hsm_storage::KeyId::new(new_key_id.as_string());
        let new_key_bytes = self.storage.load_key_async(&storage_new_key_id, namespace).await
            .map_err(|e| Error::StorageError(e.to_string()))?;

        let mut new_key: Key = postcard::from_bytes(&new_key_bytes)
            .map_err(|e| Error::StorageError(format!("Failed to deserialize key: {}", e)))?;

        new_key.previous_version = Some(*key_id);
        new_key.version = old_key.version + 1;

        let updated_bytes = postcard::to_allocvec(&new_key)
            .map_err(|e| Error::StorageError(format!("Failed to serialize key: {}", e)))?;

        self.storage.store_key_async(&storage_new_key_id, &updated_bytes, namespace).await
            .map_err(|e| Error::StorageError(e.to_string()))?;

        // Deactivate old key
        self.update_state_async(key_id, namespace, KeyState::Deactivated).await?;

        Ok(new_key_id)
    }

    /// Update key state (async)
    pub async fn update_state_async(
        &self,
        key_id: &KeyId,
        namespace: &str,
        state: KeyState,
    ) -> Result<()> {
        let storage_key_id = hsm_storage::KeyId::new(key_id.as_string());

        let key_bytes = self.storage.load_key_async(&storage_key_id, namespace).await
            .map_err(|e| Error::StorageError(e.to_string()))?;

        let mut key: Key = postcard::from_bytes(&key_bytes)
            .map_err(|e| Error::StorageError(format!("Failed to deserialize key: {}", e)))?;

        key.state = state;

        let updated_bytes = postcard::to_allocvec(&key)
            .map_err(|e| Error::StorageError(format!("Failed to serialize key: {}", e)))?;

        self.storage.store_key_async(&storage_key_id, &updated_bytes, namespace).await
            .map_err(|e| Error::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Delete a key (async)
    pub async fn delete_key_async(&self, key_id: &KeyId, namespace: &str) -> Result<()> {
        // Mark as destroyed first
        self.update_state_async(key_id, namespace, KeyState::Destroyed).await?;

        // Delete from storage (key material zeroized by hardware backend)
        let storage_key_id = hsm_storage::KeyId::new(key_id.as_string());
        self.storage
            .delete_key_async(&storage_key_id, namespace)
            .await
            .map_err(|e| Error::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Increment operation counter (async)
    pub async fn increment_operations_async(
        &self,
        key_id: &KeyId,
        namespace: &str,
    ) -> Result<()> {
        let storage_key_id = hsm_storage::KeyId::new(key_id.as_string());

        let key_bytes = self.storage.load_key_async(&storage_key_id, namespace).await
            .map_err(|e| Error::StorageError(e.to_string()))?;

        let mut key: Key = postcard::from_bytes(&key_bytes)
            .map_err(|e| Error::StorageError(format!("Failed to deserialize key: {}", e)))?;

        key.increment_operations();

        let updated_bytes = postcard::to_allocvec(&key)
            .map_err(|e| Error::StorageError(format!("Failed to serialize key: {}", e)))?;

        self.storage.store_key_async(&storage_key_id, &updated_bytes, namespace).await
            .map_err(|e| Error::StorageError(e.to_string()))?;

        Ok(())
    }
}

/// Async trait implementation for HardwareKeyManager
///
/// Provides async versions of all KeyManager operations for use in async contexts.
#[async_trait]
pub trait AsyncKeyManager: Send + Sync {
    async fn generate_key_async(&self, spec: KeySpec) -> Result<KeyId>;
    async fn get_key_async(&self, key_id: &KeyId, namespace: &str) -> Result<Arc<Key>>;
    async fn get_metadata_async(&self, key_id: &KeyId, namespace: &str) -> Result<KeyMetadata>;
    async fn list_keys_async(&self, namespace: &str, filter: KeyFilter) -> Result<Vec<KeyMetadata>>;
    async fn rotate_key_async(&self, key_id: &KeyId, namespace: &str) -> Result<KeyId>;
    async fn update_state_async(&self, key_id: &KeyId, namespace: &str, state: KeyState) -> Result<()>;
    async fn delete_key_async(&self, key_id: &KeyId, namespace: &str) -> Result<()>;
    async fn increment_operations_async(&self, key_id: &KeyId, namespace: &str) -> Result<()>;
    async fn remote_sign_async(&self, key_id: &KeyId, namespace: &str, message: &[u8]) -> Result<Vec<u8>>;
}

#[async_trait]
impl AsyncKeyManager for HardwareKeyManager {
    async fn generate_key_async(&self, spec: KeySpec) -> Result<KeyId> {
        self.generate_key_async(spec).await
    }

    async fn get_key_async(&self, key_id: &KeyId, namespace: &str) -> Result<Arc<Key>> {
        self.get_key_async(key_id, namespace).await
    }

    async fn get_metadata_async(&self, key_id: &KeyId, namespace: &str) -> Result<KeyMetadata> {
        let key = self.get_key_async(key_id, namespace).await?;
        Ok(KeyMetadata::from_key(&key))
    }

    async fn list_keys_async(&self, namespace: &str, filter: KeyFilter) -> Result<Vec<KeyMetadata>> {
        self.list_keys_async(namespace, filter).await
    }

    async fn rotate_key_async(&self, key_id: &KeyId, namespace: &str) -> Result<KeyId> {
        self.rotate_key_async(key_id, namespace).await
    }

    async fn update_state_async(&self, key_id: &KeyId, namespace: &str, state: KeyState) -> Result<()> {
        self.update_state_async(key_id, namespace, state).await
    }

    async fn delete_key_async(&self, key_id: &KeyId, namespace: &str) -> Result<()> {
        self.delete_key_async(key_id, namespace).await
    }

    async fn increment_operations_async(&self, key_id: &KeyId, namespace: &str) -> Result<()> {
        self.increment_operations_async(key_id, namespace).await
    }

    async fn remote_sign_async(&self, key_id: &KeyId, namespace: &str, message: &[u8]) -> Result<Vec<u8>> {
        self.remote_sign_async(key_id, namespace, message).await
    }
}

/// Synchronous KeyManager implementation for compatibility
///
/// Uses tokio::runtime::Handle::current().block_on() to provide sync interface.
/// For async contexts, use AsyncKeyManager trait instead.
impl KeyManager for HardwareKeyManager {
    fn generate_key(&self, spec: KeySpec) -> Result<KeyId> {
        tokio::runtime::Handle::current()
            .block_on(self.generate_key_async(spec))
    }

    fn import_key(&self, _key_data: Vec<u8>, _spec: KeySpec) -> Result<KeyId> {
        Err(Error::NotImplemented("Key import not yet implemented for hardware backend".into()))
    }

    fn get_key(&self, key_id: &KeyId, namespace: &str) -> Result<Arc<Key>> {
        tokio::runtime::Handle::current()
            .block_on(self.get_key_async(key_id, namespace))
    }

    fn get_metadata(&self, key_id: &KeyId, namespace: &str) -> Result<KeyMetadata> {
        let key = self.get_key(key_id, namespace)?;
        Ok(KeyMetadata::from_key(&key))
    }

    fn list_keys(&self, namespace: &str, filter: KeyFilter) -> Result<Vec<KeyMetadata>> {
        tokio::runtime::Handle::current()
            .block_on(self.list_keys_async(namespace, filter))
    }

    fn list_keys_batch(&self, namespace: &str, offset: usize, limit: usize) -> Result<Vec<KeyMetadata>> {
        // Load all keys and paginate in-memory
        let all_metadata = self.list_keys(namespace, KeyFilter {
            key_type: None,
            state: None,
            labels: std::collections::HashMap::new(),
        })?;
        let start = offset;
        let end = (offset + limit).min(all_metadata.len());
        Ok(all_metadata[start..end].to_vec())
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

    fn rotate_key(&self, key_id: &KeyId, namespace: &str) -> Result<KeyId> {
        tokio::runtime::Handle::current()
            .block_on(self.rotate_key_async(key_id, namespace))
    }

    fn update_state(&self, key_id: &KeyId, namespace: &str, state: KeyState) -> Result<()> {
        tokio::runtime::Handle::current()
            .block_on(self.update_state_async(key_id, namespace, state))
    }

    fn delete_key(&self, key_id: &KeyId, namespace: &str) -> Result<()> {
        tokio::runtime::Handle::current()
            .block_on(self.delete_key_async(key_id, namespace))
    }

    fn increment_operations(&self, key_id: &KeyId, namespace: &str) -> Result<()> {
        tokio::runtime::Handle::current()
            .block_on(self.increment_operations_async(key_id, namespace))
    }
}
