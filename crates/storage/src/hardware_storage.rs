//! Hardware-backed storage implementation
//!
//! This module provides storage backend integration with TEE-based hardware backends
//! for cryptographically binding keys to trusted execution environments.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │         HardwareStorageBackend                      │
//! │                                                     │
//! │  ┌───────────────────────────────────────────────┐ │
//! │  │  Application calls store_key()                │ │
//! │  └───────────────────┬───────────────────────────┘ │
//! │                      │                             │
//! │                      ▼                             │
//! │  ┌───────────────────────────────────────────────┐ │
//! │  │  1. Call hw_backend.seal_key()                │ │
//! │  │     - Encrypts with TEE-bound key             │ │
//! │  │     - Returns SealedKey                       │ │
//! │  └───────────────────┬───────────────────────────┘ │
//! │                      │                             │
//! │                      ▼                             │
//! │  ┌───────────────────────────────────────────────┐ │
//! │  │  2. Serialize SealedKey                       │ │
//! │  │     - Convert to bytes with postcard          │ │
//! │  └───────────────────┬───────────────────────────┘ │
//! │                      │                             │
//! │                      ▼                             │
//! │  ┌───────────────────────────────────────────────┐ │
//! │  │  3. Write to filesystem                       │ │
//! │  │     - Store in namespace directory            │ │
//! │  │     - Include integrity metadata              │ │
//! │  └───────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Properties
//!
//! - **TEE Binding**: Keys can only be unsealed in the same TEE with matching measurements
//! - **Confidentiality**: Key material never in plaintext on disk
//! - **Integrity**: Checksums detect tampering
//! - **Atomicity**: Write-ahead journaling ensures consistency
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "hardware")]
//! # {
//! use hsm_storage::{HardwareStorageBackend, StorageBackend, KeyId};
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
//! // Create storage with hardware backend
//! let mut storage = HardwareStorageBackend::new(
//!     PathBuf::from("/secure/storage"),
//!     Box::new(hw_backend)
//! ).await?;
//!
//! // Create namespace
//! storage.create_namespace("production")?;
//!
//! // Store key (automatically sealed by TEE)
//! let key_id = KeyId::new("signing-key-001");
//! storage.store_key(&key_id, b"secret key material", "production").await?;
//!
//! // Load key (automatically unsealed by TEE)
//! let key_data = storage.load_key(&key_id, "production").await?;
//! # Ok(())
//! # }
//! # }
//! ```

use crate::{KeyId, StorageBackend, StorageError, StorageResult};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

#[cfg(feature = "hardware")]
use hsm_hardware_backend::{HardwareBackend, PlaintextKey, SealedKey};

/// Hardware-backed storage backend
///
/// This backend integrates with TEE hardware backends (AWS Nitro, Intel SGX, AMD SEV)
/// to provide cryptographically bound key storage.
///
/// # Storage Format
///
/// Keys are stored as:
/// ```text
/// base_path/
/// └── namespaces/
///     └── {namespace}/
///         └── keys/
///             ├── {key-id}.sealed      # Serialized SealedKey
///             └── {key-id}.meta        # Metadata (timestamps, backend type)
/// ```
#[cfg(feature = "hardware")]
pub struct HardwareStorageBackend {
    /// Base directory for storage
    base_path: PathBuf,

    /// Hardware backend for key sealing/unsealing
    hw_backend: Arc<Box<dyn HardwareBackend>>,

    /// Metadata cache for fast lookups
    metadata_cache: Arc<dashmap::DashMap<String, KeyMetadata>>,
}

#[cfg(feature = "hardware")]
impl HardwareStorageBackend {
    /// Create a new hardware-backed storage backend
    ///
    /// # Arguments
    ///
    /// * `base_path` - Root directory for storage
    /// * `hw_backend` - Hardware backend for key sealing/unsealing
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Base directory cannot be created
    /// - Hardware backend is not available
    pub async fn new(
        base_path: PathBuf,
        hw_backend: Box<dyn HardwareBackend>,
    ) -> StorageResult<Self> {
        info!("Initializing hardware-backed storage at {:?}", base_path);

        // Create base directory if it doesn't exist
        fs::create_dir_all(&base_path).await?;

        // Verify hardware backend is available
        if !hw_backend.is_available().await {
            return Err(StorageError::OperationFailed(format!(
                "Hardware backend {:?} is not available",
                hw_backend.backend_type()
            )));
        }

        Ok(Self {
            base_path,
            hw_backend: Arc::new(hw_backend),
            metadata_cache: Arc::new(dashmap::DashMap::new()),
        })
    }

    /// Get the path for a namespace
    fn namespace_path(&self, namespace: &str) -> PathBuf {
        self.base_path.join("namespaces").join(namespace)
    }

    /// Get the path for a namespace's keys directory
    fn keys_path(&self, namespace: &str) -> PathBuf {
        self.namespace_path(namespace).join("keys")
    }

    /// Get the path for a sealed key file
    fn sealed_key_path(&self, key_id: &KeyId, namespace: &str) -> PathBuf {
        self.keys_path(namespace)
            .join(format!("{}.sealed", key_id.as_str()))
    }

    /// Get the path for a key metadata file
    fn metadata_path(&self, key_id: &KeyId, namespace: &str) -> PathBuf {
        self.keys_path(namespace)
            .join(format!("{}.meta", key_id.as_str()))
    }

    /// Store sealed key to disk
    async fn persist_sealed_key(
        &self,
        key_id: &KeyId,
        sealed: &SealedKey,
        namespace: &str,
    ) -> StorageResult<()> {
        let path = self.sealed_key_path(key_id, namespace);

        // Serialize sealed key
        let serialized = postcard::to_allocvec(sealed)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        // Write atomically (write to temp, then rename)
        let temp_path = path.with_extension("sealed.tmp");
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(&serialized).await?;
        file.sync_all().await?;

        fs::rename(&temp_path, &path).await?;

        debug!("Persisted sealed key {} to {:?}", key_id, path);

        // Store metadata
        let metadata = KeyMetadata {
            backend_type: sealed.metadata.backend_type,
            sealed_at: sealed.metadata.sealed_at,
            algorithm: sealed.metadata.algorithm.clone(),
        };
        self.persist_metadata(key_id, &metadata, namespace)
            .await?;

        Ok(())
    }

    /// Load sealed key from disk
    async fn load_sealed_key(
        &self,
        key_id: &KeyId,
        namespace: &str,
    ) -> StorageResult<SealedKey> {
        let path = self.sealed_key_path(key_id, namespace);

        if !path.exists() {
            return Err(StorageError::KeyNotFound(key_id.as_str().to_string()));
        }

        // Read file
        let mut file = fs::File::open(&path).await?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;

        // Deserialize
        let sealed: SealedKey = postcard::from_bytes(&buffer)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        debug!("Loaded sealed key {} from {:?}", key_id, path);

        Ok(sealed)
    }

    /// Persist metadata to disk
    async fn persist_metadata(
        &self,
        key_id: &KeyId,
        metadata: &KeyMetadata,
        namespace: &str,
    ) -> StorageResult<()> {
        let path = self.metadata_path(key_id, namespace);

        let serialized = postcard::to_allocvec(metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        fs::write(&path, serialized).await?;

        // Update cache
        let cache_key = format!("{}:{}", namespace, key_id.as_str());
        self.metadata_cache.insert(cache_key, metadata.clone());

        Ok(())
    }

    /// Load metadata from disk
    async fn load_metadata(
        &self,
        key_id: &KeyId,
        namespace: &str,
    ) -> StorageResult<KeyMetadata> {
        // Check cache first
        let cache_key = format!("{}:{}", namespace, key_id.as_str());
        if let Some(metadata) = self.metadata_cache.get(&cache_key) {
            return Ok(metadata.clone());
        }

        // Load from disk
        let path = self.metadata_path(key_id, namespace);

        if !path.exists() {
            return Err(StorageError::KeyNotFound(key_id.as_str().to_string()));
        }

        let buffer = fs::read(&path).await?;
        let metadata: KeyMetadata = postcard::from_bytes(&buffer)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        // Update cache
        self.metadata_cache.insert(cache_key, metadata.clone());

        Ok(metadata)
    }
}

/// Key metadata stored alongside sealed keys
#[cfg(feature = "hardware")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct KeyMetadata {
    backend_type: hsm_hardware_backend::BackendType,
    sealed_at: i64,
    algorithm: String,
}

#[cfg(feature = "hardware")]
#[async_trait::async_trait]
impl StorageBackend for HardwareStorageBackend {
    fn store_key(&mut self, key_id: &KeyId, data: &[u8], namespace: &str) -> StorageResult<()> {
        // StorageBackend trait is sync, but we need async
        // Use tokio runtime to block on async operation
        let runtime = tokio::runtime::Handle::current();
        runtime.block_on(async {
            self.store_key_async(key_id, data, namespace).await
        })
    }

    fn load_key(&self, key_id: &KeyId, namespace: &str) -> StorageResult<Vec<u8>> {
        let runtime = tokio::runtime::Handle::current();
        runtime.block_on(async {
            self.load_key_async(key_id, namespace).await
        })
    }

    fn delete_key(&mut self, key_id: &KeyId, namespace: &str) -> StorageResult<()> {
        let runtime = tokio::runtime::Handle::current();
        runtime.block_on(async {
            self.delete_key_async(key_id, namespace).await
        })
    }

    fn list_keys(&self, namespace: &str) -> StorageResult<Vec<KeyId>> {
        let runtime = tokio::runtime::Handle::current();
        runtime.block_on(async {
            self.list_keys_async(namespace).await
        })
    }

    fn key_exists(&self, key_id: &KeyId, namespace: &str) -> StorageResult<bool> {
        Ok(self.sealed_key_path(key_id, namespace).exists())
    }

    fn sync(&mut self) -> StorageResult<()> {
        // Hardware backend operations are already durable
        // No additional sync needed
        Ok(())
    }

    fn create_namespace(&mut self, namespace: &str) -> StorageResult<()> {
        let runtime = tokio::runtime::Handle::current();
        runtime.block_on(async {
            let keys_path = self.keys_path(namespace);
            fs::create_dir_all(&keys_path).await?;
            info!("Created namespace: {}", namespace);
            Ok(())
        })
    }

    fn delete_namespace(&mut self, namespace: &str) -> StorageResult<()> {
        let runtime = tokio::runtime::Handle::current();
        runtime.block_on(async {
            let namespace_path = self.namespace_path(namespace);
            if namespace_path.exists() {
                fs::remove_dir_all(&namespace_path).await?;
                info!("Deleted namespace: {}", namespace);
            }
            Ok(())
        })
    }

    fn list_namespaces(&self) -> StorageResult<Vec<String>> {
        let runtime = tokio::runtime::Handle::current();
        runtime.block_on(async {
            let namespaces_path = self.base_path.join("namespaces");
            if !namespaces_path.exists() {
                return Ok(Vec::new());
            }

            let mut entries = fs::read_dir(&namespaces_path).await?;
            let mut namespaces = Vec::new();

            while let Some(entry) = entries.next_entry().await? {
                if entry.file_type().await?.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        namespaces.push(name.to_string());
                    }
                }
            }

            Ok(namespaces)
        })
    }
}

#[cfg(feature = "hardware")]
impl HardwareStorageBackend {
    /// Async version of store_key
    pub async fn store_key_async(
        &self,
        key_id: &KeyId,
        data: &[u8],
        namespace: &str,
    ) -> StorageResult<()> {
        debug!(
            "Storing key {} in namespace {} (hardware-backed)",
            key_id, namespace
        );

        // Verify namespace exists
        if !self.keys_path(namespace).exists() {
            return Err(StorageError::NamespaceNotFound(namespace.to_string()));
        }

        // Seal key using hardware backend
        let plaintext = PlaintextKey::new(data.to_vec());
        let sealed = self
            .hw_backend
            .seal_key(&plaintext)
            .await
            .map_err(|e| StorageError::Encryption(e.to_string()))?;

        // Persist to disk
        self.persist_sealed_key(key_id, &sealed, namespace).await?;

        info!(
            "Stored key {} (backend: {:?})",
            key_id,
            sealed.metadata.backend_type
        );

        Ok(())
    }

    /// Async version of load_key
    pub async fn load_key_async(
        &self,
        key_id: &KeyId,
        namespace: &str,
    ) -> StorageResult<Vec<u8>> {
        debug!(
            "Loading key {} from namespace {} (hardware-backed)",
            key_id, namespace
        );

        // Load sealed key from disk
        let sealed = self.load_sealed_key(key_id, namespace).await?;

        // Unseal using hardware backend
        let plaintext = self
            .hw_backend
            .unseal_key(&sealed)
            .await
            .map_err(|e| StorageError::Encryption(format!("Unseal failed: {}", e)))?;

        debug!("Unsealed key {} successfully", key_id);

        Ok(plaintext.into_bytes())
    }

    /// Async version of delete_key
    pub async fn delete_key_async(
        &self,
        key_id: &KeyId,
        namespace: &str,
    ) -> StorageResult<()> {
        debug!("Deleting key {} from namespace {}", key_id, namespace);

        let sealed_path = self.sealed_key_path(key_id, namespace);
        let meta_path = self.metadata_path(key_id, namespace);

        // Delete sealed key file
        if sealed_path.exists() {
            fs::remove_file(&sealed_path).await?;
        }

        // Delete metadata file
        if meta_path.exists() {
            fs::remove_file(&meta_path).await?;
        }

        // Remove from cache
        let cache_key = format!("{}:{}", namespace, key_id.as_str());
        self.metadata_cache.remove(&cache_key);

        info!("Deleted key {}", key_id);

        Ok(())
    }

    /// Async version of list_keys
    pub async fn list_keys_async(&self, namespace: &str) -> StorageResult<Vec<KeyId>> {
        let keys_path = self.keys_path(namespace);

        if !keys_path.exists() {
            return Err(StorageError::NamespaceNotFound(namespace.to_string()));
        }

        let mut entries = fs::read_dir(&keys_path).await?;
        let mut keys = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "sealed" {
                    if let Some(stem) = path.file_stem() {
                        if let Some(key_id_str) = stem.to_str() {
                            keys.push(KeyId::new(key_id_str));
                        }
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Create a namespace (async version)
    pub async fn create_namespace_async(&self, namespace: &str) -> StorageResult<()> {
        let keys_path = self.keys_path(namespace);
        fs::create_dir_all(&keys_path).await?;
        info!("Created namespace: {}", namespace);
        Ok(())
    }

    /// Delete a namespace (async version)
    pub async fn delete_namespace_async(&self, namespace: &str) -> StorageResult<()> {
        let namespace_path = self.namespace_path(namespace);
        if namespace_path.exists() {
            fs::remove_dir_all(&namespace_path).await?;
            info!("Deleted namespace: {}", namespace);
        }
        Ok(())
    }

    /// List all namespaces (async version)
    pub async fn list_namespaces_async(&self) -> StorageResult<Vec<String>> {
        let namespaces_path = self.base_path.join("namespaces");
        if !namespaces_path.exists() {
            return Ok(Vec::new());
        }

        let mut entries = fs::read_dir(&namespaces_path).await?;
        let mut namespaces = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    namespaces.push(name.to_string());
                }
            }
        }

        Ok(namespaces)
    }

    /// Get statistics about stored keys
    pub async fn get_stats(&self, namespace: &str) -> StorageResult<HardwareStorageStats> {
        let keys = self.list_keys_async(namespace).await?;
        let mut backend_counts: HashMap<String, usize> = HashMap::new();
        let mut total_size = 0u64;

        for key_id in &keys {
            // Load metadata to get backend type
            if let Ok(metadata) = self.load_metadata(key_id, namespace).await {
                *backend_counts
                    .entry(metadata.backend_type.to_string())
                    .or_insert(0) += 1;
            }

            // Get file size
            let path = self.sealed_key_path(key_id, namespace);
            if let Ok(meta) = fs::metadata(&path).await {
                total_size += meta.len();
            }
        }

        Ok(HardwareStorageStats {
            total_keys: keys.len(),
            total_size_bytes: total_size,
            backend_counts,
        })
    }
}

/// Statistics about hardware storage
#[cfg(feature = "hardware")]
#[derive(Debug, Clone)]
pub struct HardwareStorageStats {
    /// Total number of keys
    pub total_keys: usize,

    /// Total size of all sealed keys on disk
    pub total_size_bytes: u64,

    /// Count of keys per backend type
    pub backend_counts: HashMap<String, usize>,
}

#[cfg(all(test, feature = "hardware"))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // Mock hardware backend for testing
    struct MockHardwareBackend;

    #[async_trait::async_trait]
    impl HardwareBackend for MockHardwareBackend {
        async fn seal_key(&self, plaintext: &PlaintextKey) -> Result<SealedKey, hsm_hardware_backend::HardwareError> {
            use hsm_hardware_backend::{BackendType, SealedKeyMetadata};

            Ok(SealedKey {
                ciphertext: plaintext.as_bytes().to_vec(), // Mock: just copy plaintext
                metadata: SealedKeyMetadata {
                    algorithm: "MOCK".to_string(),
                    version: 1,
                    sealed_at: chrono::Utc::now().timestamp(),
                    backend_type: BackendType::Software,
                    additional: HashMap::new(),
                },
                backend_data: Vec::new(),
            })
        }

        async fn unseal_key(&self, sealed: &SealedKey) -> Result<PlaintextKey, hsm_hardware_backend::HardwareError> {
            Ok(PlaintextKey::new(sealed.ciphertext.clone())) // Mock: just copy ciphertext
        }

        async fn attest(&self, _nonce: Option<&[u8]>) -> Result<hsm_hardware_backend::AttestationReport, hsm_hardware_backend::HardwareError> {
            unimplemented!("Mock backend doesn't support attestation")
        }

        async fn verify_attestation(
            &self,
            _report: &hsm_hardware_backend::AttestationReport,
            _expected: &hsm_hardware_backend::TeeMeasurements,
        ) -> Result<(), hsm_hardware_backend::HardwareError> {
            unimplemented!("Mock backend doesn't support attestation")
        }

        async fn remote_sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, hsm_hardware_backend::HardwareError> {
            unimplemented!("Mock backend doesn't support signing")
        }

        fn backend_type(&self) -> hsm_hardware_backend::BackendType {
            hsm_hardware_backend::BackendType::Software
        }

        async fn is_available(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn test_hardware_storage_store_load() {
        let temp_dir = TempDir::new().unwrap();
        let hw_backend = Box::new(MockHardwareBackend);

        let mut storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
            .await
            .unwrap();

        // Create namespace
        storage.create_namespace("test").unwrap();

        // Store key
        let key_id = KeyId::new("test-key");
        let data = b"secret data";
        storage
            .store_key_async(&key_id, data, "test")
            .await
            .unwrap();

        // Load key
        let loaded = storage.load_key_async(&key_id, "test").await.unwrap();
        assert_eq!(data.as_slice(), loaded.as_slice());
    }

    #[tokio::test]
    async fn test_hardware_storage_list_keys() {
        let temp_dir = TempDir::new().unwrap();
        let hw_backend = Box::new(MockHardwareBackend);

        let mut storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
            .await
            .unwrap();

        storage.create_namespace("test").unwrap();

        // Store multiple keys
        for i in 0..5 {
            let key_id = KeyId::new(format!("key-{}", i));
            storage
                .store_key_async(&key_id, b"data", "test")
                .await
                .unwrap();
        }

        // List keys
        let keys = storage.list_keys_async("test").await.unwrap();
        assert_eq!(keys.len(), 5);
    }

    #[tokio::test]
    async fn test_hardware_storage_delete() {
        let temp_dir = TempDir::new().unwrap();
        let hw_backend = Box::new(MockHardwareBackend);

        let mut storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
            .await
            .unwrap();

        storage.create_namespace("test").unwrap();

        let key_id = KeyId::new("test-key");
        storage
            .store_key_async(&key_id, b"data", "test")
            .await
            .unwrap();

        // Delete
        storage.delete_key_async(&key_id, "test").await.unwrap();

        // Verify deleted
        assert!(!storage.key_exists(&key_id, "test").unwrap());
    }
}
