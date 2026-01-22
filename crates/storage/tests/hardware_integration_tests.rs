//! Integration tests for hardware-backed storage
//!
//! These tests verify that the hardware storage backend correctly integrates with
//! TEE backends for key sealing and unsealing.

#![cfg(feature = "hardware")]

use hsm_hardware_backend::{
    AttestationReport, BackendType, HardwareBackend, HardwareError, PlaintextKey, SealedKey,
    SealedKeyMetadata, TeeMeasurements,
};
use hsm_storage::{HardwareStorageBackend, KeyId, StorageBackend};
use std::collections::HashMap;
use tempfile::TempDir;

// Mock hardware backend for integration testing
struct MockHardwareBackend {
    fail_seal: bool,
    fail_unseal: bool,
}

impl MockHardwareBackend {
    fn new() -> Self {
        Self {
            fail_seal: false,
            fail_unseal: false,
        }
    }

    fn with_seal_failure() -> Self {
        Self {
            fail_seal: true,
            fail_unseal: false,
        }
    }
}

#[async_trait::async_trait]
impl HardwareBackend for MockHardwareBackend {
    async fn seal_key(&self, plaintext: &PlaintextKey) -> Result<SealedKey, HardwareError> {
        if self.fail_seal {
            return Err(HardwareError::SealingFailed("Mocked failure".to_string()));
        }

        Ok(SealedKey {
            ciphertext: plaintext.as_bytes().to_vec(),
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

    async fn unseal_key(&self, sealed: &SealedKey) -> Result<PlaintextKey, HardwareError> {
        if self.fail_unseal {
            return Err(HardwareError::UnsealingFailed("Mocked failure".to_string()));
        }

        Ok(PlaintextKey::new(sealed.ciphertext.clone()))
    }

    async fn attest(&self, _nonce: Option<&[u8]>) -> Result<AttestationReport, HardwareError> {
        unimplemented!("Mock backend doesn't support attestation")
    }

    async fn verify_attestation(
        &self,
        _report: &AttestationReport,
        _expected: &TeeMeasurements,
    ) -> Result<(), HardwareError> {
        unimplemented!("Mock backend doesn't support attestation")
    }

    async fn remote_sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, HardwareError> {
        unimplemented!("Mock backend doesn't support signing")
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Software
    }

    async fn is_available(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn test_hardware_storage_basic_operations() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let mut storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
        .await
        .unwrap();

    // Create namespace (sync operation is fine)
    storage.create_namespace_async("test").await.unwrap();

    // Store key using async API
    let key_id = KeyId::new("test-key-1");
    let data = b"secret key material";
    storage
        .store_key_async(&key_id, data, "test")
        .await
        .unwrap();

    // Verify key exists (sync check is fine)
    assert!(storage.key_exists(&key_id, "test").unwrap());

    // Load key using async API
    let loaded = storage.load_key_async(&key_id, "test").await.unwrap();
    assert_eq!(data.as_slice(), loaded.as_slice());

    // Delete key using async API
    storage.delete_key_async(&key_id, "test").await.unwrap();
    assert!(!storage.key_exists(&key_id, "test").unwrap());
}

#[tokio::test]
async fn test_hardware_storage_multiple_keys() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let mut storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
        .await
        .unwrap();

    storage.create_namespace_async("test").await.unwrap();

    // Store multiple keys using async API
    let count = 10;
    for i in 0..count {
        let key_id = KeyId::new(format!("key-{}", i));
        let data = format!("data-{}", i);
        storage
            .store_key_async(&key_id, data.as_bytes(), "test")
            .await
            .unwrap();
    }

    // List keys using async API
    let keys = storage.list_keys_async("test").await.unwrap();
    assert_eq!(keys.len(), count);

    // Load each key and verify using async API
    for i in 0..count {
        let key_id = KeyId::new(format!("key-{}", i));
        let loaded = storage.load_key_async(&key_id, "test").await.unwrap();
        let expected = format!("data-{}", i);
        assert_eq!(expected.as_bytes(), loaded.as_slice());
    }
}

#[tokio::test]
async fn test_hardware_storage_namespace_isolation() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let mut storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
        .await
        .unwrap();

    storage.create_namespace_async("namespace-a").await.unwrap();
    storage.create_namespace_async("namespace-b").await.unwrap();

    let key_id = KeyId::new("shared-key-id");

    // Store different data in different namespaces using async API
    storage
        .store_key_async(&key_id, b"data-a", "namespace-a")
        .await
        .unwrap();
    storage
        .store_key_async(&key_id, b"data-b", "namespace-b")
        .await
        .unwrap();

    // Verify isolation using async API
    let data_a = storage
        .load_key_async(&key_id, "namespace-a")
        .await
        .unwrap();
    let data_b = storage
        .load_key_async(&key_id, "namespace-b")
        .await
        .unwrap();

    assert_eq!(b"data-a", data_a.as_slice());
    assert_eq!(b"data-b", data_b.as_slice());
}

#[tokio::test]
async fn test_hardware_storage_persistence() {
    let temp_dir = TempDir::new().unwrap();

    let key_id = KeyId::new("persistent-key");
    let data = b"persistent data";

    // Create storage, store key, and drop it
    {
        let hw_backend = Box::new(MockHardwareBackend::new());
        let mut storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
            .await
            .unwrap();

        storage.create_namespace_async("test").await.unwrap();
        storage
            .store_key_async(&key_id, data, "test")
            .await
            .unwrap();
    }

    // Create new storage instance and verify key persisted
    {
        let hw_backend = Box::new(MockHardwareBackend::new());
        let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
            .await
            .unwrap();

        let loaded = storage.load_key_async(&key_id, "test").await.unwrap();
        assert_eq!(data.as_slice(), loaded.as_slice());
    }
}

#[tokio::test]
async fn test_hardware_storage_async_operations() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
        .await
        .unwrap();

    // Create namespace asynchronously
    let mut storage_mut = storage;
    storage_mut.create_namespace_async("test").await.unwrap();

    // Store key asynchronously
    let key_id = KeyId::new("async-key");
    storage_mut
        .store_key_async(&key_id, b"async data", "test")
        .await
        .unwrap();

    // Load key asynchronously
    let loaded = storage_mut.load_key_async(&key_id, "test").await.unwrap();

    assert_eq!(b"async data", loaded.as_slice());
}

#[tokio::test]
async fn test_hardware_storage_get_stats() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
        .await
        .unwrap();

    let mut storage_mut = storage;
    storage_mut.create_namespace_async("test").await.unwrap();

    // Store multiple keys
    for i in 0..5 {
        let key_id = KeyId::new(format!("key-{}", i));
        storage_mut
            .store_key_async(&key_id, b"data", "test")
            .await
            .unwrap();
    }

    // Get stats
    let stats = storage_mut.get_stats("test").await.unwrap();

    assert_eq!(stats.total_keys, 5);
    assert!(stats.total_size_bytes > 0);
    assert!(stats.backend_counts.contains_key("software"));
}

#[tokio::test]
async fn test_hardware_storage_seal_failure_handling() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::with_seal_failure());

    let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
        .await
        .unwrap();

    let mut storage_mut = storage;
    storage_mut.create_namespace_async("test").await.unwrap();

    // Attempt to store key (should fail because seal fails)
    let key_id = KeyId::new("fail-key");
    let result = storage_mut.store_key_async(&key_id, b"data", "test").await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_hardware_storage_namespace_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
        .await
        .unwrap();

    let key_id = KeyId::new("test-key");

    // Attempt to store in non-existent namespace
    let result = storage
        .store_key_async(&key_id, b"data", "nonexistent")
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_hardware_storage_delete_namespace() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let mut storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
        .await
        .unwrap();

    // Create namespace and add keys
    storage.create_namespace_async("temp").await.unwrap();
    storage
        .store_key_async(&KeyId::new("key1"), b"data1", "temp")
        .await
        .unwrap();
    storage
        .store_key_async(&KeyId::new("key2"), b"data2", "temp")
        .await
        .unwrap();

    // Delete namespace using async API
    storage.delete_namespace_async("temp").await.unwrap();

    // Verify namespace is gone using async API
    let namespaces = storage.list_namespaces_async().await.unwrap();
    assert!(!namespaces.contains(&"temp".to_string()));
}

#[tokio::test]
async fn test_hardware_storage_list_namespaces() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let mut storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), hw_backend)
        .await
        .unwrap();

    // Create multiple namespaces
    storage.create_namespace_async("ns1").await.unwrap();
    storage.create_namespace_async("ns2").await.unwrap();
    storage.create_namespace_async("ns3").await.unwrap();

    // List namespaces using async API
    let namespaces = storage.list_namespaces_async().await.unwrap();

    assert_eq!(namespaces.len(), 3);
    assert!(namespaces.contains(&"ns1".to_string()));
    assert!(namespaces.contains(&"ns2".to_string()));
    assert!(namespaces.contains(&"ns3".to_string()));
}
