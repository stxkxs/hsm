//! Integration tests for hardware-backed key manager
//!
//! These tests verify that the HardwareKeyManager correctly integrates with
//! hardware backends for key generation, storage, and remote signing.

#![cfg(feature = "hardware")]

use hsm_hardware_backend::{
    AttestationReport, BackendType, HardwareBackend, HardwareError, PlaintextKey, SealedKey,
    SealedKeyMetadata, TeeMeasurements,
};
use hsm_key_manager::{
    AsyncKeyManager, HardwareKeyManager, KeyFilter, KeyManager, KeySpec, KeyState, KeyType,
    KeyUsagePolicy,
};
use hsm_storage::HardwareStorageBackend;
use std::collections::HashMap;
use tempfile::TempDir;

// Mock hardware backend for integration testing
struct MockHardwareBackend {
    fail_seal: bool,
    fail_unseal: bool,
    fail_sign: bool,
}

impl MockHardwareBackend {
    fn new() -> Self {
        Self {
            fail_seal: false,
            fail_unseal: false,
            fail_sign: false,
        }
    }

    fn with_sign_failure() -> Self {
        Self {
            fail_seal: false,
            fail_unseal: false,
            fail_sign: true,
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
            return Err(HardwareError::UnsealingFailed(
                "Mocked failure".to_string(),
            ));
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

    async fn remote_sign(&self, _key_id: &str, message: &[u8]) -> Result<Vec<u8>, HardwareError> {
        if self.fail_sign {
            return Err(HardwareError::RemoteSigningFailed("Mocked failure".to_string()));
        }

        // Return a mock signature (hash of message)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(b"mock-signature");
        Ok(hasher.finalize().to_vec())
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Software
    }

    async fn is_available(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn test_hardware_key_manager_generation() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), Box::new(MockHardwareBackend::new()))
        .await
        .unwrap();

    let manager = HardwareKeyManager::new(storage, hw_backend).await.unwrap();

    // Create namespace
    manager.create_namespace_async("test").await.unwrap();

    // Generate a key
    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: HashMap::new(),
    };

    let key_id = manager.generate_key_async(spec).await.unwrap();

    // Verify key exists
    let key = manager.get_key_async(&key_id, "test").await.unwrap();
    assert_eq!(key.key_type, KeyType::Ed25519);
    assert_eq!(key.state, KeyState::Active);
}

#[tokio::test]
async fn test_hardware_key_manager_remote_sign() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), Box::new(MockHardwareBackend::new()))
        .await
        .unwrap();

    let manager = HardwareKeyManager::new(storage, hw_backend).await.unwrap();

    // Create namespace
    manager.create_namespace_async("test").await.unwrap();

    // Generate a key
    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: HashMap::new(),
    };

    let key_id = manager.generate_key_async(spec).await.unwrap();

    // Remote sign
    let message = b"test message to sign";
    let signature = manager
        .remote_sign_async(&key_id, "test", message)
        .await
        .unwrap();

    // Verify signature is returned
    assert!(!signature.is_empty());
    assert_eq!(signature.len(), 32); // SHA-256 hash length
}

#[tokio::test]
async fn test_hardware_key_manager_list_keys() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), Box::new(MockHardwareBackend::new()))
        .await
        .unwrap();

    let manager = HardwareKeyManager::new(storage, hw_backend).await.unwrap();

    // Create namespace
    manager.create_namespace_async("test").await.unwrap();

    // Generate multiple keys
    for i in 0..5 {
        let spec = KeySpec {
            key_type: if i % 2 == 0 {
                KeyType::Ed25519
            } else {
                KeyType::EcdsaP256
            },
            namespace: "test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: HashMap::new(),
        };
        manager.generate_key_async(spec).await.unwrap();
    }

    // List all keys
    let all_keys = manager
        .list_keys_async("test", KeyFilter {
            key_type: None,
            state: None,
            labels: HashMap::new(),
        })
        .await
        .unwrap();
    assert_eq!(all_keys.len(), 5);

    // List only Ed25519 keys
    let ed25519_keys = manager
        .list_keys_async("test", KeyFilter {
            key_type: Some(KeyType::Ed25519),
            state: None,
            labels: HashMap::new(),
        })
        .await
        .unwrap();
    assert_eq!(ed25519_keys.len(), 3);

    // List only ECDSA keys
    let ecdsa_keys = manager
        .list_keys_async("test", KeyFilter {
            key_type: Some(KeyType::EcdsaP256),
            state: None,
            labels: HashMap::new(),
        })
        .await
        .unwrap();
    assert_eq!(ecdsa_keys.len(), 2);
}

#[tokio::test]
async fn test_hardware_key_manager_key_rotation() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), Box::new(MockHardwareBackend::new()))
        .await
        .unwrap();

    let manager = HardwareKeyManager::new(storage, hw_backend).await.unwrap();

    // Create namespace
    manager.create_namespace_async("test").await.unwrap();

    // Generate initial key
    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: HashMap::new(),
    };

    let old_key_id = manager.generate_key_async(spec).await.unwrap();

    // Rotate key
    let new_key_id = manager
        .rotate_key_async(&old_key_id, "test")
        .await
        .unwrap();

    // Verify new key exists
    let new_key = manager.get_key_async(&new_key_id, "test").await.unwrap();
    assert_eq!(new_key.state, KeyState::Active);
    assert_eq!(new_key.version, 2);
    assert_eq!(new_key.previous_version, Some(old_key_id));

    // Verify old key is deactivated (loading it should fail)
    let old_key_result = manager.get_key_async(&old_key_id, "test").await;
    assert!(old_key_result.is_err()); // Should fail because key is deactivated
}

#[tokio::test]
async fn test_hardware_key_manager_delete_key() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), Box::new(MockHardwareBackend::new()))
        .await
        .unwrap();

    let manager = HardwareKeyManager::new(storage, hw_backend).await.unwrap();

    // Create namespace
    manager.create_namespace_async("test").await.unwrap();

    // Generate a key
    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: HashMap::new(),
    };

    let key_id = manager.generate_key_async(spec).await.unwrap();

    // Delete key
    manager.delete_key_async(&key_id, "test").await.unwrap();

    // Verify key is deleted
    let result = manager.get_key_async(&key_id, "test").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_hardware_key_manager_namespace_isolation() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), Box::new(MockHardwareBackend::new()))
        .await
        .unwrap();

    let manager = HardwareKeyManager::new(storage, hw_backend).await.unwrap();

    // Create namespaces
    manager.create_namespace_async("namespace-a").await.unwrap();
    manager.create_namespace_async("namespace-b").await.unwrap();

    // Generate key in namespace A
    let spec_a = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "namespace-a".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: HashMap::new(),
    };
    let key_id_a = manager.generate_key_async(spec_a).await.unwrap();

    // Generate key in namespace B
    let spec_b = KeySpec {
        key_type: KeyType::EcdsaP256,
        namespace: "namespace-b".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: HashMap::new(),
    };
    let key_id_b = manager.generate_key_async(spec_b).await.unwrap();

    // Can access key from its own namespace
    assert!(manager.get_key_async(&key_id_a, "namespace-a").await.is_ok());
    assert!(manager.get_key_async(&key_id_b, "namespace-b").await.is_ok());

    // Cannot access key from different namespace
    assert!(manager.get_key_async(&key_id_a, "namespace-b").await.is_err());
    assert!(manager.get_key_async(&key_id_b, "namespace-a").await.is_err());
}

#[tokio::test]
async fn test_hardware_key_manager_sync_api() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), Box::new(MockHardwareBackend::new()))
        .await
        .unwrap();

    let manager = HardwareKeyManager::new(storage, hw_backend).await.unwrap();

    // Create namespace
    manager.create_namespace_async("test").await.unwrap();

    // Test async API
    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: HashMap::new(),
    };

    // Generate key using async API
    let key_id = manager.generate_key_async(spec).await.unwrap();

    // Get key using async API
    let key = manager.get_key_async(&key_id, "test").await.unwrap();

    assert_eq!(key.key_type, KeyType::Ed25519);
}

#[tokio::test]
async fn test_hardware_key_manager_operation_counter() {
    let temp_dir = TempDir::new().unwrap();
    let hw_backend = Box::new(MockHardwareBackend::new());

    let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), Box::new(MockHardwareBackend::new()))
        .await
        .unwrap();

    let manager = HardwareKeyManager::new(storage, hw_backend).await.unwrap();

    // Create namespace
    manager.create_namespace_async("test").await.unwrap();

    // Generate a key
    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy {
            can_sign: true,
            can_encrypt: true,
            can_derive: false,
            can_export: false,
            max_operations: Some(5),
            expires_at: None,
        },
        labels: HashMap::new(),
    };

    let key_id = manager.generate_key_async(spec).await.unwrap();

    // Perform 5 signing operations
    for _ in 0..5 {
        manager
            .remote_sign_async(&key_id, "test", b"message")
            .await
            .unwrap();
    }

    // 6th operation should fail (max_operations reached)
    let result = manager
        .remote_sign_async(&key_id, "test", b"message")
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_hardware_key_manager_persistence() {
    let temp_dir = TempDir::new().unwrap();

    let key_id = {
        // Create first instance
        let hw_backend = Box::new(MockHardwareBackend::new());
        let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), Box::new(MockHardwareBackend::new()))
            .await
            .unwrap();

        let manager = HardwareKeyManager::new(storage, hw_backend).await.unwrap();
        manager.create_namespace_async("test").await.unwrap();

        // Generate a key
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: HashMap::new(),
        };

        manager.generate_key_async(spec).await.unwrap()
    };

    // Create second instance and verify key persisted
    {
        let hw_backend = Box::new(MockHardwareBackend::new());
        let storage = HardwareStorageBackend::new(temp_dir.path().to_path_buf(), Box::new(MockHardwareBackend::new()))
            .await
            .unwrap();

        let manager = HardwareKeyManager::new(storage, hw_backend).await.unwrap();

        // Key should still exist
        let key = manager.get_key_async(&key_id, "test").await.unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
    }
}
