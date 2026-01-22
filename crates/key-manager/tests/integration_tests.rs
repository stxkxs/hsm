use hsm_key_manager::*;

#[test]
fn test_complete_key_workflow() {
    let manager = DefaultKeyManager::new();
    let namespace = "integration-test";

    // 1. Generate a key
    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: namespace.to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();

    // 2. Use the key (simulate operations)
    manager.increment_operations(&key_id, namespace).unwrap();
    manager.increment_operations(&key_id, namespace).unwrap();

    // 3. Check metadata
    let metadata = manager.get_metadata(&key_id, namespace).unwrap();
    assert_eq!(metadata.operation_count, 2);
    assert_eq!(metadata.state, KeyState::Active);

    // 4. Rotate the key
    let new_key_id = manager.rotate_key(&key_id, namespace).unwrap();

    // 5. Verify rotation
    let new_metadata = manager.get_metadata(&new_key_id, namespace).unwrap();
    assert_eq!(new_metadata.version, 2);
    assert_eq!(new_metadata.previous_version, Some(key_id));

    // 6. Old key should be deactivated
    let old_metadata = manager.get_metadata(&key_id, namespace).unwrap();
    assert_eq!(old_metadata.state, KeyState::Deactivated);

    // 7. Delete both keys
    manager.delete_key(&key_id, namespace).unwrap();
    manager.delete_key(&new_key_id, namespace).unwrap();
}

#[test]
fn test_multi_tenant_scenario() {
    let manager = DefaultKeyManager::new();

    // Tenant 1
    let tenant1_spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "tenant1".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    // Tenant 2
    let tenant2_spec = KeySpec {
        key_type: KeyType::EcdsaP256,
        namespace: "tenant2".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    // Generate keys for both tenants
    let t1_key1 = manager.generate_key(tenant1_spec.clone()).unwrap();
    let t1_key2 = manager.generate_key(tenant1_spec.clone()).unwrap();
    let t2_key1 = manager.generate_key(tenant2_spec.clone()).unwrap();
    let t2_key2 = manager.generate_key(tenant2_spec.clone()).unwrap();

    // List keys per tenant
    let t1_keys = manager.list_keys("tenant1", KeyFilter::default()).unwrap();
    let t2_keys = manager.list_keys("tenant2", KeyFilter::default()).unwrap();

    assert_eq!(t1_keys.len(), 2);
    assert_eq!(t2_keys.len(), 2);

    // Verify isolation
    assert!(manager.get_key(&t1_key1, "tenant2").is_err());
    assert!(manager.get_key(&t2_key1, "tenant1").is_err());

    // Cleanup
    manager.delete_key(&t1_key1, "tenant1").unwrap();
    manager.delete_key(&t1_key2, "tenant1").unwrap();
    manager.delete_key(&t2_key1, "tenant2").unwrap();
    manager.delete_key(&t2_key2, "tenant2").unwrap();
}

#[test]
fn test_key_expiration() {
    let manager = DefaultKeyManager::new();

    use chrono::{Duration, Utc};

    let mut policy = KeyUsagePolicy::default();
    policy.expires_at = Some(Utc::now() - Duration::seconds(10)); // Already expired

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy,
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();

    // Expired key should not be usable
    let result = manager.get_key(&key_id, "test");
    assert!(result.is_err());
}

#[test]
fn test_different_key_types() {
    let manager = DefaultKeyManager::new();

    let key_types = vec![
        KeyType::Ed25519,
        KeyType::EcdsaP256,
        KeyType::EcdsaP384,
        KeyType::Rsa2048,
    ];

    for key_type in key_types {
        let spec = KeySpec {
            key_type,
            namespace: "test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };

        let key_id = manager.generate_key(spec).unwrap();
        let key = manager.get_key(&key_id, "test").unwrap();

        assert_eq!(key.key_type, key_type);
        assert_eq!(key.state, KeyState::Active);

        manager.delete_key(&key_id, "test").unwrap();
    }
}

#[test]
fn test_key_policy_enforcement() {
    let manager = DefaultKeyManager::new();

    let mut policy = KeyUsagePolicy::default();
    policy.can_sign = true;
    policy.can_encrypt = false;
    policy.can_derive = false;
    policy.can_export = false;

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy,
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();
    let key = manager.get_key(&key_id, "test").unwrap();

    assert!(key.policy.can_sign);
    assert!(!key.policy.can_encrypt);
    assert!(!key.policy.can_derive);
    assert!(!key.policy.can_export);
}

#[test]
fn test_metadata_fingerprint() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();
    let metadata = manager.get_metadata(&key_id, "test").unwrap();

    // Fingerprint should be non-empty and consistent
    assert!(!metadata.fingerprint.is_empty());
    assert_eq!(metadata.fingerprint.len(), 64); // SHA-256 hex = 64 chars
}

#[test]
fn test_key_versioning() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    // Create initial key
    let v1_id = manager.generate_key(spec).unwrap();
    let v1_meta = manager.get_metadata(&v1_id, "test").unwrap();
    assert_eq!(v1_meta.version, 1);
    assert_eq!(v1_meta.previous_version, None);

    // Rotate to v2
    let v2_id = manager.rotate_key(&v1_id, "test").unwrap();
    let v2_meta = manager.get_metadata(&v2_id, "test").unwrap();
    assert_eq!(v2_meta.version, 2);
    assert_eq!(v2_meta.previous_version, Some(v1_id));

    // Rotate to v3
    let v3_id = manager.rotate_key(&v2_id, "test").unwrap();
    let v3_meta = manager.get_metadata(&v3_id, "test").unwrap();
    assert_eq!(v3_meta.version, 3);
    assert_eq!(v3_meta.previous_version, Some(v2_id));
}

#[test]
fn test_list_with_state_filter() {
    let manager = DefaultKeyManager::new();

    // Create active keys
    for _ in 0..3 {
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };
        manager.generate_key(spec).unwrap();
    }

    // Create and deactivate some keys
    for _ in 0..2 {
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };
        let key_id = manager.generate_key(spec).unwrap();
        manager
            .update_state(&key_id, "test", KeyState::Deactivated)
            .unwrap();
    }

    // Filter for active keys
    let filter = KeyFilter {
        key_type: None,
        state: Some(KeyState::Active),
        labels: Default::default(),
    };

    let active_keys = manager.list_keys("test", filter).unwrap();
    assert_eq!(active_keys.len(), 3);

    // Filter for deactivated keys
    let filter = KeyFilter {
        key_type: None,
        state: Some(KeyState::Deactivated),
        labels: Default::default(),
    };

    let deactivated_keys = manager.list_keys("test", filter).unwrap();
    assert_eq!(deactivated_keys.len(), 2);
}

// ===========================================================================
// Key Import Tests
// ===========================================================================

#[test]
fn test_import_ed25519_key() {
    let manager = DefaultKeyManager::new();

    // Generate a random 32-byte Ed25519 private key
    let private_key_bytes: Vec<u8> = (0..32).map(|i| (i * 7 + 13) as u8).collect();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.import_key(private_key_bytes.clone(), spec).unwrap();

    // Verify the key was imported
    let key = manager.get_key(&key_id, "test").unwrap();
    assert_eq!(key.key_type, KeyType::Ed25519);
    assert_eq!(key.state, KeyState::Active);

    // Verify private key material matches
    let private_material = key.private_material.as_ref().unwrap();
    assert_eq!(private_material.as_bytes(), &private_key_bytes);

    // Verify public key was derived
    assert!(key.public_material.is_some());
    let public_key = key.public_material.as_ref().unwrap();
    assert_eq!(public_key.len(), 32); // Ed25519 public key is 32 bytes

    manager.delete_key(&key_id, "test").unwrap();
}

#[test]
fn test_import_ed25519_invalid_length() {
    let manager = DefaultKeyManager::new();

    // Wrong size private key
    let invalid_key: Vec<u8> = vec![0u8; 16]; // Should be 32 bytes

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let result = manager.import_key(invalid_key, spec);
    assert!(result.is_err());
}

#[test]
fn test_import_ecdsa_p256_key() {
    let manager = DefaultKeyManager::new();

    // Generate a valid P-256 private key (32 bytes scalar)
    // Using a known valid scalar (not zero, less than curve order)
    let mut private_key_bytes: Vec<u8> = vec![0u8; 32];
    private_key_bytes[31] = 1; // Set to 1 (valid small scalar)

    let spec = KeySpec {
        key_type: KeyType::EcdsaP256,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.import_key(private_key_bytes, spec).unwrap();

    // Verify the key was imported
    let key = manager.get_key(&key_id, "test").unwrap();
    assert_eq!(key.key_type, KeyType::EcdsaP256);
    assert_eq!(key.state, KeyState::Active);

    // Verify public key was derived (uncompressed point = 65 bytes)
    assert!(key.public_material.is_some());
    let public_key = key.public_material.as_ref().unwrap();
    assert_eq!(public_key.len(), 65);

    manager.delete_key(&key_id, "test").unwrap();
}

#[test]
fn test_import_ecdsa_p384_key() {
    let manager = DefaultKeyManager::new();

    // Generate a valid P-384 private key (48 bytes scalar)
    let mut private_key_bytes: Vec<u8> = vec![0u8; 48];
    private_key_bytes[47] = 1; // Set to 1 (valid small scalar)

    let spec = KeySpec {
        key_type: KeyType::EcdsaP384,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.import_key(private_key_bytes, spec).unwrap();

    // Verify the key was imported
    let key = manager.get_key(&key_id, "test").unwrap();
    assert_eq!(key.key_type, KeyType::EcdsaP384);
    assert_eq!(key.state, KeyState::Active);

    // Verify public key was derived (uncompressed point = 97 bytes)
    assert!(key.public_material.is_some());
    let public_key = key.public_material.as_ref().unwrap();
    assert_eq!(public_key.len(), 97);

    manager.delete_key(&key_id, "test").unwrap();
}

#[test]
fn test_imported_key_usable_with_operations() {
    let manager = DefaultKeyManager::new();

    // Import Ed25519 key
    let private_key_bytes: Vec<u8> = (0..32).map(|i| (i * 11 + 3) as u8).collect();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.import_key(private_key_bytes, spec).unwrap();

    // Increment operations should work
    manager.increment_operations(&key_id, "test").unwrap();
    manager.increment_operations(&key_id, "test").unwrap();

    // Check metadata
    let metadata = manager.get_metadata(&key_id, "test").unwrap();
    assert_eq!(metadata.operation_count, 2);

    // Key should still be usable
    let key = manager.get_key(&key_id, "test").unwrap();
    assert_eq!(key.state, KeyState::Active);

    manager.delete_key(&key_id, "test").unwrap();
}

#[test]
fn test_imported_key_can_be_rotated() {
    let manager = DefaultKeyManager::new();

    // Import Ed25519 key
    let private_key_bytes: Vec<u8> = (0..32).map(|i| (i * 17 + 5) as u8).collect();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.import_key(private_key_bytes, spec).unwrap();

    // Rotate the imported key
    let new_key_id = manager.rotate_key(&key_id, "test").unwrap();

    // Verify rotation
    let old_metadata = manager.get_metadata(&key_id, "test").unwrap();
    let new_metadata = manager.get_metadata(&new_key_id, "test").unwrap();

    assert_eq!(old_metadata.state, KeyState::Deactivated);
    assert_eq!(new_metadata.state, KeyState::Active);
    assert_eq!(new_metadata.version, 2);
    assert_eq!(new_metadata.previous_version, Some(key_id));

    // Cleanup
    manager.delete_key(&key_id, "test").unwrap();
    manager.delete_key(&new_key_id, "test").unwrap();
}

// ===========================================================================
// Secp256k1 Tests (Bitcoin/Ethereum)
// ===========================================================================

#[test]
fn test_generate_secp256k1_key() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Secp256k1,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();
    let key = manager.get_key(&key_id, "test").unwrap();

    assert_eq!(key.key_type, KeyType::Secp256k1);
    assert_eq!(key.state, KeyState::Active);
    assert!(key.private_material.is_some());
    assert!(key.public_material.is_some());

    // secp256k1 private key is 32 bytes
    assert_eq!(key.private_material.as_ref().unwrap().as_bytes().len(), 32);
    // secp256k1 compressed public key is 33 bytes
    assert_eq!(key.public_material.as_ref().unwrap().len(), 33);

    manager.delete_key(&key_id, "test").unwrap();
}

#[test]
fn test_import_secp256k1_key() {
    let manager = DefaultKeyManager::new();

    // Valid secp256k1 private key (32 bytes, non-zero, less than curve order)
    let mut private_key_bytes: Vec<u8> = vec![0u8; 32];
    private_key_bytes[31] = 1;

    let spec = KeySpec {
        key_type: KeyType::Secp256k1,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.import_key(private_key_bytes, spec).unwrap();
    let key = manager.get_key(&key_id, "test").unwrap();

    assert_eq!(key.key_type, KeyType::Secp256k1);
    assert_eq!(key.state, KeyState::Active);
    assert!(key.public_material.is_some());
    // Compressed public key is 33 bytes
    assert_eq!(key.public_material.as_ref().unwrap().len(), 33);

    manager.delete_key(&key_id, "test").unwrap();
}

#[test]
fn test_import_secp256k1_invalid_length() {
    let manager = DefaultKeyManager::new();

    let invalid_key: Vec<u8> = vec![0u8; 16]; // Should be 32 bytes

    let spec = KeySpec {
        key_type: KeyType::Secp256k1,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let result = manager.import_key(invalid_key, spec);
    assert!(result.is_err());
}

#[test]
fn test_secp256k1_key_rotation() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Secp256k1,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();
    let new_key_id = manager.rotate_key(&key_id, "test").unwrap();

    let old_metadata = manager.get_metadata(&key_id, "test").unwrap();
    let new_metadata = manager.get_metadata(&new_key_id, "test").unwrap();

    assert_eq!(old_metadata.state, KeyState::Deactivated);
    assert_eq!(new_metadata.state, KeyState::Active);
    assert_eq!(new_metadata.key_type, KeyType::Secp256k1);

    manager.delete_key(&key_id, "test").unwrap();
    manager.delete_key(&new_key_id, "test").unwrap();
}

// ===========================================================================
// BLS12-381 Tests (Ethereum 2.0)
// ===========================================================================

#[test]
fn test_generate_bls12381_key() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Bls12381,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();
    let key = manager.get_key(&key_id, "test").unwrap();

    assert_eq!(key.key_type, KeyType::Bls12381);
    assert_eq!(key.state, KeyState::Active);
    assert!(key.private_material.is_some());
    assert!(key.public_material.is_some());

    // BLS private key is 32 bytes
    assert_eq!(key.private_material.as_ref().unwrap().as_bytes().len(), 32);
    // BLS compressed public key is 48 bytes (G1 point)
    assert_eq!(key.public_material.as_ref().unwrap().len(), 48);

    manager.delete_key(&key_id, "test").unwrap();
}

#[test]
fn test_import_bls12381_key() {
    let manager = DefaultKeyManager::new();

    // Valid BLS private key (32 bytes)
    // Using IKM that will produce a valid key
    let private_key_bytes: Vec<u8> = (0..32).map(|i| (i * 7 + 13) as u8).collect();

    let spec = KeySpec {
        key_type: KeyType::Bls12381,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.import_key(private_key_bytes, spec).unwrap();
    let key = manager.get_key(&key_id, "test").unwrap();

    assert_eq!(key.key_type, KeyType::Bls12381);
    assert_eq!(key.state, KeyState::Active);
    assert!(key.public_material.is_some());
    // Compressed public key is 48 bytes
    assert_eq!(key.public_material.as_ref().unwrap().len(), 48);

    manager.delete_key(&key_id, "test").unwrap();
}

#[test]
fn test_import_bls12381_invalid_length() {
    let manager = DefaultKeyManager::new();

    let invalid_key: Vec<u8> = vec![0u8; 16]; // Should be 32 bytes

    let spec = KeySpec {
        key_type: KeyType::Bls12381,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let result = manager.import_key(invalid_key, spec);
    assert!(result.is_err());
}

#[test]
fn test_bls12381_key_rotation() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Bls12381,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();
    let new_key_id = manager.rotate_key(&key_id, "test").unwrap();

    let old_metadata = manager.get_metadata(&key_id, "test").unwrap();
    let new_metadata = manager.get_metadata(&new_key_id, "test").unwrap();

    assert_eq!(old_metadata.state, KeyState::Deactivated);
    assert_eq!(new_metadata.state, KeyState::Active);
    assert_eq!(new_metadata.key_type, KeyType::Bls12381);

    manager.delete_key(&key_id, "test").unwrap();
    manager.delete_key(&new_key_id, "test").unwrap();
}

#[test]
fn test_different_key_types_includes_new_algorithms() {
    let manager = DefaultKeyManager::new();

    let key_types = vec![
        KeyType::Ed25519,
        KeyType::EcdsaP256,
        KeyType::EcdsaP384,
        KeyType::Secp256k1,
        KeyType::Bls12381,
    ];

    for key_type in key_types {
        let spec = KeySpec {
            key_type,
            namespace: "test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };

        let key_id = manager.generate_key(spec).unwrap();
        let key = manager.get_key(&key_id, "test").unwrap();

        assert_eq!(key.key_type, key_type);
        assert_eq!(key.state, KeyState::Active);

        manager.delete_key(&key_id, "test").unwrap();
    }
}
