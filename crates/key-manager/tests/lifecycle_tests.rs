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

#[test]
fn test_key_generation_ed25519() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();
    let key = manager.get_key(&key_id, "test").unwrap();

    assert_eq!(key.key_type, KeyType::Ed25519);
    assert_eq!(key.state, KeyState::Active);
    assert!(key.private_material.is_some());
    assert!(key.public_material.is_some());
}

#[test]
fn test_key_generation_ecdsa_p256() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::EcdsaP256,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();
    let key = manager.get_key(&key_id, "test").unwrap();

    assert_eq!(key.key_type, KeyType::EcdsaP256);
    assert_eq!(key.state, KeyState::Active);
}

#[test]
fn test_key_generation_rsa_2048() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Rsa2048,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();
    let key = manager.get_key(&key_id, "test").unwrap();

    assert_eq!(key.key_type, KeyType::Rsa2048);
    assert_eq!(key.state, KeyState::Active);
}

#[test]
fn test_key_state_transitions() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();

    // Deactivate
    manager
        .update_state(&key_id, "test", KeyState::Deactivated)
        .unwrap();
    let metadata = manager.get_metadata(&key_id, "test").unwrap();
    assert_eq!(metadata.state, KeyState::Deactivated);

    // Try to use deactivated key - should fail
    let result = manager.get_key(&key_id, "test");
    assert!(result.is_err());
}

#[test]
fn test_key_rotation() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();

    // Rotate
    let new_key_id = manager.rotate_key(&key_id, "test").unwrap();

    // Check new key metadata
    let new_metadata = manager.get_metadata(&new_key_id, "test").unwrap();
    assert_eq!(new_metadata.version, 2);
    assert_eq!(new_metadata.previous_version, Some(key_id));

    // Check old key is deactivated
    let old_metadata = manager.get_metadata(&key_id, "test").unwrap();
    assert_eq!(old_metadata.state, KeyState::Deactivated);
}

#[test]
fn test_operation_counter() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();

    // Increment operations
    manager.increment_operations(&key_id, "test").unwrap();
    manager.increment_operations(&key_id, "test").unwrap();
    manager.increment_operations(&key_id, "test").unwrap();

    let metadata = manager.get_metadata(&key_id, "test").unwrap();
    assert_eq!(metadata.operation_count, 3);
}

#[test]
fn test_max_operations_limit() {
    let manager = DefaultKeyManager::new();

    let policy = KeyUsagePolicy {
        max_operations: Some(2),
        ..Default::default()
    };

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy,
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();

    // Increment to max
    manager.increment_operations(&key_id, "test").unwrap();
    manager.increment_operations(&key_id, "test").unwrap();

    // Should fail due to max operations
    let result = manager.get_key(&key_id, "test");
    assert!(result.is_err());
}

#[test]
fn test_key_deletion() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();

    // Delete
    manager.delete_key(&key_id, "test").unwrap();

    // Verify key is gone
    let result = manager.get_key(&key_id, "test");
    assert!(result.is_err());
}

#[test]
fn test_list_keys() {
    let manager = DefaultKeyManager::new();

    // Generate multiple keys
    for _ in 0..5 {
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };
        manager.generate_key(spec).unwrap();
    }

    let keys = manager.list_keys("test", KeyFilter::default()).unwrap();
    assert_eq!(keys.len(), 5);
}

#[test]
fn test_list_keys_with_filter() {
    let manager = DefaultKeyManager::new();

    // Generate Ed25519 keys
    for _ in 0..3 {
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };
        manager.generate_key(spec).unwrap();
    }

    // Generate ECDSA keys
    for _ in 0..2 {
        let spec = KeySpec {
            key_type: KeyType::EcdsaP256,
            namespace: "test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };
        manager.generate_key(spec).unwrap();
    }

    // Filter for Ed25519 only
    let filter = KeyFilter {
        key_type: Some(KeyType::Ed25519),
        state: None,
        labels: Default::default(),
    };

    let keys = manager.list_keys("test", filter).unwrap();
    assert_eq!(keys.len(), 3);
}
