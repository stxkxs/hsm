use hsm_key_manager::*;

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

#[test]
fn test_namespace_list_isolation() {
    let manager = DefaultKeyManager::new();

    // Create keys in namespace1
    for _ in 0..3 {
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "namespace1".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };
        manager.generate_key(spec).unwrap();
    }

    // Create keys in namespace2
    for _ in 0..2 {
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "namespace2".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };
        manager.generate_key(spec).unwrap();
    }

    // List should only show keys from respective namespaces
    let keys1 = manager
        .list_keys("namespace1", KeyFilter::default())
        .unwrap();
    let keys2 = manager
        .list_keys("namespace2", KeyFilter::default())
        .unwrap();

    assert_eq!(keys1.len(), 3);
    assert_eq!(keys2.len(), 2);
}

#[test]
fn test_namespace_deletion_isolation() {
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

    // Try to delete key from wrong namespace - should fail
    assert!(manager.delete_key(&key_id1, "namespace2").is_err());
    assert!(manager.delete_key(&key_id2, "namespace1").is_err());

    // Delete from correct namespace should work
    assert!(manager.delete_key(&key_id1, "namespace1").is_ok());
    assert!(manager.delete_key(&key_id2, "namespace2").is_ok());
}

#[test]
fn test_empty_namespace() {
    let manager = DefaultKeyManager::new();

    // List keys in non-existent namespace should return empty
    let keys = manager
        .list_keys("non-existent", KeyFilter::default())
        .unwrap();
    assert_eq!(keys.len(), 0);
}

#[test]
fn test_namespace_metadata_isolation() {
    let manager = DefaultKeyManager::new();

    let spec1 = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "namespace1".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id1 = manager.generate_key(spec1).unwrap();

    // Get metadata from correct namespace
    assert!(manager.get_metadata(&key_id1, "namespace1").is_ok());

    // Get metadata from wrong namespace should fail
    assert!(manager.get_metadata(&key_id1, "namespace2").is_err());
}

#[test]
fn test_namespace_rotation_isolation() {
    let manager = DefaultKeyManager::new();

    let spec1 = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "namespace1".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id1 = manager.generate_key(spec1).unwrap();

    // Rotate in wrong namespace should fail
    assert!(manager.rotate_key(&key_id1, "namespace2").is_err());

    // Rotate in correct namespace should work
    assert!(manager.rotate_key(&key_id1, "namespace1").is_ok());
}

#[test]
fn test_multiple_namespaces() {
    let manager = DefaultKeyManager::new();

    let namespaces = vec!["ns1", "ns2", "ns3", "ns4", "ns5"];

    // Create keys in each namespace
    for ns in &namespaces {
        for _ in 0..3 {
            let spec = KeySpec {
                key_type: KeyType::Ed25519,
                namespace: ns.to_string(),
                policy: KeyUsagePolicy::default(),
                labels: Default::default(),
            };
            manager.generate_key(spec).unwrap();
        }
    }

    // Verify each namespace has exactly 3 keys
    for ns in &namespaces {
        let keys = manager.list_keys(ns, KeyFilter::default()).unwrap();
        assert_eq!(keys.len(), 3);
    }
}
