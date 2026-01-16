use hsm_key_manager::*;
use std::sync::Arc;
use std::thread;

/// Test that namespace violations are properly detected
#[test]
fn test_namespace_violation_detection() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "namespace1".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();

    // Try to access with wrong namespace - should detect violation
    match manager.get_key(&key_id, "namespace2") {
        Err(Error::KeyNotFound(_)) => {} // Expected - key not found in wrong namespace
        Err(Error::NamespaceViolation { expected, actual }) => {
            assert_eq!(expected, "namespace2");
            assert_eq!(actual, "namespace1");
        }
        _ => panic!("Expected namespace violation error"),
    }
}

/// Test that Debug implementation doesn't leak key material
#[test]
fn test_key_debug_no_leak() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();
    let key = manager.get_key(&key_id, "test").unwrap();

    // Debug output should redact private material
    let debug_output = format!("{:?}", key);
    assert!(debug_output.contains("<redacted>"));
    assert!(!debug_output.contains("private_material: Some"));
}

/// Test concurrent namespace isolation
#[test]
fn test_concurrent_namespace_isolation() {
    let manager = Arc::new(DefaultKeyManager::new());
    let mut handles = vec![];

    // Spawn multiple threads, each creating keys in their own namespace
    for i in 0..10 {
        let mgr = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            let namespace = format!("namespace{}", i);

            // Create 10 keys in this namespace
            let mut key_ids = vec![];
            for _ in 0..10 {
                let spec = KeySpec {
                    key_type: KeyType::Ed25519,
                    namespace: namespace.clone(),
                    policy: KeyUsagePolicy::default(),
                    labels: Default::default(),
                };
                let key_id = mgr.generate_key(spec).unwrap();
                key_ids.push(key_id);
            }

            // Verify all keys are accessible in their namespace
            for key_id in &key_ids {
                assert!(mgr.get_key(key_id, &namespace).is_ok());
            }

            // Verify keys are NOT accessible from other namespaces
            for j in 0..10 {
                if i != j {
                    let other_namespace = format!("namespace{}", j);
                    for key_id in &key_ids {
                        assert!(mgr.get_key(key_id, &other_namespace).is_err());
                    }
                }
            }

            key_ids.len()
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    let mut total_keys = 0;
    for handle in handles {
        total_keys += handle.join().unwrap();
    }

    assert_eq!(total_keys, 100); // 10 namespaces * 10 keys
}

/// Test batch operations respect namespace isolation
#[test]
fn test_batch_namespace_isolation() {
    let manager = DefaultKeyManager::new();

    // Create keys in multiple namespaces
    let mut ns1_keys = vec![];
    let mut ns2_keys = vec![];

    for _ in 0..5 {
        let spec1 = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "ns1".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };
        ns1_keys.push(manager.generate_key(spec1).unwrap());

        let spec2 = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "ns2".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };
        ns2_keys.push(manager.generate_key(spec2).unwrap());
    }

    // List batch should only return keys from specified namespace
    let ns1_list = manager.list_keys_batch("ns1", 0, 10).unwrap();
    assert_eq!(ns1_list.len(), 5);
    for metadata in ns1_list {
        assert_eq!(metadata.namespace, "ns1");
    }

    let ns2_list = manager.list_keys_batch("ns2", 0, 10).unwrap();
    assert_eq!(ns2_list.len(), 5);
    for metadata in ns2_list {
        assert_eq!(metadata.namespace, "ns2");
    }
}

/// Test that update operations verify namespace
#[test]
fn test_update_namespace_verification() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "namespace1".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();

    // Try to update state from wrong namespace - should fail
    assert!(manager
        .update_state(&key_id, "namespace2", KeyState::Deactivated)
        .is_err());

    // Update from correct namespace should work
    assert!(manager
        .update_state(&key_id, "namespace1", KeyState::Deactivated)
        .is_ok());
}

/// Test that increment_operations verifies namespace
#[test]
fn test_increment_operations_namespace() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "namespace1".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();

    // Try to increment from wrong namespace - should fail
    assert!(manager.increment_operations(&key_id, "namespace2").is_err());

    // Increment from correct namespace should work
    assert!(manager.increment_operations(&key_id, "namespace1").is_ok());
}

/// Test deletion batch respects namespace
#[test]
fn test_delete_batch_namespace() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "namespace1".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key1 = manager.generate_key(spec.clone()).unwrap();
    let key2 = manager.generate_key(spec).unwrap();

    // Try to delete keys with wrong namespaces - should fail
    let result = manager.delete_keys_batch(vec![
        (key1, "namespace2".to_string()),
        (key2, "namespace2".to_string()),
    ]);
    assert!(result.is_err());

    // Keys should still exist in correct namespace
    assert!(manager.get_key(&key1, "namespace1").is_ok());
    assert!(manager.get_key(&key2, "namespace1").is_ok());
}

/// Test that rotation maintains namespace consistency
#[test]
fn test_rotation_namespace_consistency() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "namespace1".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let old_key_id = manager.generate_key(spec).unwrap();
    let new_key_id = manager.rotate_key(&old_key_id, "namespace1").unwrap();

    // New key should be in same namespace
    let new_key = manager.get_key(&new_key_id, "namespace1").unwrap();
    assert_eq!(new_key.namespace, "namespace1");

    // New key should NOT be accessible from other namespace
    assert!(manager.get_key(&new_key_id, "namespace2").is_err());
}

/// Test zero-copy Arc semantics
#[test]
fn test_arc_zero_copy() {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "test".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };

    let key_id = manager.generate_key(spec).unwrap();

    // Get key multiple times
    let key1 = manager.get_key(&key_id, "test").unwrap();
    let key2 = manager.get_key(&key_id, "test").unwrap();

    // Both should point to the same Arc (cached)
    assert!(Arc::ptr_eq(&key1, &key2));
}
