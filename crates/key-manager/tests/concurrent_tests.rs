use hsm_key_manager::*;
use std::sync::Arc;
use std::thread;

#[test]
fn test_concurrent_key_generation() {
    let manager = Arc::new(DefaultKeyManager::new());
    let mut handles = vec![];

    // Spawn 10 threads, each creating 5 keys
    for thread_id in 0..10 {
        let manager_clone = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            for _ in 0..5 {
                let spec = KeySpec {
                    key_type: KeyType::Ed25519,
                    namespace: format!("thread-{}", thread_id),
                    policy: KeyUsagePolicy::default(),
                    labels: Default::default(),
                };
                manager_clone.generate_key(spec).unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify each namespace has 5 keys
    for thread_id in 0..10 {
        let namespace = format!("thread-{}", thread_id);
        let keys = manager.list_keys(&namespace, KeyFilter::default()).unwrap();
        assert_eq!(keys.len(), 5);
    }
}

#[test]
fn test_concurrent_operations_same_namespace() {
    let manager = Arc::new(DefaultKeyManager::new());
    let namespace = "shared-namespace";

    // Pre-create some keys
    let mut key_ids = vec![];
    for _ in 0..10 {
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: namespace.to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };
        let key_id = manager.generate_key(spec).unwrap();
        key_ids.push(key_id);
    }

    // Concurrently increment operations on all keys
    let mut handles = vec![];
    for key_id in key_ids.clone() {
        let manager_clone = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            for _ in 0..10 {
                manager_clone
                    .increment_operations(&key_id, namespace)
                    .unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify operation counts
    for key_id in key_ids {
        let metadata = manager.get_metadata(&key_id, namespace).unwrap();
        assert_eq!(metadata.operation_count, 10);
    }
}

#[test]
fn test_concurrent_read_write() {
    let manager = Arc::new(DefaultKeyManager::new());
    let namespace = "rw-test";

    // Create a key
    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: namespace.to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };
    let key_id = manager.generate_key(spec).unwrap();

    let mut handles = vec![];

    // Spawn readers
    for _ in 0..5 {
        let manager_clone = Arc::clone(&manager);
        let key_id_copy = key_id;
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let _metadata = manager_clone.get_metadata(&key_id_copy, namespace).unwrap();
            }
        });
        handles.push(handle);
    }

    // Spawn writers (increment operations)
    for _ in 0..5 {
        let manager_clone = Arc::clone(&manager);
        let key_id_copy = key_id;
        let handle = thread::spawn(move || {
            for _ in 0..10 {
                manager_clone
                    .increment_operations(&key_id_copy, namespace)
                    .unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify final operation count
    let metadata = manager.get_metadata(&key_id, namespace).unwrap();
    assert_eq!(metadata.operation_count, 50); // 5 threads * 10 operations
}

#[test]
fn test_concurrent_key_rotation() {
    let manager = Arc::new(DefaultKeyManager::new());

    // Create keys in different namespaces
    let mut initial_keys = vec![];
    for i in 0..5 {
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: format!("ns-{}", i),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };
        let key_id = manager.generate_key(spec).unwrap();
        initial_keys.push((key_id, format!("ns-{}", i)));
    }

    // Concurrently rotate all keys
    let mut handles = vec![];
    for (key_id, namespace) in initial_keys.clone() {
        let manager_clone = Arc::clone(&manager);
        let handle = thread::spawn(move || manager_clone.rotate_key(&key_id, &namespace).unwrap());
        handles.push(handle);
    }

    // Collect new key IDs
    let mut new_key_ids = vec![];
    for handle in handles {
        let new_key_id = handle.join().unwrap();
        new_key_ids.push(new_key_id);
    }

    // Verify all rotations succeeded
    assert_eq!(new_key_ids.len(), 5);

    // Verify old keys are deactivated
    for (old_key_id, namespace) in initial_keys {
        let metadata = manager.get_metadata(&old_key_id, &namespace).unwrap();
        assert_eq!(metadata.state, KeyState::Deactivated);
    }
}

#[test]
fn test_concurrent_list_and_create() {
    let manager = Arc::new(DefaultKeyManager::new());
    let namespace = "concurrent-list";

    let mut handles = vec![];

    // Spawn creators
    for _ in 0..5 {
        let manager_clone = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            for _ in 0..10 {
                let spec = KeySpec {
                    key_type: KeyType::Ed25519,
                    namespace: namespace.to_string(),
                    policy: KeyUsagePolicy::default(),
                    labels: Default::default(),
                };
                manager_clone.generate_key(spec).unwrap();
            }
        });
        handles.push(handle);
    }

    // Spawn listers
    for _ in 0..5 {
        let manager_clone = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            for _ in 0..20 {
                let _keys = manager_clone
                    .list_keys(namespace, KeyFilter::default())
                    .unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify final count
    let keys = manager.list_keys(namespace, KeyFilter::default()).unwrap();
    assert_eq!(keys.len(), 50); // 5 threads * 10 keys
}

#[test]
fn test_concurrent_delete() {
    let manager = Arc::new(DefaultKeyManager::new());
    let namespace = "delete-test";

    // Create keys
    let mut key_ids = vec![];
    for _ in 0..10 {
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: namespace.to_string(),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        };
        let key_id = manager.generate_key(spec).unwrap();
        key_ids.push(key_id);
    }

    // Concurrently delete all keys
    let mut handles = vec![];
    for key_id in key_ids.clone() {
        let manager_clone = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            manager_clone.delete_key(&key_id, namespace).unwrap();
        });
        handles.push(handle);
    }

    // Wait for all deletions
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify all keys are deleted
    for key_id in key_ids {
        assert!(manager.get_key(&key_id, namespace).is_err());
    }

    // Verify namespace is empty
    let keys = manager.list_keys(namespace, KeyFilter::default()).unwrap();
    assert_eq!(keys.len(), 0);
}

#[tokio::test]
async fn test_async_concurrent_operations() {
    let manager = Arc::new(DefaultKeyManager::new());
    let namespace = "async-test";

    // Create keys concurrently using async tasks
    let mut tasks = vec![];
    for _ in 0..10 {
        let manager_clone = Arc::clone(&manager);
        let task = tokio::spawn(async move {
            let spec = KeySpec {
                key_type: KeyType::Ed25519,
                namespace: namespace.to_string(),
                policy: KeyUsagePolicy::default(),
                labels: Default::default(),
            };
            manager_clone.generate_key(spec).unwrap()
        });
        tasks.push(task);
    }

    // Wait for all tasks
    let mut key_ids = vec![];
    for task in tasks {
        let key_id = task.await.unwrap();
        key_ids.push(key_id);
    }

    assert_eq!(key_ids.len(), 10);

    // Verify all keys exist
    for key_id in key_ids {
        assert!(manager.get_key(&key_id, namespace).is_ok());
    }
}
