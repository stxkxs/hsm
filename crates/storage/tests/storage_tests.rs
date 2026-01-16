//! Integration tests for storage backend

use hsm_storage::{EncryptedFileStorage, KeyId, StorageBackend};
use tempfile::TempDir;

fn create_test_storage() -> (TempDir, EncryptedFileStorage) {
    let temp_dir = TempDir::new().unwrap();
    let kek = [42u8; 32];
    let storage =
        EncryptedFileStorage::create_with_new_key(temp_dir.path().to_path_buf(), &kek).unwrap();
    (temp_dir, storage)
}

#[test]
fn test_full_lifecycle() {
    let (_temp_dir, mut storage) = create_test_storage();

    // Create namespace
    storage.create_namespace("production").unwrap();

    // Store multiple keys
    let keys = vec![
        (KeyId::new("key1"), b"data1".to_vec()),
        (KeyId::new("key2"), b"data2".to_vec()),
        (KeyId::new("key3"), b"data3".to_vec()),
    ];

    for (key_id, data) in &keys {
        storage.store_key(key_id, data, "production").unwrap();
    }

    // Verify all keys exist
    for (key_id, _) in &keys {
        assert!(storage.key_exists(key_id, "production").unwrap());
    }

    // Load and verify data
    for (key_id, data) in &keys {
        let loaded = storage.load_key(key_id, "production").unwrap();
        assert_eq!(&loaded, data);
    }

    // List keys
    let listed = storage.list_keys("production").unwrap();
    assert_eq!(listed.len(), 3);

    // Delete a key
    storage
        .delete_key(&KeyId::new("key2"), "production")
        .unwrap();
    assert!(!storage
        .key_exists(&KeyId::new("key2"), "production")
        .unwrap());

    let listed = storage.list_keys("production").unwrap();
    assert_eq!(listed.len(), 2);

    // Delete namespace
    storage.delete_namespace("production").unwrap();
    let namespaces = storage.list_namespaces().unwrap();
    assert!(!namespaces.contains(&"production".to_string()));
}

#[test]
fn test_multiple_namespaces() {
    let (_temp_dir, mut storage) = create_test_storage();

    // Create multiple namespaces
    storage.create_namespace("production").unwrap();
    storage.create_namespace("staging").unwrap();
    storage.create_namespace("development").unwrap();

    // Store keys in different namespaces
    storage
        .store_key(&KeyId::new("key1"), b"prod-data", "production")
        .unwrap();
    storage
        .store_key(&KeyId::new("key1"), b"stage-data", "staging")
        .unwrap();
    storage
        .store_key(&KeyId::new("key1"), b"dev-data", "development")
        .unwrap();

    // Verify isolation
    let prod_data = storage.load_key(&KeyId::new("key1"), "production").unwrap();
    let stage_data = storage.load_key(&KeyId::new("key1"), "staging").unwrap();
    let dev_data = storage
        .load_key(&KeyId::new("key1"), "development")
        .unwrap();

    assert_eq!(prod_data, b"prod-data");
    assert_eq!(stage_data, b"stage-data");
    assert_eq!(dev_data, b"dev-data");

    // Delete one namespace
    storage.delete_namespace("staging").unwrap();

    // Verify others still exist
    assert!(storage.load_key(&KeyId::new("key1"), "production").is_ok());
    assert!(storage.load_key(&KeyId::new("key1"), "development").is_ok());
}

#[test]
fn test_large_key_storage() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    // Store a large key (1 MB)
    let large_data = vec![0xABu8; 1024 * 1024];
    let key_id = KeyId::new("large-key");

    storage.store_key(&key_id, &large_data, "test").unwrap();

    let loaded = storage.load_key(&key_id, "test").unwrap();
    assert_eq!(loaded, large_data);
}

#[test]
fn test_overwrite_key() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    let key_id = KeyId::new("overwrite-test");

    // Store initial data
    storage.store_key(&key_id, b"initial", "test").unwrap();
    let loaded = storage.load_key(&key_id, "test").unwrap();
    assert_eq!(loaded, b"initial");

    // Overwrite with new data
    storage.store_key(&key_id, b"updated", "test").unwrap();
    let loaded = storage.load_key(&key_id, "test").unwrap();
    assert_eq!(loaded, b"updated");
}

#[test]
fn test_empty_key_data() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    let key_id = KeyId::new("empty-key");
    storage.store_key(&key_id, b"", "test").unwrap();

    let loaded = storage.load_key(&key_id, "test").unwrap();
    assert_eq!(loaded, b"");
}

#[test]
fn test_special_characters_in_key_id() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    // Use various safe characters
    let key_ids = vec![
        KeyId::new("key-with-dashes"),
        KeyId::new("key_with_underscores"),
        KeyId::new("key.with.dots"),
        KeyId::new("key123"),
    ];

    for key_id in &key_ids {
        storage.store_key(key_id, b"test-data", "test").unwrap();
    }

    for key_id in &key_ids {
        let loaded = storage.load_key(key_id, "test").unwrap();
        assert_eq!(loaded, b"test-data");
    }
}

#[test]
fn test_concurrent_namespace_operations() {
    let (_temp_dir, mut storage) = create_test_storage();

    // Create namespaces
    storage.create_namespace("ns1").unwrap();
    storage.create_namespace("ns2").unwrap();

    // Interleave operations
    storage
        .store_key(&KeyId::new("key1"), b"ns1-data1", "ns1")
        .unwrap();
    storage
        .store_key(&KeyId::new("key1"), b"ns2-data1", "ns2")
        .unwrap();
    storage
        .store_key(&KeyId::new("key2"), b"ns1-data2", "ns1")
        .unwrap();
    storage
        .store_key(&KeyId::new("key2"), b"ns2-data2", "ns2")
        .unwrap();

    // Verify all data
    assert_eq!(
        storage.load_key(&KeyId::new("key1"), "ns1").unwrap(),
        b"ns1-data1"
    );
    assert_eq!(
        storage.load_key(&KeyId::new("key1"), "ns2").unwrap(),
        b"ns2-data1"
    );
    assert_eq!(
        storage.load_key(&KeyId::new("key2"), "ns1").unwrap(),
        b"ns1-data2"
    );
    assert_eq!(
        storage.load_key(&KeyId::new("key2"), "ns2").unwrap(),
        b"ns2-data2"
    );
}

#[test]
fn test_sync_operation() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    // Store multiple keys
    for i in 0..10 {
        storage
            .store_key(
                &KeyId::new(format!("key{}", i)),
                format!("data{}", i).as_bytes(),
                "test",
            )
            .unwrap();
    }

    // Sync should succeed
    assert!(storage.sync().is_ok());

    // Verify all keys are still accessible
    for i in 0..10 {
        let loaded = storage
            .load_key(&KeyId::new(format!("key{}", i)), "test")
            .unwrap();
        assert_eq!(loaded, format!("data{}", i).as_bytes());
    }
}

#[test]
fn test_reopen_storage() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().to_path_buf();
    let kek = [99u8; 32];

    // Create and populate storage
    {
        let mut storage =
            EncryptedFileStorage::create_with_new_key(base_path.clone(), &kek).unwrap();
        storage.create_namespace("persistent").unwrap();

        for i in 0..5 {
            storage
                .store_key(
                    &KeyId::new(format!("key{}", i)),
                    format!("data{}", i).as_bytes(),
                    "persistent",
                )
                .unwrap();
        }
    }

    // Reopen and verify
    {
        let storage = EncryptedFileStorage::open(base_path, &kek).unwrap();

        let namespaces = storage.list_namespaces().unwrap();
        assert!(namespaces.contains(&"persistent".to_string()));

        let keys = storage.list_keys("persistent").unwrap();
        assert_eq!(keys.len(), 5);

        for i in 0..5 {
            let loaded = storage
                .load_key(&KeyId::new(format!("key{}", i)), "persistent")
                .unwrap();
            assert_eq!(loaded, format!("data{}", i).as_bytes());
        }
    }
}

#[test]
fn test_wrong_kek() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().to_path_buf();
    let kek1 = [42u8; 32];
    let kek2 = [99u8; 32];

    // Create storage with kek1
    {
        let _storage = EncryptedFileStorage::create_with_new_key(base_path.clone(), &kek1).unwrap();
    }

    // Try to open with kek2 (should fail)
    let result = EncryptedFileStorage::open(base_path, &kek2);
    assert!(result.is_err());
}

#[test]
fn test_list_empty_namespace() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("empty").unwrap();

    let keys = storage.list_keys("empty").unwrap();
    assert_eq!(keys.len(), 0);
}

#[test]
fn test_delete_nonexistent_key() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    let result = storage.delete_key(&KeyId::new("nonexistent"), "test");
    assert!(result.is_err());
}

#[test]
fn test_create_duplicate_namespace() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();
    let result = storage.create_namespace("test");
    assert!(result.is_err());
}

#[test]
fn test_delete_nonexistent_namespace() {
    let (_temp_dir, mut storage) = create_test_storage();

    let result = storage.delete_namespace("nonexistent");
    assert!(result.is_err());
}
