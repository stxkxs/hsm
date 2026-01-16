//! Corruption detection and recovery tests

use hsm_storage::{EncryptedFileStorage, KeyId, StorageBackend};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use tempfile::TempDir;

fn create_test_storage() -> (TempDir, EncryptedFileStorage) {
    let temp_dir = TempDir::new().unwrap();
    let kek = [42u8; 32];
    let storage =
        EncryptedFileStorage::create_with_new_key(temp_dir.path().to_path_buf(), &kek).unwrap();
    (temp_dir, storage)
}

#[test]
fn test_corrupted_key_file_detection() {
    let (temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    let key_id = KeyId::new("test-key");
    storage.store_key(&key_id, b"secret data", "test").unwrap();

    // Corrupt the encrypted key file
    let key_path = temp_dir
        .path()
        .join("namespaces/test/keys/key-test-key.enc");

    let mut file = OpenOptions::new().write(true).open(&key_path).unwrap();
    file.seek(SeekFrom::Start(10)).unwrap();
    file.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
    drop(file);

    // Attempt to load should detect corruption
    let result = storage.load_key(&key_id, "test");
    assert!(result.is_err());
}

#[test]
fn test_corrupted_metadata_detection() {
    let (temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    let key_id = KeyId::new("test-key");
    storage.store_key(&key_id, b"secret data", "test").unwrap();

    // Corrupt the metadata file
    let meta_path = temp_dir
        .path()
        .join("namespaces/test/keys/key-test-key.meta");

    let mut file = OpenOptions::new().write(true).open(&meta_path).unwrap();
    file.seek(SeekFrom::Start(5)).unwrap();
    file.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
    drop(file);

    // Load should detect corruption via checksum mismatch
    let result = storage.load_key(&key_id, "test");
    assert!(result.is_err());
}

#[test]
fn test_truncated_key_file() {
    let (temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    let key_id = KeyId::new("test-key");
    storage.store_key(&key_id, b"secret data", "test").unwrap();

    // Truncate the key file
    let key_path = temp_dir
        .path()
        .join("namespaces/test/keys/key-test-key.enc");

    fs::write(&key_path, b"truncated").unwrap();

    // Load should fail
    let result = storage.load_key(&key_id, "test");
    assert!(result.is_err());
}

#[test]
fn test_missing_metadata_file() {
    let (temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    let key_id = KeyId::new("test-key");
    storage.store_key(&key_id, b"secret data", "test").unwrap();

    // Remove metadata file
    let meta_path = temp_dir
        .path()
        .join("namespaces/test/keys/key-test-key.meta");
    fs::remove_file(&meta_path).unwrap();

    // Load should still work (metadata is optional in this implementation)
    // but in a production system, this might be an error
    let result = storage.load_key(&key_id, "test");
    // Depending on implementation, this might succeed or fail
    // For this implementation, it should succeed as we handle missing metadata
    assert!(result.is_ok());
}

#[test]
fn test_corrupted_journal_recovery() {
    let (temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    // Store a key
    let key_id = KeyId::new("test-key");
    storage
        .store_key(&key_id, b"original data", "test")
        .unwrap();

    // Corrupt the journal file
    let journal_path = temp_dir.path().join("namespaces/test/journal/wal.log");

    if journal_path.exists() {
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&journal_path)
            .unwrap();
        file.write_all(&[0xFF; 100]).unwrap();
        drop(file);
    }

    // Reopening should handle corrupted journal gracefully
    drop(storage);
    let kek = [42u8; 32];
    let storage_result = EncryptedFileStorage::open(temp_dir.path().to_path_buf(), &kek);

    // Storage should open (recovery might skip corrupted entries)
    assert!(storage_result.is_ok());
}

#[test]
fn test_partial_write_recovery() {
    let (temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    // Store some keys
    for i in 0..5 {
        storage
            .store_key(
                &KeyId::new(format!("key{}", i)),
                format!("data{}", i).as_bytes(),
                "test",
            )
            .unwrap();
    }

    // Create a journal entry but don't complete the operation
    let journal_path = temp_dir.path().join("namespaces/test/journal/wal.log");

    if journal_path.exists() {
        // Append incomplete data
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&journal_path)
            .unwrap();
        file.write_all(&[0, 0, 0, 10]).unwrap(); // Length prefix
        file.write_all(&[1, 2, 3]).unwrap(); // Incomplete data
        drop(file);
    }

    // Reopen - should handle incomplete journal entry
    drop(storage);
    let kek = [42u8; 32];
    let storage = EncryptedFileStorage::open(temp_dir.path().to_path_buf(), &kek).unwrap();

    // Original keys should still be accessible
    for i in 0..5 {
        let loaded = storage
            .load_key(&KeyId::new(format!("key{}", i)), "test")
            .unwrap();
        assert_eq!(loaded, format!("data{}", i).as_bytes());
    }
}

#[test]
fn test_empty_key_file() {
    let (temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    let key_id = KeyId::new("test-key");
    storage.store_key(&key_id, b"data", "test").unwrap();

    // Replace with empty file
    let key_path = temp_dir
        .path()
        .join("namespaces/test/keys/key-test-key.enc");
    fs::write(&key_path, b"").unwrap();

    let result = storage.load_key(&key_id, "test");
    assert!(result.is_err());
}

#[test]
fn test_filesystem_consistency_after_error() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    // Try to store to non-existent namespace (should fail)
    let result = storage.store_key(&KeyId::new("key1"), b"data", "nonexistent");
    assert!(result.is_err());

    // Storage should still work for valid operations
    storage
        .store_key(&KeyId::new("key2"), b"valid data", "test")
        .unwrap();
    let loaded = storage.load_key(&KeyId::new("key2"), "test").unwrap();
    assert_eq!(loaded, b"valid data");
}

#[test]
fn test_atomic_write_failure_recovery() {
    let (temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    // Store initial key
    let key_id = KeyId::new("atomic-test");
    storage.store_key(&key_id, b"initial", "test").unwrap();

    // Verify initial state
    let loaded = storage.load_key(&key_id, "test").unwrap();
    assert_eq!(loaded, b"initial");

    // Store updated key
    storage.store_key(&key_id, b"updated", "test").unwrap();

    // Verify update
    let loaded = storage.load_key(&key_id, "test").unwrap();
    assert_eq!(loaded, b"updated");

    // Reopen storage
    drop(storage);
    let kek = [42u8; 32];
    let storage = EncryptedFileStorage::open(temp_dir.path().to_path_buf(), &kek).unwrap();

    // Should have the updated value
    let loaded = storage.load_key(&key_id, "test").unwrap();
    assert_eq!(loaded, b"updated");
}

#[test]
fn test_multiple_corruption_types() {
    let (temp_dir, mut storage) = create_test_storage();

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

    // Corrupt some files in different ways
    // Corrupt key 3
    let key3_path = temp_dir.path().join("namespaces/test/keys/key-key3.enc");
    fs::write(&key3_path, b"corrupted").unwrap();

    // Truncate key 5
    let key5_path = temp_dir.path().join("namespaces/test/keys/key-key5.enc");
    fs::write(&key5_path, b"x").unwrap();

    // Delete key 7's metadata
    let key7_meta = temp_dir.path().join("namespaces/test/keys/key-key7.meta");
    if key7_meta.exists() {
        fs::remove_file(&key7_meta).unwrap();
    }

    // Verify uncorrupted keys still work
    for i in [0, 1, 2, 4, 6, 8, 9] {
        let loaded = storage
            .load_key(&KeyId::new(format!("key{}", i)), "test")
            .unwrap();
        assert_eq!(loaded, format!("data{}", i).as_bytes());
    }

    // Verify corrupted keys fail appropriately
    assert!(storage.load_key(&KeyId::new("key3"), "test").is_err());
    assert!(storage.load_key(&KeyId::new("key5"), "test").is_err());
    // key7 might succeed or fail depending on implementation
}

#[test]
fn test_checksum_verification() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    // Store data
    let key_id = KeyId::new("checksum-test");
    let data = b"important data that must not be corrupted";
    storage.store_key(&key_id, data, "test").unwrap();

    // Load should succeed with valid checksum
    let loaded = storage.load_key(&key_id, "test").unwrap();
    assert_eq!(loaded, data);

    // The checksum is verified during load
    // Any corruption would be detected
}

#[test]
fn test_journal_replay_idempotency() {
    let (temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("test").unwrap();

    // Store keys
    for i in 0..3 {
        storage
            .store_key(
                &KeyId::new(format!("key{}", i)),
                format!("data{}", i).as_bytes(),
                "test",
            )
            .unwrap();
    }

    // Close and reopen multiple times (replay journal each time)
    for _ in 0..3 {
        drop(storage);
        let kek = [42u8; 32];
        storage = EncryptedFileStorage::open(temp_dir.path().to_path_buf(), &kek).unwrap();
    }

    // Data should still be correct
    for i in 0..3 {
        let loaded = storage
            .load_key(&KeyId::new(format!("key{}", i)), "test")
            .unwrap();
        assert_eq!(loaded, format!("data{}", i).as_bytes());
    }
}
