//! Integration tests for export and import functionality.

use backup::{BackupError, KeyExporter, KeyImporter};

#[test]
fn test_export_import_roundtrip() {
    let exporter = KeyExporter::new();
    let importer = KeyImporter::new();

    let original_data = b"this_is_my_secret_key_data_12345";
    let password = b"very_strong_password_here_123";
    let namespace = "production";

    // Export the data
    let backup = exporter
        .export_keys(original_data, password, Some(namespace.to_string()))
        .expect("Failed to export keys");

    // Verify backup properties
    assert_eq!(backup.version, 1);
    assert_eq!(backup.namespace, Some(namespace.to_string()));
    assert!(backup.encrypted_data.len() > 0);
    assert!(backup.nonce.len() == 12);

    // Import the data
    let imported = importer
        .import_keys(&backup, password)
        .expect("Failed to import keys");

    // Verify imported data
    assert_eq!(imported.data, original_data);
    assert_eq!(imported.namespace, Some(namespace.to_string()));
    assert_eq!(imported.key_count, 1);
}

#[test]
fn test_export_import_json_format() {
    let exporter = KeyExporter::new();
    let importer = KeyImporter::new();

    let data = b"json_test_data";
    let password = b"password12345678";

    // Export to JSON
    let json = exporter
        .export_to_json(data, password, None)
        .expect("Failed to export to JSON");

    // Verify it's valid JSON
    let backup_check: serde_json::Value = serde_json::from_slice(&json).expect("Invalid JSON");
    assert!(backup_check.get("version").is_some());
    assert!(backup_check.get("encrypted_data").is_some());

    // Import from JSON
    let imported = importer
        .import_from_json(&json, password)
        .expect("Failed to import from JSON");

    assert_eq!(imported.data, data);
}

#[test]
fn test_wrong_password_import() {
    let exporter = KeyExporter::new();
    let importer = KeyImporter::new();

    let backup = exporter
        .export_keys(b"secret", b"correct_password", None)
        .unwrap();

    let result = importer.import_keys(&backup, b"wrong_password");

    assert!(matches!(result, Err(BackupError::InvalidPassword)));
}

#[test]
fn test_empty_data_export() {
    let exporter = KeyExporter::new();

    let result = exporter.export_keys(&[], b"test-password-1234", None);

    assert!(matches!(result, Err(BackupError::EmptyData)));
}

#[test]
fn test_empty_password_export() {
    let exporter = KeyExporter::new();

    let result = exporter.export_keys(b"data", &[], None);

    assert!(matches!(result, Err(BackupError::WeakPassword)));
}

#[test]
fn test_password_verification() {
    let exporter = KeyExporter::new();
    let importer = KeyImporter::new();

    let password = b"test_password_123";
    let backup = exporter.export_keys(b"data", password, None).unwrap();

    // Correct password
    assert!(importer.check_password(&backup, password).unwrap());

    // Wrong password
    assert!(!importer.check_password(&backup, b"wrong").unwrap());
}

#[test]
fn test_backup_integrity_check() {
    let exporter = KeyExporter::new();
    let importer = KeyImporter::new();

    let backup = exporter
        .export_keys(b"test_data", b"test-password-1234", None)
        .unwrap();

    // Verify backup structure
    assert!(importer.verify_backup(&backup).is_ok());
}

#[test]
fn test_large_data_export_import() {
    let exporter = KeyExporter::new();
    let importer = KeyImporter::new();

    // Create 1MB of data
    let large_data = vec![0x42u8; 1024 * 1024];
    let password = b"test-password-1234";

    let backup = exporter
        .export_keys(&large_data, password, None)
        .expect("Failed to export large data");

    let imported = importer
        .import_keys(&backup, password)
        .expect("Failed to import large data");

    assert_eq!(imported.data, large_data);
}

#[test]
fn test_multiple_export_import_cycles() {
    let exporter = KeyExporter::new();
    let importer = KeyImporter::new();

    let mut data = b"initial_data".to_vec();
    let password = b"test-password-1234";

    for i in 0..5 {
        // Export
        let backup = exporter
            .export_keys(&data, password, Some(format!("cycle_{}", i)))
            .unwrap();

        // Import
        let imported = importer.import_keys(&backup, password).unwrap();

        assert_eq!(imported.data, data);

        // Modify data for next cycle
        data.push(i as u8);
    }
}

#[test]
fn test_metadata_preservation() {
    let exporter = KeyExporter::new();
    let importer = KeyImporter::new();

    let data = b"test_data";
    let password = b"test-password-1234";
    let namespace = "test_namespace";

    let backup = exporter
        .export_keys(data, password, Some(namespace.to_string()))
        .unwrap();

    assert_eq!(backup.namespace, Some(namespace.to_string()));
    assert!(backup.timestamp > 0);
    assert_eq!(
        backup.metadata.get("algorithm"),
        Some(&"AES-256-GCM".to_string())
    );

    let imported = importer.import_keys(&backup, password).unwrap();

    assert_eq!(imported.namespace, Some(namespace.to_string()));
    assert_eq!(imported.timestamp, backup.timestamp);
}

#[test]
fn test_concurrent_exports() {
    use std::sync::Arc;
    use std::thread;

    let exporter = Arc::new(KeyExporter::new());
    let mut handles = vec![];

    for i in 0..10 {
        let exporter = Arc::clone(&exporter);
        let handle = thread::spawn(move || {
            let data = format!("data_{}", i);
            let password = format!("test-password-{:04}", i);

            exporter
                .export_keys(data.as_bytes(), password.as_bytes(), None)
                .unwrap()
        });
        handles.push(handle);
    }

    for handle in handles {
        let backup = handle.join().unwrap();
        assert!(backup.encrypted_data.len() > 0);
    }
}

#[test]
fn test_invalid_json_import() {
    let importer = KeyImporter::new();

    let invalid_json = b"{this is not valid json}";
    let result = importer.import_from_json(invalid_json, b"test-password-1234");

    assert!(matches!(result, Err(BackupError::Deserialization(_))));
}

#[test]
fn test_serialization_deserialization() {
    let exporter = KeyExporter::new();

    let backup = exporter
        .export_keys(b"test", b"test-password-1234", None)
        .unwrap();

    let json = exporter.serialize_backup(&backup).unwrap();

    // Deserialize and verify
    let deserialized: backup::EncryptedBackup = serde_json::from_slice(&json).unwrap();

    assert_eq!(deserialized.version, backup.version);
    assert_eq!(deserialized.encrypted_data, backup.encrypted_data);
    assert_eq!(deserialized.nonce, backup.nonce);
}
