//! Property-based tests for backup module using proptest.

use backup::*;
use proptest::prelude::*;

// Property: Export then import should recover original data
proptest! {
    #[test]
    fn prop_export_import_roundtrip(
        data in prop::collection::vec(any::<u8>(), 1..10000),
        password in prop::collection::vec(any::<u8>(), 16..64),
    ) {
        let exporter = export::KeyExporter::new();
        let importer = import::KeyImporter::new();

        let backup = exporter.export_keys(&data, &password, None).unwrap();
        let imported = importer.import_keys(&backup, &password).unwrap();

        prop_assert_eq!(&imported.data, &data);
    }
}

// Property: Compression then decompression should recover original data
proptest! {
    #[test]
    fn prop_compression_roundtrip(
        data in prop::collection::vec(any::<u8>(), 1..100000),
    ) {
        let manager = compression::CompressionManager::default();

        let compressed = manager.compress(&data).unwrap();
        let decompressed = manager.decompress(&compressed.data).unwrap();

        prop_assert_eq!(decompressed, data);
    }
}

// Property: Shamir's Secret Sharing recovery with threshold shares
proptest! {
    #[test]
    fn prop_shamir_recovery(
        secret in prop::collection::vec(any::<u8>(), 1..1000),
        threshold in 2u8..10u8,
    ) {
        let share_count = threshold + 5; // Always more shares than threshold

        let config = shamir::ShamirConfig::new(threshold, share_count).unwrap();
        let shamir = shamir::ShamirSecretSharing::new(config);

        let shares = shamir.split_secret(&secret).unwrap();
        prop_assert_eq!(shares.len(), share_count as usize);

        // Test recovery with exactly threshold shares
        let recovery_shares = &shares[..threshold as usize];
        let recovered = shamir.recover_secret(recovery_shares).unwrap();

        prop_assert_eq!(recovered, secret);
    }
}

// Property: Any subset of threshold shares should recover the same secret
proptest! {
    #[test]
    fn prop_shamir_any_subset(
        secret in prop::collection::vec(any::<u8>(), 32..33), // Fixed size for efficiency
    ) {
        let threshold = 3u8;
        let share_count = 7u8;

        let config = shamir::ShamirConfig::new(threshold, share_count).unwrap();
        let shamir = shamir::ShamirSecretSharing::new(config);

        let shares = shamir.split_secret(&secret).unwrap();

        // Test multiple combinations
        let subset1 = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
        let subset2 = vec![shares[0].clone(), shares[3].clone(), shares[6].clone()];
        let subset3 = vec![shares[2].clone(), shares[4].clone(), shares[5].clone()];

        let recovered1 = shamir.recover_secret(&subset1).unwrap();
        let recovered2 = shamir.recover_secret(&subset2).unwrap();
        let recovered3 = shamir.recover_secret(&subset3).unwrap();

        prop_assert_eq!(&recovered1, &secret);
        prop_assert_eq!(&recovered2, &secret);
        prop_assert_eq!(&recovered3, &secret);
    }
}

// Property: Integrity verification should detect tampering
proptest! {
    #[test]
    fn prop_integrity_detects_tampering(
        data in prop::collection::vec(any::<u8>(), 1..10000),
        tamper_index in 0usize..1000,
    ) {
        let key = integrity::IntegrityManager::generate_key();
        let manager = integrity::IntegrityManager::new(key).unwrap();

        let mut verified = manager.create_verified(&data).unwrap();

        // Verify original is valid
        prop_assert!(manager.verify(&verified).is_ok());

        // Tamper with data
        if tamper_index < verified.data.len() {
            verified.data[tamper_index] ^= 0xFF;

            // Verification should fail
            prop_assert!(manager.verify(&verified).is_err());
        }
    }
}

// Property: HMAC tags should be deterministic for same data
proptest! {
    #[test]
    fn prop_hmac_deterministic(
        data in prop::collection::vec(any::<u8>(), 1..10000),
    ) {
        let key = integrity::IntegrityManager::generate_key();
        let manager = integrity::IntegrityManager::new(key).unwrap();

        let tag1 = manager.tag_bytes(&data).unwrap();
        let tag2 = manager.tag_bytes(&data).unwrap();

        prop_assert_eq!(tag1, tag2);
    }
}

// Property: Parallel processing should give same results as sequential
proptest! {
    #[test]
    fn prop_parallel_correctness(
        num_keys in 1usize..100,
    ) {
        let processor = parallel::ParallelProcessor::default();

        let keys: Vec<_> = (0..num_keys)
            .map(|i| parallel::ParallelKey {
                id: format!("key_{}", i),
                data: vec![(i % 10) as u8; 10],  // Use modulo to prevent overflow
            })
            .collect();

        // Process in parallel
        let parallel_results = processor.process_keys(keys.clone(), |key| {
            Ok(key.data.len())  // Use length instead of sum to avoid overflow
        }).unwrap();

        // Process sequentially
        let sequential_results: Vec<usize> = keys.iter()
            .map(|key| key.data.len())
            .collect();

        prop_assert_eq!(parallel_results, sequential_results);
    }
}

// Property: Incremental backup restore should have all keys from chain
proptest! {
    #[test]
    fn prop_incremental_restore_completeness(
        num_full_keys in 10usize..50,
        num_incremental_keys in 1usize..20,
    ) {
        let manager = incremental::IncrementalBackupManager::new();

        // Create full backup
        let mut full_backup = incremental::IncrementalBackup::new_full("backup1".to_string());
        for i in 0..num_full_keys {
            full_backup.add_key(incremental::KeyEntry {
                id: format!("key_{}", i),
                data: vec![i as u8; 10],
                modified_at: 1000,
            });
        }

        // Create incremental backup
        let mut inc_backup = incremental::IncrementalBackup::new_incremental(
            "backup2".to_string(),
            "backup1".to_string(),
        );
        for i in 0..num_incremental_keys {
            inc_backup.add_key(incremental::KeyEntry {
                id: format!("new_key_{}", i),
                data: vec![i as u8; 10],
                modified_at: 2000,
            });
        }

        let chain = vec![full_backup, inc_backup];
        let restored = manager.restore_from_chain(&chain).unwrap();

        // Should have all keys
        prop_assert_eq!(restored.len(), num_full_keys + num_incremental_keys);
    }
}

// Property: Compression should reduce size for repetitive data
proptest! {
    #[test]
    fn prop_compression_reduces_repetitive_data(
        byte_value in any::<u8>(),
        count in 100usize..10000,
    ) {
        let manager = compression::CompressionManager::default();
        let data = vec![byte_value; count];

        let compressed = manager.compress(&data).unwrap();

        // Repetitive data should compress to less than 50% of original
        prop_assert!(compressed.compression_ratio() > 0.5);
    }
}

// Property: Wrong password should always fail import
proptest! {
    #[test]
    fn prop_wrong_password_fails(
        data in prop::collection::vec(any::<u8>(), 1..1000),
        correct_password in prop::collection::vec(any::<u8>(), 16..64),
        wrong_password in prop::collection::vec(any::<u8>(), 16..64),
    ) {
        // Skip if passwords are the same
        if correct_password == wrong_password {
            return Ok(());
        }

        let exporter = export::KeyExporter::new();
        let importer = import::KeyImporter::new();

        let backup = exporter.export_keys(&data, &correct_password, None).unwrap();

        // Wrong password should fail
        let result = importer.import_keys(&backup, &wrong_password);
        prop_assert!(result.is_err());
    }
}

// Property: Backup verification should pass for valid backups
proptest! {
    #[test]
    fn prop_backup_verification(
        data in prop::collection::vec(any::<u8>(), 1..1000),
        password in prop::collection::vec(any::<u8>(), 16..64),
    ) {
        let exporter = export::KeyExporter::new();
        let verifier = verification::BackupVerifier::new();

        let backup = exporter.export_keys(&data, &password, None).unwrap();

        let result = verifier.verify_backup(&backup);
        prop_assert!(result.is_valid);
    }
}

// Property: Health check should pass for valid backups
proptest! {
    #[test]
    fn prop_health_check_valid_backups(
        data in prop::collection::vec(any::<u8>(), 1..1000),
        password in prop::collection::vec(any::<u8>(), 16..64),
    ) {
        let exporter = export::KeyExporter::new();
        let checker = health::BackupHealthChecker::new();

        let backup = exporter.export_keys(&data, &password, None).unwrap();

        let health = checker.check_backup_health(&backup, &password);
        prop_assert!(health.is_healthy());
    }
}

// Property: Shamir shares should be unique
proptest! {
    #[test]
    fn prop_shamir_shares_unique(
        secret in prop::collection::vec(any::<u8>(), 32..33),
    ) {
        let config = shamir::ShamirConfig::new(3, 5).unwrap();
        let shamir = shamir::ShamirSecretSharing::new(config);

        let shares = shamir.split_secret(&secret).unwrap();

        // All shares should be different
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                prop_assert_ne!(&shares[i].data, &shares[j].data);
                prop_assert_ne!(shares[i].index, shares[j].index);
            }
        }
    }
}

// Property: Insufficient shares should fail recovery
proptest! {
    #[test]
    fn prop_shamir_insufficient_shares_fails(
        secret in prop::collection::vec(any::<u8>(), 32..33),
    ) {
        let threshold = 5u8;
        let share_count = 10u8;

        let config = shamir::ShamirConfig::new(threshold, share_count).unwrap();
        let shamir = shamir::ShamirSecretSharing::new(config);

        let shares = shamir.split_secret(&secret).unwrap();

        // Try with fewer than threshold shares
        let insufficient = &shares[..(threshold - 1) as usize];
        let result = shamir.recover_secret(insufficient);

        prop_assert!(result.is_err());
    }
}
