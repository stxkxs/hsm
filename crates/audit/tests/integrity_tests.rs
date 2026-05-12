use hsm_audit::{
    AuditConfig, AuditLogger, AuditVerifier, EventType, OperationResult, StorageConfig,
};
use tempfile::TempDir;

#[test]
fn test_hash_chain_integrity() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    // Log a series of events
    for i in 1..=100 {
        logger
            .log_success(
                EventType::Sign,
                format!("operation_{}", i),
                "default",
                "client_1",
                Some(format!("key_{}", i)),
            )
            .unwrap();
    }

    // Verify full chain integrity
    assert!(logger.verify_integrity().is_ok());

    // Get all events and verify chain linkage
    let events = logger.get_events_range(1, 100).unwrap();
    for i in 1..events.len() {
        assert_eq!(events[i].prev_hash, events[i - 1].current_hash);
    }
}

#[test]
fn test_tamper_detection_single_event() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    for i in 1..=10 {
        logger
            .log_success(
                EventType::Encrypt,
                format!("op_{}", i),
                "default",
                "client_1",
                None,
            )
            .unwrap();
    }

    // Get events and tamper with one
    let mut events = logger.get_events_range(1, 10).unwrap();
    let original_hash = events[5].current_hash.clone();

    // Tamper with the operation
    events[5].operation = "tampered_operation".to_string();

    // The hash should no longer match
    assert_ne!(events[5].compute_hash(), original_hash);
    assert!(!events[5].verify_hash());

    // Verification should fail
    let result = AuditVerifier::verify_events(&events).unwrap();
    assert!(!result.passed);
}

#[test]
fn test_chain_break_detection() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    for i in 1..=10 {
        logger
            .log_success(
                EventType::Decrypt,
                format!("op_{}", i),
                "default",
                "client_1",
                None,
            )
            .unwrap();
    }

    let mut events = logger.get_events_range(1, 10).unwrap();

    // Break the chain by modifying prev_hash
    events[5].prev_hash = "0".repeat(64);

    // Verification should detect the broken chain
    assert!(AuditVerifier::verify_hash_chain(&events).is_err());
}

#[test]
fn test_sequence_gap_detection() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    for i in 1..=10 {
        logger
            .log_success(
                EventType::KeyGeneration,
                format!("op_{}", i),
                "default",
                "client_1",
                None,
            )
            .unwrap();
    }

    let mut events = logger.get_events_range(1, 10).unwrap();

    // Create a sequence gap
    events[5].sequence = 100;

    // Verification should detect the gap
    assert!(AuditVerifier::verify_hash_chain(&events).is_err());
}

#[test]
fn test_merkle_tree_integrity() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    // Log events
    for i in 1..=16 {
        logger
            .log_success(
                EventType::Sign,
                format!("op_{}", i),
                "default",
                "client_1",
                None,
            )
            .unwrap();
    }

    let merkle_tree = logger.merkle_tree().read();
    let root = merkle_tree.get_root().unwrap();

    // Verify each event is in the tree
    for i in 1..=16 {
        let event = logger.get_event(i).unwrap();
        assert!(merkle_tree.verify_inclusion(&event.current_hash));

        // Generate and verify proof
        let proof = merkle_tree.generate_proof(&event.current_hash).unwrap();
        assert!(proof.verify(&root));
    }
}

#[test]
fn test_merkle_root_changes_on_update() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    logger
        .log_success(EventType::Sign, "op_1", "default", "client_1", None)
        .unwrap();
    let root1 = logger.get_merkle_root().unwrap();

    logger
        .log_success(EventType::Sign, "op_2", "default", "client_1", None)
        .unwrap();
    let root2 = logger.get_merkle_root().unwrap();

    logger
        .log_success(EventType::Sign, "op_3", "default", "client_1", None)
        .unwrap();
    let root3 = logger.get_merkle_root().unwrap();

    // Each root should be different
    assert_ne!(root1, root2);
    assert_ne!(root2, root3);
    assert_ne!(root1, root3);
}

#[test]
fn test_persistence_integrity() {
    let temp_dir = TempDir::new().unwrap();
    let base_dir = temp_dir.path().to_path_buf();

    let original_root;
    let original_events;

    // Create logger and log events
    {
        let config = AuditConfig {
            storage: StorageConfig {
                base_dir: base_dir.clone(),
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: false,
        };

        let logger = AuditLogger::new(config).unwrap();

        for i in 1..=20 {
            logger
                .log_success(
                    EventType::KeyRotation,
                    format!("rotate_{}", i),
                    "default",
                    "client_1",
                    Some(format!("key_{}", i)),
                )
                .unwrap();
        }

        logger.flush().unwrap();
        original_root = logger.get_merkle_root().unwrap();
        original_events = logger.get_events_range(1, 20).unwrap();
    }

    // Reload from storage
    {
        let config = AuditConfig {
            storage: StorageConfig {
                base_dir: base_dir.clone(),
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: true,
        };

        let logger = AuditLogger::new(config).unwrap();

        assert_eq!(logger.current_sequence(), 20);
        assert!(logger.verify_integrity().is_ok());

        let reloaded_root = logger.get_merkle_root().unwrap();
        assert_eq!(original_root, reloaded_root);

        let reloaded_events = logger.get_events_range(1, 20).unwrap();

        // Verify all events are identical
        for i in 0..20 {
            assert_eq!(
                original_events[i].current_hash,
                reloaded_events[i].current_hash
            );
        }
    }
}

#[test]
fn test_verification_report() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    for i in 1..=50 {
        logger
            .log_success(
                EventType::Sign,
                format!("operation_{}", i),
                "default",
                "client_1",
                None,
            )
            .unwrap();
    }

    let events = logger.get_events_range(1, 50).unwrap();
    let report = AuditVerifier::generate_report(&events);

    assert!(report.is_valid());
    assert_eq!(report.total_events, 50);
    assert_eq!(report.hash_valid_count, 50);
    assert_eq!(report.chain_valid_count, 49); // N-1 chain links
    assert_eq!(report.sequence_valid_count, 50);
    assert!(report.all_hashes_valid);
    assert!(report.chain_intact);
    assert!(report.sequences_continuous);
    assert!(report.merkle_root.is_some());

    let summary = report.summary();
    assert!(summary.contains("Total Events: 50"));
    assert!(summary.contains("Overall: VALID"));
}

#[test]
fn test_mixed_event_types() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    // Log different types of events
    logger
        .log_success(
            EventType::KeyGeneration,
            "generate_key",
            "default",
            "client_1",
            Some("key_1".to_string()),
        )
        .unwrap();

    logger
        .log_failure(
            EventType::Authentication,
            "login",
            "default",
            "client_2",
            None,
            "Invalid credentials",
        )
        .unwrap();

    logger
        .log_success(
            EventType::Sign,
            "sign_document",
            "default",
            "client_1",
            Some("key_1".to_string()),
        )
        .unwrap();

    logger
        .log_success(
            EventType::SystemStartup,
            "system_start",
            "system",
            "system",
            None,
        )
        .unwrap();

    logger
        .log_failure(
            EventType::AccessDenied,
            "read_key",
            "default",
            "client_3",
            Some("key_1".to_string()),
            "Insufficient permissions",
        )
        .unwrap();

    assert_eq!(logger.current_sequence(), 5);
    assert!(logger.verify_integrity().is_ok());

    let events = logger.get_events_range(1, 5).unwrap();

    // Verify event types
    assert_eq!(events[0].event_type, EventType::KeyGeneration);
    assert_eq!(events[1].event_type, EventType::Authentication);
    assert_eq!(events[2].event_type, EventType::Sign);
    assert_eq!(events[3].event_type, EventType::SystemStartup);
    assert_eq!(events[4].event_type, EventType::AccessDenied);

    // Verify results
    assert_eq!(events[0].result, OperationResult::Success);
    assert!(matches!(events[1].result, OperationResult::Failure { .. }));
    assert_eq!(events[2].result, OperationResult::Success);
}

#[test]
fn test_concurrent_logging() {
    use std::sync::Arc;
    use std::thread;

    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            sync_writes: true,
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = Arc::new(AuditLogger::new(config).unwrap());
    let mut handles = vec![];

    // Spawn multiple threads logging events
    for thread_id in 0..4 {
        let logger_clone = Arc::clone(&logger);
        let handle = thread::spawn(move || {
            for i in 0..25 {
                logger_clone
                    .log_success(
                        EventType::Sign,
                        format!("thread_{}_op_{}", thread_id, i),
                        "default",
                        format!("client_{}", thread_id),
                        None,
                    )
                    .unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Should have logged 100 events
    assert_eq!(logger.current_sequence(), 100);
    assert!(logger.verify_integrity().is_ok());
}

#[test]
fn test_log_rotation_integrity() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            max_file_size: 20000, // Large enough to hold all events
            max_files: 15,
            sync_writes: true,
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    // Log enough events to trigger multiple rotations
    for i in 1..=200 {
        logger
            .log_success(
                EventType::Sign,
                format!("op_{}", i),
                "default",
                "client_1",
                None,
            )
            .unwrap();
    }

    logger.flush().unwrap();

    // Verify integrity still holds
    assert!(logger.verify_integrity().is_ok());

    // Read all events from storage (including rotated files)
    let all_events = logger.get_all_events_from_storage().unwrap();

    // Should have all events
    assert_eq!(all_events.len(), 200);

    // Verify the chain across all files
    assert!(AuditVerifier::verify_hash_chain(&all_events).is_ok());
}
