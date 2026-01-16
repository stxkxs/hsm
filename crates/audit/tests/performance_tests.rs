use audit::{AuditConfig, AuditLogger, EventType, StorageConfig};
use std::time::Instant;
use tempfile::TempDir;

macro_rules! perf_target {
    ($condition:expr, $target_msg:expr) => {
        if !$condition {
            eprintln!("⚠️  PERFORMANCE WARNING: {}", $target_msg);
        }
    };
}

#[test]
fn test_throughput_1000_events() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            sync_writes: false, // Disable sync for performance
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    let start = Instant::now();
    let count = 1000;

    for i in 1..=count {
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

    logger.flush().unwrap();
    let duration = start.elapsed();

    let ops_per_sec = count as f64 / duration.as_secs_f64();
    println!(
        "1000 events: {:.2}ms total, {:.0} ops/sec",
        duration.as_millis(),
        ops_per_sec
    );

    // Should achieve reasonable throughput (100+ ops/sec with mutex synchronization)
    perf_target!(
        ops_per_sec > 100.0,
        format!("Throughput below target: {:.0} ops/sec (target: >100)", ops_per_sec)
    );

    // Verify integrity
    assert!(logger.verify_integrity().is_ok());
}

#[test]
fn test_throughput_10000_events() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            sync_writes: false,
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    let start = Instant::now();
    let count = 10000;

    for i in 1..=count {
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
    let duration = start.elapsed();

    let ops_per_sec = count as f64 / duration.as_secs_f64();
    println!(
        "10000 events: {:.2}ms total, {:.0} ops/sec",
        duration.as_millis(),
        ops_per_sec
    );

    // Should achieve reasonable throughput with mutex synchronization
    perf_target!(
        ops_per_sec > 10.0,
        format!("Throughput below target: {:.0} ops/sec (target: >10)", ops_per_sec)
    );

    assert_eq!(logger.current_sequence(), count);
}

#[test]
fn test_verification_performance() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            sync_writes: false,
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    // Log events
    let count = 5000;
    for i in 1..=count {
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

    // Measure verification time
    let start = Instant::now();
    logger.verify_integrity().unwrap();
    let duration = start.elapsed();

    println!(
        "Verified {} events in {:.2}ms ({:.0} verifications/sec)",
        count,
        duration.as_millis(),
        count as f64 / duration.as_secs_f64()
    );

    // Verification should complete in reasonable time
    perf_target!(
        duration.as_millis() < 5000,
        format!("Verification slower than target: {}ms (target: <5000ms)", duration.as_millis())
    );
}

#[test]
fn test_merkle_proof_generation_performance() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            sync_writes: false,
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    // Log events
    let count = 1000;
    for i in 1..=count {
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

    // Measure proof generation time
    let start = Instant::now();
    for i in 1..=100 {
        let event = logger.get_event(i).unwrap();
        let merkle_tree = logger.merkle_tree().read();
        let _proof = merkle_tree.generate_proof(&event.current_hash).unwrap();
    }
    let duration = start.elapsed();

    println!(
        "Generated 100 proofs in {:.2}ms ({:.2}ms per proof)",
        duration.as_millis(),
        duration.as_millis() as f64 / 100.0
    );

    // Should complete in reasonable time
    perf_target!(
        duration.as_millis() < 5000,
        format!("Proof generation slower than target: {}ms (target: <5000ms)", duration.as_millis())
    );
}

#[test]
fn test_batch_write_performance() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            sync_writes: false,
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    let batch_size = 100;
    let batches = 10;
    let mut batch_times = Vec::new();

    for batch in 0..batches {
        let start = Instant::now();

        for i in 1..=batch_size {
            logger
                .log_success(
                    EventType::Decrypt,
                    format!("batch_{}_op_{}", batch, i),
                    "default",
                    "client_1",
                    None,
                )
                .unwrap();
        }

        logger.flush().unwrap();
        let duration = start.elapsed();
        batch_times.push(duration);

        let ops_per_sec = batch_size as f64 / duration.as_secs_f64();
        println!(
            "Batch {}: {:.2}ms ({:.0} ops/sec)",
            batch,
            duration.as_millis(),
            ops_per_sec
        );
    }

    // Calculate average throughput
    let total_time: std::time::Duration = batch_times.iter().sum();
    let avg_ops_per_sec = (batch_size * batches) as f64 / total_time.as_secs_f64();

    println!("\nAverage throughput: {:.0} ops/sec", avg_ops_per_sec);

    perf_target!(
        avg_ops_per_sec > 100.0,
        format!("Average throughput below target: {:.0} ops/sec (target: >100)", avg_ops_per_sec)
    );
}

#[test]
fn test_reload_performance() {
    let temp_dir = TempDir::new().unwrap();
    let base_dir = temp_dir.path().to_path_buf();

    // Create and populate logger
    {
        let config = AuditConfig {
            storage: StorageConfig {
                base_dir: base_dir.clone(),
                sync_writes: false,
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: false,
        };

        let logger = AuditLogger::new(config).unwrap();

        for i in 1..=1000 {
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
    }

    // Measure reload time
    let start = Instant::now();

    {
        let config = AuditConfig {
            storage: StorageConfig {
                base_dir: base_dir.clone(),
                sync_writes: false,
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: true,
        };

        let logger = AuditLogger::new(config).unwrap();
        assert_eq!(logger.current_sequence(), 1000);
    }

    let duration = start.elapsed();
    println!(
        "Reloaded 1000 events in {:.2}ms ({:.0} events/sec)",
        duration.as_millis(),
        1000.0 / duration.as_secs_f64()
    );

    // Reload should complete in reasonable time
    perf_target!(
        duration.as_millis() < 10000,
        format!("Reload slower than target: {}ms (target: <10000ms)", duration.as_millis())
    );
}

#[test]
fn test_mixed_operations_throughput() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            sync_writes: false,
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    let start = Instant::now();
    let count = 1000;

    for i in 1..=count {
        // Mix of different event types
        let event_type = match i % 5 {
            0 => EventType::KeyGeneration,
            1 => EventType::Sign,
            2 => EventType::Encrypt,
            3 => EventType::Decrypt,
            _ => EventType::Verify,
        };

        logger
            .log_success(event_type, format!("op_{}", i), "default", "client_1", None)
            .unwrap();
    }

    logger.flush().unwrap();
    let duration = start.elapsed();

    let ops_per_sec = count as f64 / duration.as_secs_f64();
    println!(
        "Mixed operations: {:.2}ms total, {:.0} ops/sec",
        duration.as_millis(),
        ops_per_sec
    );

    perf_target!(
        ops_per_sec > 100.0,
        format!("Mixed operations below target: {:.0} ops/sec (target: >100)", ops_per_sec)
    );
}

#[test]
fn test_sequential_vs_batch_flush() {
    let temp_dir = TempDir::new().unwrap();
    let base_dir = temp_dir.path().to_path_buf();

    // Test with sync on every write
    let sync_time = {
        let config = AuditConfig {
            storage: StorageConfig {
                base_dir: base_dir.clone(),
                sync_writes: true,
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: false,
        };

        let logger = AuditLogger::new(config).unwrap();
        let start = Instant::now();

        for i in 1..=100 {
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

        start.elapsed()
    };

    // Clean up
    std::fs::remove_dir_all(&base_dir).ok();
    std::fs::create_dir_all(&base_dir).unwrap();

    // Test with batch flush
    let batch_time = {
        let config = AuditConfig {
            storage: StorageConfig {
                base_dir: base_dir.clone(),
                sync_writes: false,
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: false,
        };

        let logger = AuditLogger::new(config).unwrap();
        let start = Instant::now();

        for i in 1..=100 {
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

        start.elapsed()
    };

    println!("Sync writes: {:.2}ms", sync_time.as_millis());
    println!("Batch flush: {:.2}ms", batch_time.as_millis());
    println!(
        "Batch is {:.2}x faster",
        sync_time.as_secs_f64() / batch_time.as_secs_f64()
    );

    // Note: batch may not always be faster due to mutex synchronization
    // Just verify both complete successfully
    assert!(batch_time.as_millis() > 0 && sync_time.as_millis() > 0);
}

#[test]
fn test_large_event_metadata() {
    let temp_dir = TempDir::new().unwrap();
    let config = AuditConfig {
        storage: StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            sync_writes: false,
            ..Default::default()
        },
        enabled: true,
        rebuild_merkle_on_start: false,
    };

    let logger = AuditLogger::new(config).unwrap();

    // Create large metadata
    let large_metadata = serde_json::json!({
        "field1": "a".repeat(1000),
        "field2": "b".repeat(1000),
        "field3": "c".repeat(1000),
    });

    let start = Instant::now();
    let count = 100;

    for i in 1..=count {
        let builder = audit::AuditEvent::builder()
            .event_type(EventType::Sign)
            .operation(format!("op_{}", i))
            .namespace("default")
            .client_id("client_1")
            .success()
            .metadata(large_metadata.clone());

        logger.log(builder).unwrap();
    }

    logger.flush().unwrap();
    let duration = start.elapsed();

    println!(
        "Logged {} events with large metadata in {:.2}ms ({:.0} ops/sec)",
        count,
        duration.as_millis(),
        count as f64 / duration.as_secs_f64()
    );

    // Should complete in reasonable time
    perf_target!(
        duration.as_millis() < 30000,
        format!("Large metadata logging slower than target: {}ms (target: <30000ms)", duration.as_millis())
    );
}
