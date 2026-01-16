use audit::{
    AsyncAuditConfig, AsyncAuditLogger, AuditConfig, AuditLogger, EnhancedAuditStorage,
    EnhancedStorageConfig, EventType, StorageConfig, TamperDetector,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tempfile::TempDir;

// Synchronous logging benchmarks
fn bench_sync_logging(c: &mut Criterion) {
    let mut group = c.benchmark_group("sync_logging");

    for size in [100, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
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

                for i in 1..=size {
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
                black_box(logger.current_sequence());
            });
        });
    }

    group.finish();
}

// Asynchronous logging benchmarks
fn bench_async_logging(c: &mut Criterion) {
    let mut group = c.benchmark_group("async_logging");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    for size in [100, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.to_async(&runtime).iter(|| async move {
                let temp_dir = TempDir::new().unwrap();
                let config = AsyncAuditConfig {
                    storage: StorageConfig {
                        base_dir: temp_dir.path().to_path_buf(),
                        sync_writes: false,
                        ..Default::default()
                    },
                    enabled: true,
                    rebuild_merkle_on_start: false,
                    channel_capacity: 10000,
                    batch_size: 100,
                    ..Default::default()
                };

                let logger = AsyncAuditLogger::new(config).unwrap();

                for i in 1..=size {
                    logger
                        .log_success(
                            EventType::Sign,
                            format!("op_{}", i),
                            "default",
                            "client_1",
                            None,
                        )
                        .await
                        .unwrap();
                }

                // Wait for processing
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                logger.flush().await.unwrap();
                black_box(logger.current_sequence());
            });
        });
    }

    group.finish();
}

// Verification benchmarks
fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification");

    for size in [100, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            // Setup: create events
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

            for i in 1..=size {
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

            let events = logger.get_events_range(1, size as u64).unwrap();

            b.iter(|| {
                black_box(TamperDetector::verify_integrity(&events).unwrap());
            });
        });
    }

    group.finish();
}

// Quick verification benchmarks
fn bench_quick_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("quick_verification");

    for size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            // Setup: create events
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

            for i in 1..=size {
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

            let events = logger.get_events_range(1, size as u64).unwrap();

            b.iter(|| {
                black_box(TamperDetector::quick_verify(&events).unwrap());
            });
        });
    }

    group.finish();
}

// Enhanced storage benchmarks
fn bench_enhanced_storage(c: &mut Criterion) {
    let mut group = c.benchmark_group("enhanced_storage");

    // Test different configurations
    let configs = vec![
        ("plain", false, false),
        ("compressed", true, false),
        ("encrypted", false, true),
        ("both", true, true),
    ];

    for (name, compress, encrypt) in configs {
        group.bench_function(name, |b| {
            b.iter(|| {
                let temp_dir = TempDir::new().unwrap();
                let encryption_key = if encrypt { Some(vec![42u8; 32]) } else { None };

                let config = EnhancedStorageConfig {
                    base_dir: temp_dir.path().to_path_buf(),
                    enable_compression: compress,
                    enable_encryption: encrypt,
                    encryption_key,
                    durable_writes: false,
                    ..Default::default()
                };

                let storage = EnhancedAuditStorage::new(config).unwrap();

                // Write 1000 events
                for i in 1..=1000 {
                    let event = audit::AuditEvent::builder()
                        .sequence(i)
                        .event_type(EventType::Sign)
                        .operation("test_op")
                        .namespace("test")
                        .client_id("client_1")
                        .success()
                        .build()
                        .unwrap();

                    storage.write_event(&event).unwrap();
                }

                storage.flush().unwrap();
                black_box(storage.current_size());
            });
        });
    }

    group.finish();
}

// Merkle proof generation benchmarks
fn bench_merkle_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof");

    for tree_size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(100)); // 100 proofs per benchmark
        group.bench_with_input(
            BenchmarkId::from_parameter(tree_size),
            tree_size,
            |b, &tree_size| {
                // Setup: create logger with events
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

                for i in 1..=tree_size {
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

                b.iter(|| {
                    // Generate 100 proofs
                    for i in 1..=100 {
                        let event = logger.get_event((i % tree_size) + 1).unwrap();
                        let merkle_tree = logger.merkle_tree().read();
                        let proof = merkle_tree.generate_proof(&event.current_hash).unwrap();
                        black_box(merkle_tree.verify_proof(&proof).unwrap());
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_sync_logging,
    bench_async_logging,
    bench_verification,
    bench_quick_verification,
    bench_enhanced_storage,
    bench_merkle_proof
);
criterion_main!(benches);
