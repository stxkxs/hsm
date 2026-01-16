use backup::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn benchmark_export(c: &mut Criterion) {
    let mut group = c.benchmark_group("export");

    for size in [1024, 10_240, 102_400].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let exporter = export::KeyExporter::new();
            let data = vec![0xAB; size];
            let password = b"benchmark_password_123";

            b.iter(|| {
                exporter
                    .export_keys(black_box(&data), black_box(password), None)
                    .unwrap()
            });
        });
    }

    group.finish();
}

fn benchmark_import(c: &mut Criterion) {
    let mut group = c.benchmark_group("import");

    for size in [1024, 10_240, 102_400].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let exporter = export::KeyExporter::new();
            let importer = import::KeyImporter::new();
            let data = vec![0xAB; size];
            let password = b"benchmark_password_123";

            let backup = exporter.export_keys(&data, password, None).unwrap();

            b.iter(|| {
                importer
                    .import_keys(black_box(&backup), black_box(password))
                    .unwrap()
            });
        });
    }

    group.finish();
}

fn benchmark_shamir_split(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir_split");

    for &(threshold, shares) in [(3, 5), (5, 10), (7, 15)].iter() {
        let id = format!("{}/{}", threshold, shares);

        group.bench_with_input(
            BenchmarkId::from_parameter(&id),
            &(threshold, shares),
            |b, &(t, s)| {
                let config = shamir::ShamirConfig::new(t, s).unwrap();
                let shamir = shamir::ShamirSecretSharing::new(config);
                let secret = vec![0xAB; 32];

                b.iter(|| shamir.split_secret(black_box(&secret)).unwrap());
            },
        );
    }

    group.finish();
}

fn benchmark_shamir_recover(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir_recover");

    for &(threshold, shares) in [(3, 5), (5, 10), (7, 15)].iter() {
        let id = format!("{}/{}", threshold, shares);

        group.bench_with_input(
            BenchmarkId::from_parameter(&id),
            &(threshold, shares),
            |b, &(t, s)| {
                let config = shamir::ShamirConfig::new(t, s).unwrap();
                let shamir = shamir::ShamirSecretSharing::new(config);
                let secret = vec![0xAB; 32];
                let shares = shamir.split_secret(&secret).unwrap();
                let recovery_shares = &shares[..t as usize];

                b.iter(|| shamir.recover_secret(black_box(recovery_shares)).unwrap());
            },
        );
    }

    group.finish();
}

fn benchmark_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression");

    for size in [1024, 10_240, 102_400, 1_024_000].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("compress", size), size, |b, &size| {
            let manager = compression::CompressionManager::default();
            let data = vec![0xAB; size];

            b.iter(|| manager.compress(black_box(&data)).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("decompress", size), size, |b, &size| {
            let manager = compression::CompressionManager::default();
            let data = vec![0xAB; size];
            let compressed = manager.compress(&data).unwrap();

            b.iter(|| manager.decompress(black_box(&compressed.data)).unwrap());
        });
    }

    group.finish();
}

fn benchmark_parallel_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel");

    for num_keys in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("process", num_keys),
            num_keys,
            |b, &num_keys| {
                let processor = parallel::ParallelProcessor::default();
                let keys: Vec<_> = (0..num_keys)
                    .map(|i| parallel::ParallelKey {
                        id: format!("key_{}", i),
                        data: vec![0xAB; 256],
                    })
                    .collect();

                b.iter(|| {
                    processor
                        .process_keys(black_box(keys.clone()), |key| Ok(key.data.len()))
                        .unwrap()
                });
            },
        );
    }

    group.finish();
}

fn benchmark_integrity_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("integrity");

    for size in [1024, 10_240, 102_400].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::new("create_verified", size),
            size,
            |b, &size| {
                let key = integrity::IntegrityManager::generate_key();
                let manager = integrity::IntegrityManager::new(key).unwrap();
                let data = vec![0xAB; size];

                b.iter(|| manager.create_verified(black_box(&data)).unwrap());
            },
        );

        group.bench_with_input(BenchmarkId::new("verify", size), size, |b, &size| {
            let key = integrity::IntegrityManager::generate_key();
            let manager = integrity::IntegrityManager::new(key).unwrap();
            let data = vec![0xAB; size];
            let verified = manager.create_verified(&data).unwrap();

            b.iter(|| manager.verify(black_box(&verified)).unwrap());
        });
    }

    group.finish();
}

fn benchmark_incremental_backup(c: &mut Criterion) {
    let mut group = c.benchmark_group("incremental");

    group.bench_function("create_full", |b| {
        let mut manager = incremental::IncrementalBackupManager::new();
        let keys: Vec<_> = (0..100)
            .map(|i| incremental::KeyEntry {
                id: format!("key_{}", i),
                data: vec![0xAB; 256],
                modified_at: 1000,
            })
            .collect();

        b.iter(|| {
            manager.create_full_backup(black_box("backup1".to_string()), black_box(keys.clone()))
        });
    });

    group.bench_function("create_incremental", |b| {
        let mut manager = incremental::IncrementalBackupManager::new();
        let keys: Vec<_> = (0..10)
            .map(|i| incremental::KeyEntry {
                id: format!("key_{}", i),
                data: vec![0xAB; 256],
                modified_at: 2000,
            })
            .collect();

        b.iter(|| {
            manager.create_incremental_backup(
                black_box("backup2".to_string()),
                black_box("backup1".to_string()),
                black_box(keys.clone()),
            )
        });
    });

    group.bench_function("restore_chain", |b| {
        let manager = incremental::IncrementalBackupManager::new();

        let mut full_backup = incremental::IncrementalBackup::new_full("backup1".to_string());
        for i in 0..100 {
            full_backup.add_key(incremental::KeyEntry {
                id: format!("key_{}", i),
                data: vec![0xAB; 256],
                modified_at: 1000,
            });
        }

        let mut inc_backup = incremental::IncrementalBackup::new_incremental(
            "backup2".to_string(),
            "backup1".to_string(),
        );
        for i in 0..10 {
            inc_backup.add_key(incremental::KeyEntry {
                id: format!("key_{}", i),
                data: vec![0xCD; 256],
                modified_at: 2000,
            });
        }

        let chain = vec![full_backup, inc_backup];

        b.iter(|| manager.restore_from_chain(black_box(&chain)).unwrap());
    });

    group.finish();
}

fn benchmark_health_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("health");

    group.bench_function("check_backup_health", |b| {
        let exporter = export::KeyExporter::new();
        let checker = health::BackupHealthChecker::new();
        let password = b"test_password";
        let backup = exporter
            .export_keys(&vec![0xAB; 10_240], password, None)
            .unwrap();

        b.iter(|| checker.check_backup_health(black_box(&backup), black_box(password)));
    });

    group.bench_function("test_restore", |b| {
        let exporter = export::KeyExporter::new();
        let checker = health::BackupHealthChecker::new();
        let password = b"test_password";
        let backup = exporter
            .export_keys(&vec![0xAB; 10_240], password, None)
            .unwrap();

        b.iter(|| checker.test_restore(black_box(&backup), black_box(password)));
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_export,
    benchmark_import,
    benchmark_shamir_split,
    benchmark_shamir_recover,
    benchmark_compression,
    benchmark_parallel_processing,
    benchmark_integrity_verification,
    benchmark_incremental_backup,
    benchmark_health_check,
);

criterion_main!(benches);
