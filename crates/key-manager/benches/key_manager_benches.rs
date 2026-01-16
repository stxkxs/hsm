use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hsm_key_manager::*;
use std::sync::Arc;
use std::thread;

fn bench_key_generation(c: &mut Criterion) {
    let manager = DefaultKeyManager::new();

    let mut group = c.benchmark_group("key_generation");

    // Ed25519 (fastest)
    group.bench_function("ed25519", |b| {
        b.iter(|| {
            let spec = KeySpec {
                key_type: KeyType::Ed25519,
                namespace: "bench".to_string(),
                policy: KeyUsagePolicy::default(),
                labels: Default::default(),
            };
            black_box(manager.generate_key(spec).unwrap())
        })
    });

    // ECDSA P256
    group.bench_function("ecdsa_p256", |b| {
        b.iter(|| {
            let spec = KeySpec {
                key_type: KeyType::EcdsaP256,
                namespace: "bench".to_string(),
                policy: KeyUsagePolicy::default(),
                labels: Default::default(),
            };
            black_box(manager.generate_key(spec).unwrap())
        })
    });

    // RSA 2048
    group.bench_function("rsa_2048", |b| {
        b.iter(|| {
            let spec = KeySpec {
                key_type: KeyType::Rsa2048,
                namespace: "bench".to_string(),
                policy: KeyUsagePolicy::default(),
                labels: Default::default(),
            };
            black_box(manager.generate_key(spec).unwrap())
        })
    });

    group.finish();
}

fn bench_key_lookup(c: &mut Criterion) {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "bench".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };
    let key_id = manager.generate_key(spec).unwrap();

    let mut group = c.benchmark_group("key_lookup");

    // Cold lookup (first access)
    group.bench_function("cold_lookup", |b| {
        b.iter_with_setup(
            || {
                // Setup: create a new manager with the key
                let mgr = DefaultKeyManager::new();
                let spec = KeySpec {
                    key_type: KeyType::Ed25519,
                    namespace: "bench_cold".to_string(),
                    policy: KeyUsagePolicy::default(),
                    labels: Default::default(),
                };
                let kid = mgr.generate_key(spec).unwrap();
                (mgr, kid)
            },
            |(mgr, kid)| {
                // Benchmark: first lookup (cold)
                black_box(mgr.get_key(&kid, "bench_cold").unwrap())
            },
        )
    });

    // Hot lookup (cached)
    group.bench_function("hot_lookup", |b| {
        // Warm up cache
        let _ = manager.get_key(&key_id, "bench").unwrap();

        b.iter(|| black_box(manager.get_key(&key_id, "bench").unwrap()))
    });

    // Metadata lookup
    group.bench_function("metadata_lookup", |b| {
        b.iter(|| black_box(manager.get_metadata(&key_id, "bench").unwrap()))
    });

    group.finish();
}

fn bench_concurrent_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent");

    for num_threads in [1, 2, 4, 8, 16].iter() {
        group.throughput(Throughput::Elements(*num_threads as u64 * 100));
        group.bench_with_input(
            BenchmarkId::new("concurrent_reads", num_threads),
            num_threads,
            |b, &num_threads| {
                let manager = Arc::new(DefaultKeyManager::new());
                let spec = KeySpec {
                    key_type: KeyType::Ed25519,
                    namespace: "concurrent_bench".to_string(),
                    policy: KeyUsagePolicy::default(),
                    labels: Default::default(),
                };
                let key_id = manager.generate_key(spec).unwrap();

                // Warm up cache
                let _ = manager.get_key(&key_id, "concurrent_bench").unwrap();

                b.iter(|| {
                    let mut handles = vec![];
                    for _ in 0..num_threads {
                        let mgr = Arc::clone(&manager);
                        let kid = key_id;
                        let handle = thread::spawn(move || {
                            for _ in 0..100 {
                                black_box(mgr.get_key(&kid, "concurrent_bench").unwrap());
                            }
                        });
                        handles.push(handle);
                    }
                    for handle in handles {
                        handle.join().unwrap();
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_list_operations(c: &mut Criterion) {
    let manager = DefaultKeyManager::new();

    // Create keys for benchmarking
    for size in [10, 50, 100, 500].iter() {
        let namespace = format!("list_bench_{}", size);
        for _ in 0..*size {
            let spec = KeySpec {
                key_type: KeyType::Ed25519,
                namespace: namespace.clone(),
                policy: KeyUsagePolicy::default(),
                labels: Default::default(),
            };
            manager.generate_key(spec).unwrap();
        }
    }

    let mut group = c.benchmark_group("list_operations");

    for size in [10, 50, 100, 500].iter() {
        let namespace = format!("list_bench_{}", size);

        group.throughput(Throughput::Elements(*size));
        group.bench_with_input(BenchmarkId::new("list_all", size), &namespace, |b, ns| {
            b.iter(|| black_box(manager.list_keys(ns, KeyFilter::default()).unwrap()))
        });

        group.bench_with_input(
            BenchmarkId::new("list_batch_10", size),
            &namespace,
            |b, ns| b.iter(|| black_box(manager.list_keys_batch(ns, 0, 10).unwrap())),
        );
    }

    group.finish();
}

fn bench_update_operations(c: &mut Criterion) {
    let manager = DefaultKeyManager::new();

    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: "update_bench".to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };
    let key_id = manager.generate_key(spec).unwrap();

    let mut group = c.benchmark_group("update_operations");

    group.bench_function("increment_operations", |b| {
        b.iter(|| {
            black_box(
                manager
                    .increment_operations(&key_id, "update_bench")
                    .unwrap(),
            )
        })
    });

    group.bench_function("update_state", |b| {
        b.iter(|| {
            black_box(
                manager
                    .update_state(&key_id, "update_bench", KeyState::Active)
                    .unwrap(),
            )
        })
    });

    group.finish();
}

fn bench_key_rotation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_rotation");

    group.bench_function("rotate_ed25519", |b| {
        b.iter_with_setup(
            || {
                let manager = DefaultKeyManager::new();
                let spec = KeySpec {
                    key_type: KeyType::Ed25519,
                    namespace: "rotation_bench".to_string(),
                    policy: KeyUsagePolicy::default(),
                    labels: Default::default(),
                };
                let key_id = manager.generate_key(spec).unwrap();
                (manager, key_id)
            },
            |(manager, key_id)| black_box(manager.rotate_key(&key_id, "rotation_bench").unwrap()),
        )
    });

    group.finish();
}

fn bench_batch_operations(c: &mut Criterion) {
    let manager = DefaultKeyManager::new();

    let mut group = c.benchmark_group("batch_operations");

    for batch_size in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*batch_size));
        group.bench_with_input(
            BenchmarkId::new("generate_batch", batch_size),
            batch_size,
            |b, &size| {
                b.iter(|| {
                    let specs: Vec<KeySpec> = (0..size)
                        .map(|i| KeySpec {
                            key_type: KeyType::Ed25519,
                            namespace: format!("batch_gen_{}", i % 10),
                            policy: KeyUsagePolicy::default(),
                            labels: Default::default(),
                        })
                        .collect();
                    black_box(manager.generate_keys_batch(specs).unwrap())
                })
            },
        );
    }

    group.finish();
}

fn bench_namespace_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("namespace_operations");

    // Create manager with multiple namespaces
    let manager = DefaultKeyManager::new();
    for ns_id in 0..10 {
        let namespace = format!("ns_{}", ns_id);
        for _ in 0..50 {
            let spec = KeySpec {
                key_type: KeyType::Ed25519,
                namespace: namespace.clone(),
                policy: KeyUsagePolicy::default(),
                labels: Default::default(),
            };
            manager.generate_key(spec).unwrap();
        }
    }

    group.bench_function("list_single_namespace", |b| {
        b.iter(|| black_box(manager.list_keys("ns_5", KeyFilter::default()).unwrap()))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_key_lookup,
    bench_concurrent_operations,
    bench_list_operations,
    bench_update_operations,
    bench_key_rotation,
    bench_batch_operations,
    bench_namespace_operations,
);
criterion_main!(benches);
