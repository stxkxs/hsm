use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hsm_storage::*;
use std::hint::black_box;
use tempfile::TempDir;

// Helper to create test storage
fn create_test_storage() -> (TempDir, EncryptedFileStorage) {
    let temp_dir = TempDir::new().unwrap();
    let kek = [42u8; 32];
    let mut storage =
        EncryptedFileStorage::create_with_new_key(temp_dir.path().to_path_buf(), &kek).unwrap();
    storage.create_namespace("bench").unwrap();
    (temp_dir, storage)
}

// Helper to create cached storage
fn create_cached_storage() -> (TempDir, CachedStorage<EncryptedFileStorage>) {
    let temp_dir = TempDir::new().unwrap();
    let kek = [42u8; 32];
    let mut backend =
        EncryptedFileStorage::create_with_new_key(temp_dir.path().to_path_buf(), &kek).unwrap();
    backend.create_namespace("bench").unwrap();
    let cached = CachedStorage::new(backend, 10000);
    (temp_dir, cached)
}

// Benchmark: Write throughput
fn bench_write_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_throughput");

    for size in [256, 1024, 4096, 16384] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let (_temp, mut storage) = create_test_storage();
            let data = vec![0u8; size];
            let mut counter = 0u64;

            b.iter(|| {
                let key_id = KeyId::new(format!("key-{}", counter));
                counter += 1;
                storage
                    .store_key(&key_id, black_box(&data), "bench")
                    .unwrap();
            });
        });
    }

    group.finish();
}

// Benchmark: Read throughput (cold)
fn bench_read_throughput_cold(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_throughput_cold");

    for size in [256, 1024, 4096, 16384] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let (_temp, mut storage) = create_test_storage();
            let data = vec![0u8; size];

            // Pre-populate with 100 keys
            for i in 0..100 {
                let key_id = KeyId::new(format!("key-{}", i));
                storage.store_key(&key_id, &data, "bench").unwrap();
            }

            let mut counter = 0u64;
            b.iter(|| {
                let key_id = KeyId::new(format!("key-{}", counter % 100));
                counter += 1;
                storage.load_key(black_box(&key_id), "bench").unwrap()
            });
        });
    }

    group.finish();
}

// Benchmark: Read throughput (cached)
fn bench_read_throughput_cached(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_throughput_cached");

    for size in [256, 1024, 4096, 16384] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let (_temp, cached) = create_cached_storage();
            let data = vec![0u8; size];

            // Pre-populate with 100 keys
            for i in 0..100 {
                let key_id = KeyId::new(format!("key-{}", i));
                cached.store_key_cached(&key_id, &data, "bench").unwrap();
            }

            let mut counter = 0u64;
            b.iter(|| {
                let key_id = KeyId::new(format!("key-{}", counter % 100));
                counter += 1;
                cached.load_key_cached(black_box(&key_id), "bench").unwrap()
            });
        });
    }

    group.finish();
}

// Benchmark: Cache hit rate
fn bench_cache_hit_rate(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_hit_rate");

    group.bench_function("90_percent_hot", |b| {
        let (_temp, cached) = create_cached_storage();
        let data = vec![0u8; 1024];

        // Pre-populate with 1000 keys
        for i in 0..1000 {
            let key_id = KeyId::new(format!("key-{}", i));
            cached.store_key_cached(&key_id, &data, "bench").unwrap();
        }

        let mut counter = 0u64;
        b.iter(|| {
            // 90% of requests hit the first 100 keys (hot keys)
            let key_num = if counter % 10 < 9 {
                counter % 100
            } else {
                100 + (counter % 900)
            };
            counter += 1;

            let key_id = KeyId::new(format!("key-{}", key_num));
            cached.load_key_cached(black_box(&key_id), "bench").unwrap()
        });
    });

    group.finish();
}

// Benchmark: Compression
fn bench_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression");

    // Repetitive data (compresses well)
    group.bench_function("compress_repetitive_1kb", |b| {
        let data = vec![b'A'; 1024];
        b.iter(|| compress(black_box(&data), None).unwrap());
    });

    group.bench_function("decompress_repetitive_1kb", |b| {
        let data = vec![b'A'; 1024];
        let compressed = compress(&data, None).unwrap();
        b.iter(|| decompress(black_box(&compressed)).unwrap());
    });

    // Random data (compresses poorly)
    group.bench_function("compress_random_1kb", |b| {
        use rand::RngCore;
        let mut data = vec![0u8; 1024];
        rand::rngs::OsRng.fill_bytes(&mut data);

        b.iter(|| compress(black_box(&data), None).unwrap());
    });

    group.finish();
}

// Benchmark: Integrity protection
fn bench_integrity(c: &mut Criterion) {
    let mut group = c.benchmark_group("integrity");

    let manager = IntegrityKeyManager::generate();
    let master_key = MasterKey::generate();
    let data = vec![0u8; 1024];
    let encrypted = master_key.encrypt(&data).unwrap();

    group.bench_function("add_protection", |b| {
        b.iter(|| manager.protect(black_box(encrypted.clone())).unwrap());
    });

    group.bench_function("verify_protection", |b| {
        let protected = manager.protect(encrypted.clone()).unwrap();
        b.iter(|| manager.verify(black_box(&protected)).unwrap());
    });

    group.finish();
}

// Benchmark: Sharding distribution
fn bench_sharding(c: &mut Criterion) {
    let mut group = c.benchmark_group("sharding");

    group.bench_function("get_shard_1000_keys", |b| {
        let keys: Vec<KeyId> = (0..1000)
            .map(|i| KeyId::new(format!("key-{}", i)))
            .collect();

        let mut counter = 0usize;
        b.iter(|| {
            let key = &keys[counter % 1000];
            counter += 1;
            get_shard_number(black_box(key))
        });
    });

    group.bench_function("compute_stats_10000_keys", |b| {
        let keys: Vec<KeyId> = (0..10000)
            .map(|i| KeyId::new(format!("key-{}", i)))
            .collect();

        b.iter(|| ShardStats::from_keys(black_box(&keys)));
    });

    group.finish();
}

// Benchmark: Async storage
fn bench_async_storage(c: &mut Criterion) {
    let group = c.benchmark_group("async_storage");

    // Async benchmarks are skipped for now due to runtime overhead
    // In production, async I/O would show benefits under concurrent load

    group.finish();
}

criterion_group!(
    benches,
    bench_write_throughput,
    bench_read_throughput_cold,
    bench_read_throughput_cached,
    bench_cache_hit_rate,
    bench_compression,
    bench_integrity,
    bench_sharding,
    bench_async_storage,
);

criterion_main!(benches);
