//! Performance tests for storage backend

// the perf_target! macro intentionally negates a comparison to warn when a target is missed
#![allow(clippy::neg_cmp_op_on_partial_ord)]

use hsm_storage::{EncryptedFileStorage, KeyId, StorageBackend};
use std::time::Instant;
use tempfile::TempDir;

macro_rules! perf_target {
    ($condition:expr, $target_msg:expr) => {
        if !$condition {
            eprintln!("⚠️  PERFORMANCE WARNING: {}", $target_msg);
        }
    };
}

fn create_test_storage() -> (TempDir, EncryptedFileStorage) {
    let temp_dir = TempDir::new().unwrap();
    let kek = [42u8; 32];
    let storage =
        EncryptedFileStorage::create_with_new_key(temp_dir.path().to_path_buf(), &kek).unwrap();
    (temp_dir, storage)
}

#[test]
fn test_write_throughput() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("perf").unwrap();

    let num_keys = 1000;
    let data = vec![0xAB; 256]; // 256 bytes per key

    let start = Instant::now();

    for i in 0..num_keys {
        storage
            .store_key(&KeyId::new(format!("key{}", i)), &data, "perf")
            .unwrap();
    }

    let duration = start.elapsed();
    let ops_per_sec = num_keys as f64 / duration.as_secs_f64();

    println!(
        "Write throughput: {:.2} ops/sec ({} keys in {:?})",
        ops_per_sec, num_keys, duration
    );

    // Note: Performance depends on hardware and includes encryption, journaling, and fsync
    // Realistic target for production-grade durability is 10+ ops/sec
    perf_target!(
        ops_per_sec > 10.0,
        format!(
            "Write throughput below target: {:.2} ops/sec (target: >10)",
            ops_per_sec
        )
    );
}

#[test]
fn test_read_throughput() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("perf").unwrap();

    // Prepare data
    let num_keys = 1000;
    let data = vec![0xAB; 256];

    for i in 0..num_keys {
        storage
            .store_key(&KeyId::new(format!("key{}", i)), &data, "perf")
            .unwrap();
    }

    // Measure read performance
    let start = Instant::now();

    for i in 0..num_keys {
        let _loaded = storage
            .load_key(&KeyId::new(format!("key{}", i)), "perf")
            .unwrap();
    }

    let duration = start.elapsed();
    let ops_per_sec = num_keys as f64 / duration.as_secs_f64();

    println!(
        "Read throughput: {:.2} ops/sec ({} keys in {:?})",
        ops_per_sec, num_keys, duration
    );

    perf_target!(
        ops_per_sec > 50.0,
        format!(
            "Read throughput below target: {:.2} ops/sec (target: >50)",
            ops_per_sec
        )
    );
}

#[test]
fn test_mixed_workload() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("perf").unwrap();

    let num_operations = 1000;
    let data = vec![0xAB; 256];

    let start = Instant::now();

    for i in 0..num_operations {
        // Write
        storage
            .store_key(&KeyId::new(format!("key{}", i)), &data, "perf")
            .unwrap();

        // Read back every other key
        if i % 2 == 0 && i > 0 {
            let _loaded = storage
                .load_key(&KeyId::new(format!("key{}", i - 1)), "perf")
                .unwrap();
        }
    }

    let duration = start.elapsed();
    let ops_per_sec = (num_operations + num_operations / 2) as f64 / duration.as_secs_f64();

    println!(
        "Mixed workload throughput: {:.2} ops/sec ({} ops in {:?})",
        ops_per_sec,
        num_operations + num_operations / 2,
        duration
    );

    perf_target!(
        ops_per_sec > 15.0,
        format!(
            "Mixed workload throughput below target: {:.2} ops/sec (target: >15)",
            ops_per_sec
        )
    );
}

#[test]
fn test_large_key_performance() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("perf").unwrap();

    // 1 MB keys
    let large_data = vec![0xAB; 1024 * 1024];
    let num_keys = 10;

    let start = Instant::now();

    for i in 0..num_keys {
        storage
            .store_key(&KeyId::new(format!("large{}", i)), &large_data, "perf")
            .unwrap();
    }

    let duration = start.elapsed();
    let mb_per_sec =
        (num_keys as f64 * large_data.len() as f64) / (1024.0 * 1024.0) / duration.as_secs_f64();

    println!(
        "Large key write: {:.2} MB/sec ({} x 1MB keys in {:?})",
        mb_per_sec, num_keys, duration
    );

    // With encryption and journaling overhead, 1+ MB/sec is acceptable
    perf_target!(
        mb_per_sec > 1.0,
        format!(
            "Large key write throughput below target: {:.2} MB/sec (target: >1.0)",
            mb_per_sec
        )
    );
}

#[test]
fn test_small_key_performance() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("perf").unwrap();

    // 32 byte keys (typical for cryptographic keys)
    let small_data = vec![0xAB; 32];
    let num_keys = 5000;

    let start = Instant::now();

    for i in 0..num_keys {
        storage
            .store_key(&KeyId::new(format!("small{}", i)), &small_data, "perf")
            .unwrap();
    }

    let duration = start.elapsed();
    let ops_per_sec = num_keys as f64 / duration.as_secs_f64();

    println!(
        "Small key write: {:.2} ops/sec ({} x 32B keys in {:?})",
        ops_per_sec, num_keys, duration
    );

    perf_target!(
        ops_per_sec > 30.0,
        format!(
            "Small key write throughput below target: {:.2} ops/sec (target: >30)",
            ops_per_sec
        )
    );
}

#[test]
fn test_list_keys_performance() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("perf").unwrap();

    // Create many keys
    let num_keys = 1000;
    let data = vec![0xAB; 256];

    for i in 0..num_keys {
        storage
            .store_key(&KeyId::new(format!("key{:04}", i)), &data, "perf")
            .unwrap();
    }

    // Measure list performance
    let start = Instant::now();

    for _ in 0..100 {
        let keys = storage.list_keys("perf").unwrap();
        assert_eq!(keys.len(), num_keys);
    }

    let duration = start.elapsed();
    let lists_per_sec = 100.0 / duration.as_secs_f64();

    println!(
        "List keys throughput: {:.2} lists/sec (100 lists of {} keys in {:?})",
        lists_per_sec, num_keys, duration
    );

    perf_target!(
        lists_per_sec > 10.0,
        format!(
            "List keys throughput below target: {:.2} lists/sec (target: >10)",
            lists_per_sec
        )
    );
}

#[test]
fn test_delete_performance() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("perf").unwrap();

    // Create keys
    let num_keys = 1000;
    let data = vec![0xAB; 256];

    for i in 0..num_keys {
        storage
            .store_key(&KeyId::new(format!("key{}", i)), &data, "perf")
            .unwrap();
    }

    // Measure delete performance
    let start = Instant::now();

    for i in 0..num_keys {
        storage
            .delete_key(&KeyId::new(format!("key{}", i)), "perf")
            .unwrap();
    }

    let duration = start.elapsed();
    let ops_per_sec = num_keys as f64 / duration.as_secs_f64();

    println!(
        "Delete throughput: {:.2} ops/sec ({} keys in {:?})",
        ops_per_sec, num_keys, duration
    );

    perf_target!(
        ops_per_sec > 50.0,
        format!(
            "Delete throughput below target: {:.2} ops/sec (target: >50)",
            ops_per_sec
        )
    );
}

#[test]
fn test_namespace_operations_performance() {
    let (_temp_dir, mut storage) = create_test_storage();

    let num_namespaces = 100;

    let start = Instant::now();

    for i in 0..num_namespaces {
        storage
            .create_namespace(&format!("namespace{}", i))
            .unwrap();
    }

    let duration = start.elapsed();
    let ops_per_sec = num_namespaces as f64 / duration.as_secs_f64();

    println!(
        "Namespace creation: {:.2} ops/sec ({} namespaces in {:?})",
        ops_per_sec, num_namespaces, duration
    );

    perf_target!(
        ops_per_sec > 20.0,
        format!(
            "Namespace creation below target: {:.2} ops/sec (target: >20)",
            ops_per_sec
        )
    );

    // Test listing
    let start = Instant::now();

    for _ in 0..100 {
        let namespaces = storage.list_namespaces().unwrap();
        assert_eq!(namespaces.len(), num_namespaces);
    }

    let duration = start.elapsed();
    let lists_per_sec = 100.0 / duration.as_secs_f64();

    println!(
        "Namespace listing: {:.2} lists/sec (100 lists of {} namespaces in {:?})",
        lists_per_sec, num_namespaces, duration
    );
}

#[test]
fn test_sync_performance() {
    let (_temp_dir, mut storage) = create_test_storage();

    storage.create_namespace("perf").unwrap();

    // Store some keys
    let data = vec![0xAB; 256];
    for i in 0..100 {
        storage
            .store_key(&KeyId::new(format!("key{}", i)), &data, "perf")
            .unwrap();
    }

    // Measure sync performance
    let start = Instant::now();

    for _ in 0..100 {
        storage.sync().unwrap();
    }

    let duration = start.elapsed();
    let syncs_per_sec = 100.0 / duration.as_secs_f64();

    println!(
        "Sync throughput: {:.2} syncs/sec (100 syncs in {:?})",
        syncs_per_sec, duration
    );

    perf_target!(
        syncs_per_sec > 10.0,
        format!(
            "Sync throughput below target: {:.2} syncs/sec (target: >10)",
            syncs_per_sec
        )
    );
}

#[test]
fn test_concurrent_namespace_performance() {
    let (_temp_dir, mut storage) = create_test_storage();

    // Create multiple namespaces
    for i in 0..5 {
        storage.create_namespace(&format!("ns{}", i)).unwrap();
    }

    let num_ops = 500; // 100 ops per namespace
    let data = vec![0xAB; 256];

    let start = Instant::now();

    for i in 0..num_ops {
        let ns = format!("ns{}", i % 5);
        storage
            .store_key(&KeyId::new(format!("key{}", i)), &data, &ns)
            .unwrap();
    }

    let duration = start.elapsed();
    let ops_per_sec = num_ops as f64 / duration.as_secs_f64();

    println!(
        "Multi-namespace throughput: {:.2} ops/sec ({} ops across 5 namespaces in {:?})",
        ops_per_sec, num_ops, duration
    );

    perf_target!(
        ops_per_sec > 10.0,
        format!(
            "Multi-namespace throughput below target: {:.2} ops/sec (target: >10)",
            ops_per_sec
        )
    );
}

#[test]
fn test_reopen_performance() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().to_path_buf();
    let kek = [42u8; 32];

    // Create storage with some data
    {
        let mut storage =
            EncryptedFileStorage::create_with_new_key(base_path.clone(), &kek).unwrap();
        storage.create_namespace("perf").unwrap();

        for i in 0..100 {
            storage
                .store_key(&KeyId::new(format!("key{}", i)), &vec![0xAB; 256], "perf")
                .unwrap();
        }
    }

    // Measure reopen time
    let start = Instant::now();

    for _ in 0..10 {
        let _storage = EncryptedFileStorage::open(base_path.clone(), &kek).unwrap();
    }

    let duration = start.elapsed();
    let avg_open_time = duration.as_millis() / 10;

    println!("Average reopen time: {} ms", avg_open_time);

    // Allow up to 1 second for reopen (includes journal replay and recovery)
    perf_target!(
        avg_open_time < 1000,
        format!(
            "Reopen time slower than target: {} ms (target: <1000ms)",
            avg_open_time
        )
    );
}
