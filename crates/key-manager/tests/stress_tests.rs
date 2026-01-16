use hsm_key_manager::*;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

/// Stress test with 1000+ concurrent operations
#[test]
fn test_high_concurrency_stress() {
    let manager = Arc::new(DefaultKeyManager::new());
    let num_threads = 20;
    let ops_per_thread = 50;
    let mut handles = vec![];

    let start = Instant::now();

    for thread_id in 0..num_threads {
        let mgr = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            let namespace = format!("stress_ns_{}", thread_id);
            let mut operations = 0;

            // Generate keys
            let mut key_ids = vec![];
            for _ in 0..ops_per_thread {
                let spec = KeySpec {
                    key_type: KeyType::Ed25519,
                    namespace: namespace.clone(),
                    policy: KeyUsagePolicy::default(),
                    labels: Default::default(),
                };
                let key_id = mgr.generate_key(spec).unwrap();
                key_ids.push(key_id);
                operations += 1;
            }

            // Read keys
            for key_id in &key_ids {
                let _ = mgr.get_key(key_id, &namespace).unwrap();
                operations += 1;
            }

            // Update keys
            for key_id in &key_ids {
                mgr.increment_operations(key_id, &namespace).unwrap();
                operations += 1;
            }

            // List keys
            let _ = mgr.list_keys(&namespace, KeyFilter::default()).unwrap();
            operations += 1;

            operations
        });
        handles.push(handle);
    }

    // Wait for all threads
    let mut total_operations = 0;
    for handle in handles {
        total_operations += handle.join().unwrap();
    }

    let duration = start.elapsed();

    // 20 threads * (50 generates + 50 reads + 50 updates + 1 list) = 3020 operations
    assert_eq!(total_operations, num_threads * (ops_per_thread * 3 + 1));

    println!(
        "Stress test: {} operations in {:?}",
        total_operations, duration
    );
    println!(
        "Throughput: {:.0} ops/sec",
        total_operations as f64 / duration.as_secs_f64()
    );

    // Should achieve > 1000 ops/sec
    let ops_per_sec = total_operations as f64 / duration.as_secs_f64();
    assert!(
        ops_per_sec > 1000.0,
        "Throughput {} ops/sec is below target of 1000 ops/sec",
        ops_per_sec
    );
}

/// Test concurrent read performance (hot cache)
#[test]
fn test_concurrent_read_performance() {
    let manager = Arc::new(DefaultKeyManager::new());
    let namespace = "perf_test";

    // Create a single key
    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: namespace.to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };
    let key_id = manager.generate_key(spec).unwrap();

    // Warm up cache
    let _ = manager.get_key(&key_id, namespace).unwrap();

    // Concurrent reads
    let num_threads = 10;
    let reads_per_thread = 1000;
    let mut handles = vec![];

    let start = Instant::now();

    for _ in 0..num_threads {
        let mgr = Arc::clone(&manager);
        let kid = key_id;
        let handle = thread::spawn(move || {
            for _ in 0..reads_per_thread {
                let _ = mgr.get_key(&kid, namespace).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let duration = start.elapsed();
    let total_reads = num_threads * reads_per_thread;
    let avg_latency_us = duration.as_micros() / total_reads as u128;

    println!("Concurrent reads: {} reads in {:?}", total_reads, duration);
    println!("Average latency: {}μs", avg_latency_us);

    // Cached reads should be < 100μs on average
    assert!(
        avg_latency_us < 100,
        "Average cached read latency {}μs exceeds 100μs target",
        avg_latency_us
    );
}

/// Test concurrent key generation performance
#[test]
fn test_concurrent_generation_performance() {
    let manager = Arc::new(DefaultKeyManager::new());
    let num_threads = 10;
    let keys_per_thread = 10;
    let mut handles = vec![];

    let start = Instant::now();

    for thread_id in 0..num_threads {
        let mgr = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            let namespace = format!("gen_ns_{}", thread_id);
            let mut latencies = vec![];

            for _ in 0..keys_per_thread {
                let key_start = Instant::now();
                let spec = KeySpec {
                    key_type: KeyType::Ed25519,
                    namespace: namespace.clone(),
                    policy: KeyUsagePolicy::default(),
                    labels: Default::default(),
                };
                let _ = mgr.generate_key(spec).unwrap();
                latencies.push(key_start.elapsed());
            }

            latencies
        });
        handles.push(handle);
    }

    let mut all_latencies = vec![];
    for handle in handles {
        all_latencies.extend(handle.join().unwrap());
    }

    let duration = start.elapsed();

    // Calculate p99 latency
    all_latencies.sort();
    let p99_index = (all_latencies.len() as f64 * 0.99) as usize;
    let p99_latency = all_latencies[p99_index];

    println!(
        "Key generation: {} keys in {:?}",
        all_latencies.len(),
        duration
    );
    println!("P99 latency: {:?}", p99_latency);

    // P99 should be < 50ms for Ed25519
    assert!(
        p99_latency.as_millis() < 50,
        "P99 latency {:?} exceeds 50ms target",
        p99_latency
    );
}

/// Test concurrent updates with contention
#[test]
fn test_concurrent_update_contention() {
    let manager = Arc::new(DefaultKeyManager::new());
    let namespace = "contention_test";

    // Create a single key that will be updated concurrently
    let spec = KeySpec {
        key_type: KeyType::Ed25519,
        namespace: namespace.to_string(),
        policy: KeyUsagePolicy::default(),
        labels: Default::default(),
    };
    let key_id = manager.generate_key(spec).unwrap();

    let num_threads = 20;
    let updates_per_thread = 50;
    let mut handles = vec![];

    for _ in 0..num_threads {
        let mgr = Arc::clone(&manager);
        let kid = key_id;
        let handle = thread::spawn(move || {
            for _ in 0..updates_per_thread {
                mgr.increment_operations(&kid, namespace).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify final operation count
    let key = manager.get_key(&key_id, namespace).unwrap();
    assert_eq!(
        key.operation_count,
        (num_threads * updates_per_thread) as u64
    );
}

/// Test mixed workload (reads, writes, updates)
#[test]
fn test_mixed_workload() {
    let manager = Arc::new(DefaultKeyManager::new());

    // First, pre-populate all namespaces with some keys
    for ns_id in 0..3 {
        let namespace = format!("mixed_ns_{}", ns_id);
        for _ in 0..10 {
            let spec = KeySpec {
                key_type: KeyType::Ed25519,
                namespace: namespace.clone(),
                policy: KeyUsagePolicy::default(),
                labels: Default::default(),
            };
            manager.generate_key(spec).unwrap();
        }
    }

    let num_threads = 15;
    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let mgr = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            let namespace = format!("mixed_ns_{}", thread_id % 3); // 3 namespaces

            match thread_id % 3 {
                0 => {
                    // Thread type 0: Generate more keys
                    for _ in 0..20 {
                        let spec = KeySpec {
                            key_type: KeyType::Ed25519,
                            namespace: namespace.clone(),
                            policy: KeyUsagePolicy::default(),
                            labels: Default::default(),
                        };
                        let _ = mgr.generate_key(spec).unwrap();
                    }
                }
                1 => {
                    // Thread type 1: List and read keys
                    for _ in 0..50 {
                        let keys = mgr.list_keys(&namespace, KeyFilter::default()).unwrap();
                        for metadata in keys.iter().take(5) {
                            let _ = mgr.get_key(&metadata.id, &namespace);
                        }
                    }
                }
                _ => {
                    // Thread type 2: Update keys
                    for _ in 0..30 {
                        let keys = mgr.list_keys(&namespace, KeyFilter::default()).unwrap();
                        for metadata in keys.iter().take(3) {
                            let _ = mgr.increment_operations(&metadata.id, &namespace);
                        }
                    }
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify all namespaces have keys
    for i in 0..3 {
        let namespace = format!("mixed_ns_{}", i);
        let keys = manager.list_keys(&namespace, KeyFilter::default()).unwrap();
        assert!(keys.len() > 0, "Namespace {} should have keys", namespace);
    }
}

/// Test batch operations under load
#[test]
fn test_batch_operations_stress() {
    let manager = Arc::new(DefaultKeyManager::new());

    // Generate many keys in batch
    let mut specs = vec![];
    for i in 0..100 {
        specs.push(KeySpec {
            key_type: KeyType::Ed25519,
            namespace: format!("batch_ns_{}", i % 10),
            policy: KeyUsagePolicy::default(),
            labels: Default::default(),
        });
    }

    let start = Instant::now();
    let key_ids = manager.generate_keys_batch(specs).unwrap();
    let batch_gen_time = start.elapsed();

    assert_eq!(key_ids.len(), 100);
    println!("Batch generation: 100 keys in {:?}", batch_gen_time);

    // Test batch list with pagination
    for i in 0..10 {
        let namespace = format!("batch_ns_{}", i);
        let page1 = manager.list_keys_batch(&namespace, 0, 5).unwrap();
        let page2 = manager.list_keys_batch(&namespace, 5, 5).unwrap();

        assert!(page1.len() > 0 || page2.len() > 0);
    }
}

/// Test no deadlocks under high contention
#[test]
fn test_no_deadlocks() {
    let manager = Arc::new(DefaultKeyManager::new());
    let num_threads = 30;
    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let mgr = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            let ns1 = "namespace_a";
            let ns2 = "namespace_b";

            // Alternate between namespaces to create contention
            let namespace = if thread_id % 2 == 0 { ns1 } else { ns2 };

            for _ in 0..20 {
                // Generate
                let spec = KeySpec {
                    key_type: KeyType::Ed25519,
                    namespace: namespace.to_string(),
                    policy: KeyUsagePolicy::default(),
                    labels: Default::default(),
                };
                let key_id = mgr.generate_key(spec).unwrap();

                // Read
                let _ = mgr.get_key(&key_id, namespace).unwrap();

                // Update
                mgr.increment_operations(&key_id, namespace).unwrap();

                // List
                let _ = mgr.list_keys(namespace, KeyFilter::default()).unwrap();
            }
        });
        handles.push(handle);
    }

    // If this completes without hanging, we have no deadlocks
    for handle in handles {
        handle.join().unwrap();
    }
}
