use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hsm_grpc_api::*;
use std::time::Duration;

fn benchmark_validation(c: &mut Criterion) {
    use hsm_grpc_api::validation::*;

    let mut group = c.benchmark_group("validation");

    // Benchmark key ID validation
    group.bench_function("validate_key_id", |b| {
        let key_id = b"test-key-12345678";
        b.iter(|| validate_key_id(black_box(key_id)))
    });

    // Benchmark namespace validation
    group.bench_function("validate_namespace", |b| {
        let namespace = "test-namespace-123";
        b.iter(|| validate_namespace(black_box(namespace)))
    });

    // Benchmark data size validation
    group.bench_function("validate_data_size_small", |b| {
        let data = vec![0u8; 1024];
        b.iter(|| validate_data_size(black_box(&data), "test"))
    });

    group.bench_function("validate_data_size_large", |b| {
        let data = vec![0u8; 1024 * 1024]; // 1MB
        b.iter(|| validate_data_size(black_box(&data), "test"))
    });

    group.finish();
}

fn benchmark_cache(c: &mut Criterion) {
    use hsm_grpc_api::cache::*;

    let mut group = c.benchmark_group("cache");

    // Benchmark cache insertion
    group.bench_function("cache_insert", |b| {
        let cache = TtlCache::new(10000, Duration::from_secs(300));
        let mut counter = 0u64;
        b.iter(|| {
            let key = format!("key-{}", counter);
            cache.insert(black_box(key), black_box(vec![1, 2, 3, 4, 5]));
            counter += 1;
        })
    });

    // Benchmark cache get (hit)
    group.bench_function("cache_get_hit", |b| {
        let cache = TtlCache::new(10000, Duration::from_secs(300));
        cache.insert("test-key", vec![1, 2, 3, 4, 5]);
        b.iter(|| {
            let result = cache.get(black_box(&"test-key"));
            black_box(result);
        })
    });

    // Benchmark cache get (miss)
    group.bench_function("cache_get_miss", |b| {
        let cache: TtlCache<String, Vec<u8>> = TtlCache::new(10000, Duration::from_secs(300));
        b.iter(|| {
            let result = cache.get(black_box(&"nonexistent-key".to_string()));
            black_box(result);
        })
    });

    // Benchmark response cache
    group.bench_function("response_cache_get_key", |b| {
        let cache = ResponseCache::new();
        let key = CacheKey::GetKey {
            key_id: b"test-key".to_vec(),
            namespace: "test".to_string(),
        };
        cache.get_key_cache.insert(key.clone(), vec![1, 2, 3, 4, 5]);
        b.iter(|| {
            let result = cache.get_key_cache.get(black_box(&key));
            black_box(result);
        })
    });

    group.finish();
}

fn benchmark_circuit_breaker(c: &mut Criterion) {
    use hsm_grpc_api::circuit_breaker::*;

    let mut group = c.benchmark_group("circuit_breaker");

    // Benchmark circuit breaker (closed state)
    group.bench_function("cb_closed_success", |b| {
        let config = CircuitBreakerConfig {
            failure_threshold: 5,
            success_threshold: 2,
            timeout: Duration::from_secs(60),
            half_open_max_requests: 1,
        };
        let cb = CircuitBreaker::new(config);
        b.iter(|| {
            let result = cb.call(|| -> Result<(), ()> { Ok(()) });
            black_box(result);
        })
    });

    // Benchmark circuit breaker (open state)
    group.bench_function("cb_open_rejection", |b| {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_secs(60),
            half_open_max_requests: 1,
        };
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        for _ in 0..2 {
            let _ = cb.call(|| -> Result<(), ()> { Err(()) });
        }

        b.iter(|| {
            let result = cb.call(|| -> Result<(), ()> { Ok(()) });
            black_box(result);
        })
    });

    // Benchmark getting stats
    group.bench_function("cb_stats", |b| {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        b.iter(|| {
            let stats = cb.stats();
            black_box(stats);
        })
    });

    group.finish();
}

fn benchmark_error_conversion(c: &mut Criterion) {
    use tonic::Status;

    let mut group = c.benchmark_group("error_conversion");

    group.bench_function("error_to_status_key_not_found", |b| {
        b.iter(|| {
            let error = ApiError::KeyNotFound("test-key".to_string());
            let status: Status = error.into();
            black_box(status);
        })
    });

    group.bench_function("error_to_status_crypto_error", |b| {
        b.iter(|| {
            let error = ApiError::CryptoError("operation failed".to_string());
            let status: Status = error.into();
            black_box(status);
        })
    });

    group.bench_function("error_to_status_auth_failed", |b| {
        b.iter(|| {
            let error = ApiError::AuthenticationFailed("invalid token".to_string());
            let status: Status = error.into();
            black_box(status);
        })
    });

    group.finish();
}

fn benchmark_batch_operations(c: &mut Criterion) {
    use hsm_grpc_api::validation::*;

    let mut group = c.benchmark_group("batch_operations");

    // Benchmark batch size validation
    for size in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("validate_batch_size", size),
            size,
            |b, &size| b.iter(|| validate_batch_size(black_box(size), "test")),
        );
    }

    group.finish();
}

fn benchmark_metadata_validation(c: &mut Criterion) {
    use hsm_grpc_api::validation::*;
    use std::collections::HashMap;

    let mut group = c.benchmark_group("metadata");

    // Small metadata
    group.bench_function("validate_metadata_small", |b| {
        let mut metadata = HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "value2".to_string());
        b.iter(|| validate_metadata(black_box(&metadata)))
    });

    // Medium metadata
    group.bench_function("validate_metadata_medium", |b| {
        let mut metadata = HashMap::new();
        for i in 0..50 {
            metadata.insert(format!("key{}", i), format!("value{}", i));
        }
        b.iter(|| validate_metadata(black_box(&metadata)))
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_validation,
    benchmark_cache,
    benchmark_circuit_breaker,
    benchmark_error_conversion,
    benchmark_batch_operations,
    benchmark_metadata_validation,
);

criterion_main!(benches);
