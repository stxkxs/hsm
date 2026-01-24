//! Benchmarks for hardware backend operations
//!
//! These benchmarks measure the performance of seal/unseal/attest/sign operations
//! across different TEE backends.
//!
//! # Success Metrics
//!
//! Performance targets for production deployment:
//!
//! ## AWS Nitro Enclaves
//! - seal_key: < 10ms
//! - unseal_key: < 10ms
//! - remote_sign: < 5ms (CRITICAL: transaction signing hot path)
//! - attest: < 100ms (includes KMS roundtrip)
//!
//! ## Intel SGX
//! - seal_key: < 5ms (local operation, very fast)
//! - unseal_key: < 5ms
//! - remote_sign: < 2ms (fastest, in-enclave)
//! - attest: < 200ms (includes IAS roundtrip for remote attestation)
//!
//! ## AMD SEV
//! - seal_key: < 5ms
//! - unseal_key: < 5ms
//! - remote_sign: < 2ms
//! - attest: < 20ms (local attestation)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hsm_hardware_backend::{HardwareBackend, PlaintextKey};

#[cfg(feature = "aws-nitro")]
use hsm_hardware_backend::{NitroConfig, NitroEnclaveBackend};

#[cfg(feature = "intel-sgx")]
use hsm_hardware_backend::{SgxBackend, SgxConfig};

#[cfg(feature = "amd-sev")]
use hsm_hardware_backend::{SevBackend, SevConfig};

// Common test data
fn get_test_key(size: usize) -> PlaintextKey {
    PlaintextKey::new(vec![0x42; size])
}

fn get_test_message(size: usize) -> Vec<u8> {
    vec![0x99; size]
}

#[cfg(feature = "aws-nitro")]
fn bench_nitro_seal_unseal(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    // Note: This benchmark requires valid AWS credentials and KMS access
    // In CI without credentials, it will be skipped

    let config = NitroConfig {
        region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
        kms_key_arn: std::env::var("KMS_KEY_ARN")
            .unwrap_or_else(|_| "arn:aws:kms:us-east-1:123456789012:key/test".to_string()),
        enclave_cid: Some(16),
        verify_attestation: false,
        expected_pcrs: None,
    };

    // Try to create backend, skip if not available
    let backend = match runtime.block_on(NitroEnclaveBackend::new(config)) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("Skipping AWS Nitro benchmarks (credentials not available)");
            return;
        }
    };

    let mut group = c.benchmark_group("nitro");

    // Benchmark different key sizes
    for size in [32, 256, 2048] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("seal_key", size), &size, |b, &s| {
            let key = get_test_key(s);
            b.to_async(&runtime).iter(|| async {
                let sealed = backend.seal_key(black_box(&key)).await.unwrap();
                black_box(sealed)
            });
        });

        // Pre-seal a key for unseal benchmarks
        let key = get_test_key(size);
        let sealed = runtime.block_on(backend.seal_key(&key)).unwrap();

        group.bench_with_input(BenchmarkId::new("unseal_key", size), &size, |b, _| {
            b.to_async(&runtime).iter(|| async {
                let unsealed = backend.unseal_key(black_box(&sealed)).await.unwrap();
                black_box(unsealed)
            });
        });
    }

    // Benchmark remote signing (CRITICAL PATH)
    group.bench_function("remote_sign", |b| {
        let message = get_test_message(32);
        b.to_async(&runtime).iter(|| async {
            let signature = backend
                .remote_sign(black_box("test-key"), black_box(&message))
                .await
                .unwrap();
            black_box(signature)
        });
    });

    // Benchmark attestation
    group.bench_function("attest", |b| {
        b.to_async(&runtime).iter(|| async {
            let report = backend.attest(black_box(Some(b"nonce"))).await.unwrap();
            black_box(report)
        });
    });

    group.finish();
}

#[cfg(feature = "intel-sgx")]
fn bench_sgx_seal_unseal(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let config = SgxConfig::default();

    let backend = match runtime.block_on(SgxBackend::new(config)) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("Skipping Intel SGX benchmarks (SGX not available)");
            return;
        }
    };

    let mut group = c.benchmark_group("sgx");

    // Benchmark different key sizes
    for size in [32, 256, 2048] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("seal_key", size), &size, |b, &s| {
            let key = get_test_key(s);
            b.to_async(&runtime).iter(|| async {
                let sealed = backend.seal_key(black_box(&key)).await.unwrap();
                black_box(sealed)
            });
        });

        let key = get_test_key(size);
        let sealed = runtime.block_on(backend.seal_key(&key)).unwrap();

        group.bench_with_input(BenchmarkId::new("unseal_key", size), &size, |b, _| {
            b.to_async(&runtime).iter(|| async {
                let unsealed = backend.unseal_key(black_box(&sealed)).await.unwrap();
                black_box(unsealed)
            });
        });
    }

    // Benchmark remote signing
    group.bench_function("remote_sign", |b| {
        let message = get_test_message(32);
        b.to_async(&runtime).iter(|| async {
            let signature = backend
                .remote_sign(black_box("test-key"), black_box(&message))
                .await
                .unwrap();
            black_box(signature)
        });
    });

    // Benchmark attestation
    group.bench_function("attest", |b| {
        b.to_async(&runtime).iter(|| async {
            let report = backend.attest(black_box(Some(b"nonce"))).await.unwrap();
            black_box(report)
        });
    });

    group.finish();
}

#[cfg(feature = "amd-sev")]
fn bench_sev_seal_unseal(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let config = SevConfig::default();

    let backend = match runtime.block_on(SevBackend::new(config)) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("Skipping AMD SEV benchmarks (SEV not available)");
            return;
        }
    };

    let mut group = c.benchmark_group("sev");

    // Benchmark different key sizes
    for size in [32, 256, 2048] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("seal_key", size), &size, |b, &s| {
            let key = get_test_key(s);
            b.to_async(&runtime).iter(|| async {
                let sealed = backend.seal_key(black_box(&key)).await.unwrap();
                black_box(sealed)
            });
        });

        let key = get_test_key(size);
        let sealed = runtime.block_on(backend.seal_key(&key)).unwrap();

        group.bench_with_input(BenchmarkId::new("unseal_key", size), &size, |b, _| {
            b.to_async(&runtime).iter(|| async {
                let unsealed = backend.unseal_key(black_box(&sealed)).await.unwrap();
                black_box(unsealed)
            });
        });
    }

    // Benchmark remote signing
    group.bench_function("remote_sign", |b| {
        let message = get_test_message(32);
        b.to_async(&runtime).iter(|| async {
            let signature = backend
                .remote_sign(black_box("test-key"), black_box(&message))
                .await
                .unwrap();
            black_box(signature)
        });
    });

    // Benchmark attestation
    group.bench_function("attest", |b| {
        b.to_async(&runtime).iter(|| async {
            let report = backend.attest(black_box(Some(b"nonce"))).await.unwrap();
            black_box(report)
        });
    });

    group.finish();
}

// Create conditional criterion groups
#[cfg(feature = "aws-nitro")]
criterion_group!(nitro_benches, bench_nitro_seal_unseal);

#[cfg(feature = "intel-sgx")]
criterion_group!(sgx_benches, bench_sgx_seal_unseal);

#[cfg(feature = "amd-sev")]
criterion_group!(sev_benches, bench_sev_seal_unseal);

// Combine all available benchmarks
#[cfg(all(feature = "aws-nitro", feature = "intel-sgx", feature = "amd-sev"))]
criterion_main!(nitro_benches, sgx_benches, sev_benches);

#[cfg(all(feature = "aws-nitro", feature = "intel-sgx", not(feature = "amd-sev")))]
criterion_main!(nitro_benches, sgx_benches);

#[cfg(all(feature = "aws-nitro", not(feature = "intel-sgx"), feature = "amd-sev"))]
criterion_main!(nitro_benches, sev_benches);

#[cfg(all(not(feature = "aws-nitro"), feature = "intel-sgx", feature = "amd-sev"))]
criterion_main!(sgx_benches, sev_benches);

#[cfg(all(
    feature = "aws-nitro",
    not(feature = "intel-sgx"),
    not(feature = "amd-sev")
))]
criterion_main!(nitro_benches);

#[cfg(all(
    not(feature = "aws-nitro"),
    feature = "intel-sgx",
    not(feature = "amd-sev")
))]
criterion_main!(sgx_benches);

#[cfg(all(
    not(feature = "aws-nitro"),
    not(feature = "intel-sgx"),
    feature = "amd-sev"
))]
criterion_main!(sev_benches);

// Fallback if no features enabled
#[cfg(not(any(feature = "aws-nitro", feature = "intel-sgx", feature = "amd-sev")))]
fn main() {
    eprintln!("No hardware backend features enabled. Enable at least one of: aws-nitro, intel-sgx, amd-sev");
}
