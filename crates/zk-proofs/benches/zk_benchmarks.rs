//! # ZK Proof Benchmarks
//!
//! Performance benchmarks for zero-knowledge proofs in the audit system.
//!
//! ## Performance Targets
//!
//! - Proof generation: < 100ms for 1000 events (Merkle), < 50ms (single event)
//! - Proof verification: < 10ms
//! - Proof size: < 1KB
//!
//! ## Benchmarks
//!
//! - Lasso lookup argument (10-40x speedup target)
//! - Merkle tree integrity proofs
//! - Event existence proofs
//! - Batch proof generation

use ark_bn254::Fr;
use ark_std::{rand::SeedableRng, test_rng};
use audit::{AuditEventBuilder, EventType, OperationResult};
use chrono::Utc;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use zk_proofs::{
    event_proof::EventProofRequest,
    lasso::{LookupArgument, LookupTable},
    merkle_proof::MerkleProofRequest,
    proof_system::ProofSystem,
};

/// Create a test audit event
fn create_test_event(sequence: u64) -> audit::AuditEvent {
    use audit::OperationResult;

    audit::AuditEvent {
        timestamp: Utc::now(),
        sequence,
        event_type: EventType::Sign,
        operation: format!("operation_{}", sequence),
        namespace: "benchmark".to_string(),
        client_id: format!("client_{}", sequence),
        key_id: Some(format!("key_{}", sequence)),
        result: OperationResult::Success,
        prev_hash: "0".repeat(64),
        current_hash: format!("{:064x}", sequence),
        metadata: None,
    }
}

/// Benchmark Lasso lookup argument
fn bench_lasso_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("lasso_lookup");

    for table_size in [16, 64, 256, 1024].iter() {
        group.throughput(Throughput::Elements(*table_size as u64));

        let values: Vec<Fr> = (0..*table_size).map(|i| Fr::from(i as u64)).collect();
        let table = LookupTable::new(format!("table_{}", table_size), values);
        let lookup_arg = LookupArgument::new(table);

        let indices: Vec<usize> = (0..(*table_size / 2)).collect();

        group.bench_with_input(BenchmarkId::new("prove", table_size), table_size, |b, _| {
            let mut rng = test_rng();
            b.iter(|| {
                let proof = lookup_arg.prove(black_box(&indices), &mut rng);
                black_box(proof)
            });
        });

        let mut rng = test_rng();
        let proof = lookup_arg.prove(&indices, &mut rng).unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify", table_size),
            table_size,
            |b, _| {
                b.iter(|| {
                    let valid = lookup_arg.verify(black_box(&proof));
                    black_box(valid)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark Merkle tree proof generation
fn bench_merkle_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_generation");

    // Initialize proof system once
    let mut proof_system = ProofSystem::new().unwrap();
    proof_system.initialize(1024, 10).unwrap();

    for num_leaves in [8, 64, 256, 1000].iter() {
        group.throughput(Throughput::Elements(*num_leaves as u64));

        let leaf_hashes: Vec<[u8; 32]> = (0..*num_leaves)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[0] = (i % 256) as u8;
                hash[1] = ((i / 256) % 256) as u8;
                hash
            })
            .collect();

        let merkle_root = [1u8; 32]; // Simplified

        let request = MerkleProofRequest {
            leaf_hashes: leaf_hashes.clone(),
            expected_root: merkle_root,
        };

        group.bench_with_input(
            BenchmarkId::new("generate", num_leaves),
            num_leaves,
            |b, _| {
                let mut local_proof_system = ProofSystem::new().unwrap();
                local_proof_system.initialize(1024, 10).unwrap();

                b.iter(|| {
                    let result = local_proof_system.prove_merkle_integrity(black_box(&request));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark Merkle tree proof verification
fn bench_merkle_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_verification");

    let mut proof_system = ProofSystem::new().unwrap();
    proof_system.initialize(128, 8).unwrap();

    for num_leaves in [8, 64].iter() {
        let leaf_hashes: Vec<[u8; 32]> = (0..*num_leaves)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[0] = i as u8;
                hash
            })
            .collect();

        let request = MerkleProofRequest {
            leaf_hashes,
            expected_root: [1u8; 32],
        };

        let (proof, _) = proof_system.prove_merkle_integrity(&request).unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify", num_leaves),
            num_leaves,
            |b, _| {
                b.iter(|| {
                    let valid = proof_system.verify_merkle_proof(black_box(&proof));
                    black_box(valid)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark event existence proof generation
fn bench_event_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_proof_generation");

    let mut proof_system = ProofSystem::new().unwrap();
    proof_system.initialize(16, 4).unwrap();

    let event = create_test_event(42);

    for merkle_depth in [0, 2, 4, 8].iter() {
        let merkle_path: Vec<[u8; 32]> =
            (0..*merkle_depth).map(|i| [(i % 256) as u8; 32]).collect();

        let request = EventProofRequest {
            event: event.clone(),
            merkle_root: [0u8; 32],
            merkle_path: merkle_path.clone(),
        };

        group.bench_with_input(
            BenchmarkId::new("generate", merkle_depth),
            merkle_depth,
            |b, _| {
                let mut local_proof_system = ProofSystem::new().unwrap();
                local_proof_system.initialize(16, 4).unwrap();

                b.iter(|| {
                    let result = local_proof_system.prove_event_existence(black_box(&request));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark event existence proof verification
fn bench_event_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_proof_verification");

    let mut proof_system = ProofSystem::new().unwrap();
    proof_system.initialize(16, 4).unwrap();

    let event = create_test_event(100);

    let request = EventProofRequest {
        event,
        merkle_root: [0u8; 32],
        merkle_path: vec![],
    };

    let (proof, _) = proof_system.prove_event_existence(&request).unwrap();

    group.bench_function("verify_event_proof", |b| {
        b.iter(|| {
            let valid = proof_system.verify_event_proof(black_box(&proof));
            black_box(valid)
        });
    });

    group.finish();
}

/// Benchmark proof size
fn bench_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_size");

    let mut proof_system = ProofSystem::new().unwrap();
    proof_system.initialize(64, 4).unwrap();

    // Merkle proof
    let merkle_request = MerkleProofRequest {
        leaf_hashes: vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]],
        expected_root: [0u8; 32],
    };

    let (merkle_proof, merkle_metrics) = proof_system
        .prove_merkle_integrity(&merkle_request)
        .unwrap();
    println!("Merkle proof size: {} bytes", merkle_metrics.proof_size);
    assert!(
        merkle_metrics.proof_size < 1024,
        "Merkle proof size {} exceeds 1KB target",
        merkle_metrics.proof_size
    );

    // Event proof
    let event = create_test_event(1);
    let event_request = EventProofRequest {
        event,
        merkle_root: [0u8; 32],
        merkle_path: vec![],
    };

    let (event_proof, event_metrics) = proof_system.prove_event_existence(&event_request).unwrap();
    println!("Event proof size: {} bytes", event_metrics.proof_size);
    assert!(
        event_metrics.proof_size < 1024,
        "Event proof size {} exceeds 1KB target",
        event_metrics.proof_size
    );

    group.finish();
}

/// Benchmark end-to-end workflow
fn bench_end_to_end_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end_workflow");

    group.bench_function("full_workflow", |b| {
        b.iter(|| {
            // Initialize proof system
            let mut proof_system = ProofSystem::new().unwrap();
            proof_system.initialize(16, 4).unwrap();

            // Create event
            let event = create_test_event(1);

            // Generate proof
            let request = EventProofRequest {
                event,
                merkle_root: [0u8; 32],
                merkle_path: vec![],
            };

            let (proof, metrics) = proof_system.prove_event_existence(&request).unwrap();

            // Verify proof
            let valid = proof_system.verify_event_proof(&proof).unwrap();

            black_box((valid, metrics))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_lasso_lookup,
    bench_merkle_proof_generation,
    bench_merkle_proof_verification,
    bench_event_proof_generation,
    bench_event_proof_verification,
    bench_proof_size,
    bench_end_to_end_workflow,
);
criterion_main!(benches);
