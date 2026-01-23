//! Benchmarks for anti-slashing operations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hsm_validator::slashing_db::SlashingProtectionDb;
use hsm_validator::types::SigningRoot;

fn random_root() -> SigningRoot {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).unwrap();
    SigningRoot::new(bytes)
}

fn random_pubkey() -> Vec<u8> {
    let mut bytes = vec![0u8; 48];
    getrandom::getrandom(&mut bytes).unwrap();
    bytes
}

fn bench_attestation_check(c: &mut Criterion) {
    let db = SlashingProtectionDb::in_memory().unwrap();
    let pubkey = random_pubkey();
    db.register_validator(&pubkey).unwrap();

    let mut group = c.benchmark_group("attestation_check");

    // Benchmark with varying number of existing attestations
    for n_existing in [0, 100, 1000, 10000].iter() {
        // Pre-populate with attestations
        let test_db = SlashingProtectionDb::in_memory().unwrap();
        let test_pubkey = random_pubkey();
        test_db.register_validator(&test_pubkey).unwrap();

        for i in 0..*n_existing {
            let root = random_root();
            test_db
                .check_and_record_attestation(&test_pubkey, i * 10, i * 10 + 5, &root)
                .unwrap();
        }

        group.bench_with_input(
            BenchmarkId::new("existing_attestations", n_existing),
            n_existing,
            |b, &n| {
                let mut epoch = n * 10 + 100;
                b.iter(|| {
                    let root = random_root();
                    let result = test_db.check_and_record_attestation(
                        black_box(&test_pubkey),
                        black_box(epoch),
                        black_box(epoch + 5),
                        black_box(&root),
                    );
                    epoch += 10;
                    result
                });
            },
        );
    }

    group.finish();
}

fn bench_block_check(c: &mut Criterion) {
    let db = SlashingProtectionDb::in_memory().unwrap();
    let pubkey = random_pubkey();
    db.register_validator(&pubkey).unwrap();

    let mut group = c.benchmark_group("block_check");

    for n_existing in [0, 100, 1000, 10000].iter() {
        let test_db = SlashingProtectionDb::in_memory().unwrap();
        let test_pubkey = random_pubkey();
        test_db.register_validator(&test_pubkey).unwrap();

        for i in 0..*n_existing {
            let root = random_root();
            test_db
                .check_and_record_block(&test_pubkey, i as u64, &root)
                .unwrap();
        }

        group.bench_with_input(
            BenchmarkId::new("existing_blocks", n_existing),
            n_existing,
            |b, &n| {
                let mut slot = n as u64 + 100;
                b.iter(|| {
                    let root = random_root();
                    let result = test_db.check_and_record_block(
                        black_box(&test_pubkey),
                        black_box(slot),
                        black_box(&root),
                    );
                    slot += 1;
                    result
                });
            },
        );
    }

    group.finish();
}

fn bench_concurrent_validators(c: &mut Criterion) {
    let db = SlashingProtectionDb::in_memory().unwrap();

    // Register multiple validators
    let mut pubkeys = Vec::new();
    for _ in 0..100 {
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();
        pubkeys.push(pubkey);
    }

    c.bench_function("concurrent_validators_attestation", |b| {
        let mut idx = 0;
        let mut epoch = 0u64;
        b.iter(|| {
            let pubkey = &pubkeys[idx % pubkeys.len()];
            let root = random_root();
            let result = db.check_and_record_attestation(
                black_box(pubkey),
                black_box(epoch),
                black_box(epoch + 5),
                black_box(&root),
            );
            idx += 1;
            epoch += 10;
            result
        });
    });
}

criterion_group!(
    benches,
    bench_attestation_check,
    bench_block_check,
    bench_concurrent_validators,
);

criterion_main!(benches);
