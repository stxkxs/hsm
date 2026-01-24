//! Benchmarks for Threshold Cryptography Operations
//!
//! This benchmark suite measures performance of:
//! - Distributed Key Generation (DKG) for various configurations
//! - Threshold signing operations (FROST, ECDSA, BLS)
//!
//! Run with: cargo bench -p hsm-crypto-engine --bench threshold_bench
//! Quick test: cargo bench -p hsm-crypto-engine --bench threshold_bench -- --test

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use hsm_crypto_engine::threshold::{
    bls::{dkg::BlsDkg, BlsKeyShare, ThresholdBlsEngine},
    config::DkgConfig,
    ecdsa::{dkg::EcdsaDkg, EcdsaGroupPublicKey, EcdsaKeyShare, ThresholdEcdsaEngine},
    types::EcdsaCurve,
    FrostEngine, GroupPublicKey, ParticipantId, ThresholdConfig, ThresholdScheme,
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Setup FROST shares for signing benchmarks
fn setup_frost_shares(
    threshold: u16,
    total: u16,
) -> (
    GroupPublicKey,
    Vec<hsm_crypto_engine::threshold::types::KeyShare>,
) {
    let config = ThresholdConfig::new(threshold, total).unwrap();
    FrostEngine::trusted_dealer_keygen(config).unwrap()
}

/// Setup ECDSA keys via trusted dealer
fn setup_ecdsa_keys(
    threshold: u16,
    total: u16,
    curve: EcdsaCurve,
) -> (EcdsaGroupPublicKey, Vec<EcdsaKeyShare>) {
    let config = ThresholdConfig::new(threshold, total).unwrap();
    ThresholdEcdsaEngine::trusted_dealer_keygen(config, curve).unwrap()
}

/// Run full ECDSA DKG
fn run_ecdsa_dkg_full(
    threshold: u16,
    total: u16,
    curve: EcdsaCurve,
) -> (Vec<EcdsaKeyShare>, EcdsaGroupPublicKey) {
    let participants: Vec<ParticipantId> = (1..=total).map(ParticipantId).collect();
    let scheme = match curve {
        EcdsaCurve::P256 => ThresholdScheme::ThresholdEcdsaP256,
        EcdsaCurve::Secp256k1 => ThresholdScheme::ThresholdEcdsaSecp256k1,
    };
    let config = DkgConfig::new(scheme, threshold, participants.clone()).unwrap();

    let mut dkgs: Vec<EcdsaDkg> = participants
        .iter()
        .map(|&p| EcdsaDkg::new(config.clone(), p, curve).unwrap())
        .collect();

    // Round 1
    let r1_packages: Vec<_> = dkgs
        .iter_mut()
        .map(|dkg| dkg.round1_generate_commitments().unwrap())
        .collect();

    for (i, dkg) in dkgs.iter_mut().enumerate() {
        let others: Vec<_> = r1_packages
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, p)| p.clone())
            .collect();
        dkg.round1_receive_commitments(others).unwrap();
    }

    // Round 2
    let r2_packages: Vec<Vec<_>> = dkgs
        .iter_mut()
        .map(|dkg| dkg.round2_generate_shares().unwrap())
        .collect();

    for (i, dkg) in dkgs.iter_mut().enumerate() {
        let receiver_id = participants[i];
        let shares: Vec<_> = r2_packages
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .flat_map(|(_, pkgs)| pkgs.iter().filter(|p| p.receiver == receiver_id).cloned())
            .collect();
        dkg.round2_receive_shares(shares).unwrap();
    }

    // Finalize
    let results: Vec<_> = dkgs.into_iter().map(|dkg| dkg.finalize()).collect();
    let mut shares = Vec::new();
    let mut group_key = None;

    for result in results {
        let (share, gk) = result.unwrap();
        shares.push(share);
        if group_key.is_none() {
            group_key = Some(gk);
        }
    }

    (shares, group_key.unwrap())
}

/// Run full BLS DKG
fn run_bls_dkg_full(threshold: u16, total: u16) -> (Vec<BlsKeyShare>, GroupPublicKey) {
    let participants: Vec<ParticipantId> = (1..=total).map(ParticipantId).collect();
    let config = DkgConfig::new(
        ThresholdScheme::ThresholdBls12381,
        threshold,
        participants.clone(),
    )
    .unwrap();

    let mut dkgs: Vec<BlsDkg> = participants
        .iter()
        .map(|&p| BlsDkg::new(config.clone(), p).unwrap())
        .collect();

    // Round 1
    let r1_packages: Vec<_> = dkgs.iter_mut().map(|dkg| dkg.round1().unwrap()).collect();

    // Round 2
    let r2_packages: Vec<Vec<_>> = dkgs
        .iter_mut()
        .map(|dkg| dkg.round2(r1_packages.clone()).unwrap())
        .collect();

    // Collect packages per participant
    let mut packages_per_participant: Vec<Vec<_>> = vec![Vec::new(); total as usize];
    for sender_packages in r2_packages {
        for pkg in sender_packages {
            let receiver_idx = (pkg.receiver.0 - 1) as usize;
            packages_per_participant[receiver_idx].push(pkg);
        }
    }

    // Finalize
    let mut shares = Vec::new();
    let mut group_pk = None;

    for (i, dkg) in dkgs.iter_mut().enumerate() {
        let (share, gpk) = dkg.finalize(packages_per_participant[i].clone()).unwrap();
        shares.push(share);
        group_pk = Some(gpk);
    }

    (shares, group_pk.unwrap())
}

/// Setup BLS keys via trusted dealer
fn setup_bls_keys(threshold: u16, total: u16) -> (GroupPublicKey, Vec<BlsKeyShare>) {
    let config = ThresholdConfig::new(threshold, total).unwrap();
    ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap()
}

// ============================================================================
// DKG Benchmarks
// ============================================================================

fn bench_dkg_frost_trusted_dealer(c: &mut Criterion) {
    let mut group = c.benchmark_group("dkg_frost_trusted_dealer");

    for (threshold, total) in [(2, 3), (3, 5), (5, 9)] {
        group.bench_with_input(
            BenchmarkId::new("keygen", format!("{}_of_{}", threshold, total)),
            &(threshold, total),
            |b, &(t, n)| {
                b.iter(|| {
                    let config = ThresholdConfig::new(t, n).unwrap();
                    FrostEngine::trusted_dealer_keygen(black_box(config))
                });
            },
        );
    }

    group.finish();
}

fn bench_dkg_ecdsa_p256(c: &mut Criterion) {
    let mut group = c.benchmark_group("dkg_ecdsa_p256");
    group.sample_size(10); // DKG is slow, use fewer samples

    for (threshold, total) in [(2, 3), (3, 5)] {
        group.bench_with_input(
            BenchmarkId::new("full_dkg", format!("{}_of_{}", threshold, total)),
            &(threshold, total),
            |b, &(t, n)| {
                b.iter(|| run_ecdsa_dkg_full(black_box(t), black_box(n), EcdsaCurve::P256));
            },
        );
    }

    group.finish();
}

fn bench_dkg_ecdsa_secp256k1(c: &mut Criterion) {
    let mut group = c.benchmark_group("dkg_ecdsa_secp256k1");
    group.sample_size(10);

    for (threshold, total) in [(2, 3), (3, 5)] {
        group.bench_with_input(
            BenchmarkId::new("full_dkg", format!("{}_of_{}", threshold, total)),
            &(threshold, total),
            |b, &(t, n)| {
                b.iter(|| run_ecdsa_dkg_full(black_box(t), black_box(n), EcdsaCurve::Secp256k1));
            },
        );
    }

    group.finish();
}

fn bench_dkg_bls(c: &mut Criterion) {
    let mut group = c.benchmark_group("dkg_bls");
    group.sample_size(10);

    for (threshold, total) in [(2, 3), (3, 5)] {
        group.bench_with_input(
            BenchmarkId::new("full_dkg", format!("{}_of_{}", threshold, total)),
            &(threshold, total),
            |b, &(t, n)| {
                b.iter(|| run_bls_dkg_full(black_box(t), black_box(n)));
            },
        );
    }

    group.finish();
}

fn bench_dkg_bls_trusted_dealer(c: &mut Criterion) {
    let mut group = c.benchmark_group("dkg_bls_trusted_dealer");

    for (threshold, total) in [(2, 3), (3, 5), (5, 9)] {
        group.bench_with_input(
            BenchmarkId::new("keygen", format!("{}_of_{}", threshold, total)),
            &(threshold, total),
            |b, &(t, n)| {
                b.iter(|| {
                    let config = ThresholdConfig::new(t, n).unwrap();
                    ThresholdBlsEngine::trusted_dealer_keygen(black_box(config))
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Signing Benchmarks
// ============================================================================

fn bench_frost_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("frost_signing");
    group.throughput(Throughput::Elements(1));

    // Setup 2-of-3 keys
    let (group_key, shares) = setup_frost_shares(2, 3);
    let message = b"benchmark message for FROST signing";

    group.bench_function("generate_nonces", |b| {
        b.iter(|| FrostEngine::generate_nonces(black_box(&shares[0])));
    });

    group.bench_function("sign_share_2_of_3", |b| {
        // Need fresh nonces each time to avoid reuse
        b.iter_batched(
            || {
                let (n0, c0) = FrostEngine::generate_nonces(&shares[0]).unwrap();
                let (n1, c1) = FrostEngine::generate_nonces(&shares[1]).unwrap();
                (n0, n1, vec![c0, c1])
            },
            |(n0, _n1, commits)| {
                FrostEngine::sign_share(
                    black_box(&shares[0]),
                    black_box(&n0),
                    black_box(message),
                    black_box(&commits),
                    black_box(&group_key),
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("aggregate_2_of_3", |b| {
        b.iter_batched(
            || {
                let (n0, c0) = FrostEngine::generate_nonces(&shares[0]).unwrap();
                let (n1, c1) = FrostEngine::generate_nonces(&shares[1]).unwrap();
                let commits = vec![c0, c1];
                let s0 = FrostEngine::sign_share(&shares[0], &n0, message, &commits, &group_key)
                    .unwrap();
                let s1 = FrostEngine::sign_share(&shares[1], &n1, message, &commits, &group_key)
                    .unwrap();
                (commits, vec![s0, s1])
            },
            |(commits, sig_shares)| {
                FrostEngine::aggregate_signatures(
                    black_box(message),
                    black_box(&commits),
                    black_box(&sig_shares),
                    black_box(&group_key),
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("verify", |b| {
        let (n0, c0) = FrostEngine::generate_nonces(&shares[0]).unwrap();
        let (n1, c1) = FrostEngine::generate_nonces(&shares[1]).unwrap();
        let commits = vec![c0, c1];
        let s0 = FrostEngine::sign_share(&shares[0], &n0, message, &commits, &group_key).unwrap();
        let s1 = FrostEngine::sign_share(&shares[1], &n1, message, &commits, &group_key).unwrap();
        let signature =
            FrostEngine::aggregate_signatures(message, &commits, &[s0, s1], &group_key).unwrap();

        b.iter(|| {
            FrostEngine::verify(
                black_box(&group_key),
                black_box(message),
                black_box(&signature),
            )
        });
    });

    group.bench_function("full_signing_2_of_3", |b| {
        b.iter_batched(
            || {},
            |_| {
                let (n0, c0) = FrostEngine::generate_nonces(&shares[0]).unwrap();
                let (n1, c1) = FrostEngine::generate_nonces(&shares[1]).unwrap();
                let commits = vec![c0, c1];
                let s0 = FrostEngine::sign_share(&shares[0], &n0, message, &commits, &group_key)
                    .unwrap();
                let s1 = FrostEngine::sign_share(&shares[1], &n1, message, &commits, &group_key)
                    .unwrap();
                let signature =
                    FrostEngine::aggregate_signatures(message, &commits, &[s0, s1], &group_key)
                        .unwrap();
                let _valid = FrostEngine::verify(&group_key, message, &signature).unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_ecdsa_p256_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa_p256_signing");
    group.throughput(Throughput::Elements(1));

    // Setup 2-of-3 keys
    let (group_key, shares) = setup_ecdsa_keys(2, 3, EcdsaCurve::P256);
    let message = b"benchmark message for ECDSA P-256";
    let message_hash = ThresholdEcdsaEngine::hash_message(message);

    group.bench_function("generate_nonces", |b| {
        b.iter(|| ThresholdEcdsaEngine::generate_nonces(black_box(&shares[0])));
    });

    group.bench_function("presign_2_of_3", |b| {
        let (nonce0, commitment0) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
        let (_nonce1, commitment1) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
        let commitments = vec![commitment0, commitment1];
        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        b.iter(|| {
            ThresholdEcdsaEngine::presign(
                black_box(&shares[0]),
                black_box(&nonce0),
                black_box(&commitments),
                black_box(&participants),
            )
        });
    });

    group.bench_function("sign_share_2_of_3", |b| {
        b.iter_batched(
            || {
                let (n0, c0) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
                let (n1, c1) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
                let commits = vec![c0, c1];
                let participants = vec![shares[0].participant_id, shares[1].participant_id];
                let presig0 =
                    ThresholdEcdsaEngine::presign(&shares[0], &n0, &commits, &participants)
                        .unwrap();
                (presig0,)
            },
            |(presig0,)| {
                ThresholdEcdsaEngine::sign_share(
                    black_box(&shares[0]),
                    black_box(&presig0),
                    black_box(&message_hash),
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("full_signing_2_of_3", |b| {
        b.iter_batched(
            || {},
            |_| {
                let (n0, c0) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
                let (_n1, c1) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
                let commits = vec![c0, c1];
                let participants = vec![shares[0].participant_id, shares[1].participant_id];

                let presig0 =
                    ThresholdEcdsaEngine::presign(&shares[0], &n0, &commits, &participants)
                        .unwrap();
                let presig1 =
                    ThresholdEcdsaEngine::presign(&shares[1], &n0, &commits, &participants)
                        .unwrap();

                let sig0 =
                    ThresholdEcdsaEngine::sign_share(&shares[0], &presig0, &message_hash).unwrap();
                let sig1 =
                    ThresholdEcdsaEngine::sign_share(&shares[1], &presig1, &message_hash).unwrap();

                let _signature = ThresholdEcdsaEngine::aggregate(
                    &group_key,
                    &presig0,
                    &[sig0, sig1],
                    &participants,
                )
                .unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_ecdsa_secp256k1_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa_secp256k1_signing");
    group.throughput(Throughput::Elements(1));

    // Setup 2-of-3 keys
    let (group_key, shares) = setup_ecdsa_keys(2, 3, EcdsaCurve::Secp256k1);
    let message = b"benchmark message for ECDSA secp256k1";
    let message_hash = ThresholdEcdsaEngine::hash_message(message);

    group.bench_function("full_signing_2_of_3", |b| {
        b.iter_batched(
            || {},
            |_| {
                let (n0, c0) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
                let (_n1, c1) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
                let commits = vec![c0, c1];
                let participants = vec![shares[0].participant_id, shares[1].participant_id];

                let presig0 =
                    ThresholdEcdsaEngine::presign(&shares[0], &n0, &commits, &participants)
                        .unwrap();
                let presig1 =
                    ThresholdEcdsaEngine::presign(&shares[1], &n0, &commits, &participants)
                        .unwrap();

                let sig0 =
                    ThresholdEcdsaEngine::sign_share(&shares[0], &presig0, &message_hash).unwrap();
                let sig1 =
                    ThresholdEcdsaEngine::sign_share(&shares[1], &presig1, &message_hash).unwrap();

                let _signature = ThresholdEcdsaEngine::aggregate(
                    &group_key,
                    &presig0,
                    &[sig0, sig1],
                    &participants,
                )
                .unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_bls_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("bls_signing");
    group.throughput(Throughput::Elements(1));

    // Setup 2-of-3 keys
    let (group_key, shares) = setup_bls_keys(2, 3);
    let message = b"benchmark message for BLS signing";

    group.bench_function("sign_share", |b| {
        b.iter(|| ThresholdBlsEngine::sign_share(black_box(&shares[0]), black_box(message)));
    });

    group.bench_function("aggregate_2_of_3", |b| {
        let sig0 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let sig1 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        b.iter(|| {
            ThresholdBlsEngine::aggregate(
                black_box(&[sig0.clone(), sig1.clone()]),
                black_box(&participants),
            )
        });
    });

    group.bench_function("verify", |b| {
        let sig0 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let sig1 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
        let participants = vec![shares[0].participant_id, shares[1].participant_id];
        let signature = ThresholdBlsEngine::aggregate(&[sig0, sig1], &participants).unwrap();

        b.iter(|| {
            ThresholdBlsEngine::verify(
                black_box(&group_key),
                black_box(message),
                black_box(&signature),
            )
        });
    });

    group.bench_function("full_signing_2_of_3", |b| {
        b.iter(|| {
            let sig0 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
            let sig1 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
            let participants = vec![shares[0].participant_id, shares[1].participant_id];
            let signature = ThresholdBlsEngine::aggregate(&[sig0, sig1], &participants).unwrap();
            let _valid = ThresholdBlsEngine::verify(&group_key, message, &signature).unwrap();
        });
    });

    group.finish();
}

// ============================================================================
// Comparative Signing Benchmarks
// ============================================================================

fn bench_signing_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing_comparison");
    group.throughput(Throughput::Elements(1));

    let message = b"comparison benchmark message";

    // FROST Ed25519
    let (frost_key, frost_shares) = setup_frost_shares(2, 3);
    group.bench_function("frost_ed25519_full", |b| {
        b.iter_batched(
            || {},
            |_| {
                let (n0, c0) = FrostEngine::generate_nonces(&frost_shares[0]).unwrap();
                let (n1, c1) = FrostEngine::generate_nonces(&frost_shares[1]).unwrap();
                let commits = vec![c0, c1];
                let s0 =
                    FrostEngine::sign_share(&frost_shares[0], &n0, message, &commits, &frost_key)
                        .unwrap();
                let s1 =
                    FrostEngine::sign_share(&frost_shares[1], &n1, message, &commits, &frost_key)
                        .unwrap();
                FrostEngine::aggregate_signatures(message, &commits, &[s0, s1], &frost_key).unwrap()
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // ECDSA P-256
    let (p256_key, p256_shares) = setup_ecdsa_keys(2, 3, EcdsaCurve::P256);
    let message_hash = ThresholdEcdsaEngine::hash_message(message);
    group.bench_function("ecdsa_p256_full", |b| {
        b.iter_batched(
            || {},
            |_| {
                let (n0, c0) = ThresholdEcdsaEngine::generate_nonces(&p256_shares[0]).unwrap();
                let (_n1, c1) = ThresholdEcdsaEngine::generate_nonces(&p256_shares[1]).unwrap();
                let commits = vec![c0, c1];
                let participants =
                    vec![p256_shares[0].participant_id, p256_shares[1].participant_id];
                let presig0 =
                    ThresholdEcdsaEngine::presign(&p256_shares[0], &n0, &commits, &participants)
                        .unwrap();
                let presig1 =
                    ThresholdEcdsaEngine::presign(&p256_shares[1], &n0, &commits, &participants)
                        .unwrap();
                let sig0 =
                    ThresholdEcdsaEngine::sign_share(&p256_shares[0], &presig0, &message_hash)
                        .unwrap();
                let sig1 =
                    ThresholdEcdsaEngine::sign_share(&p256_shares[1], &presig1, &message_hash)
                        .unwrap();
                ThresholdEcdsaEngine::aggregate(&p256_key, &presig0, &[sig0, sig1], &participants)
                    .unwrap()
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // ECDSA secp256k1
    let (secp256k1_key, secp256k1_shares) = setup_ecdsa_keys(2, 3, EcdsaCurve::Secp256k1);
    group.bench_function("ecdsa_secp256k1_full", |b| {
        b.iter_batched(
            || {},
            |_| {
                let (n0, c0) = ThresholdEcdsaEngine::generate_nonces(&secp256k1_shares[0]).unwrap();
                let (_n1, c1) =
                    ThresholdEcdsaEngine::generate_nonces(&secp256k1_shares[1]).unwrap();
                let commits = vec![c0, c1];
                let participants = vec![
                    secp256k1_shares[0].participant_id,
                    secp256k1_shares[1].participant_id,
                ];
                let presig0 = ThresholdEcdsaEngine::presign(
                    &secp256k1_shares[0],
                    &n0,
                    &commits,
                    &participants,
                )
                .unwrap();
                let presig1 = ThresholdEcdsaEngine::presign(
                    &secp256k1_shares[1],
                    &n0,
                    &commits,
                    &participants,
                )
                .unwrap();
                let sig0 =
                    ThresholdEcdsaEngine::sign_share(&secp256k1_shares[0], &presig0, &message_hash)
                        .unwrap();
                let sig1 =
                    ThresholdEcdsaEngine::sign_share(&secp256k1_shares[1], &presig1, &message_hash)
                        .unwrap();
                ThresholdEcdsaEngine::aggregate(
                    &secp256k1_key,
                    &presig0,
                    &[sig0, sig1],
                    &participants,
                )
                .unwrap()
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // BLS
    let (_bls_key, bls_shares) = setup_bls_keys(2, 3);
    group.bench_function("bls_full", |b| {
        b.iter(|| {
            let sig0 = ThresholdBlsEngine::sign_share(&bls_shares[0], message).unwrap();
            let sig1 = ThresholdBlsEngine::sign_share(&bls_shares[1], message).unwrap();
            let participants = vec![bls_shares[0].participant_id, bls_shares[1].participant_id];
            ThresholdBlsEngine::aggregate(&[sig0, sig1], &participants).unwrap()
        });
    });

    group.finish();
}

// ============================================================================
// Scaling Benchmarks
// ============================================================================

fn bench_scaling_with_participants(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling");
    group.sample_size(10);

    let message = b"scaling benchmark message";

    // Test FROST signing with increasing participants
    for (threshold, total) in [(2, 3), (3, 5), (5, 9)] {
        let (group_key, shares) = setup_frost_shares(threshold, total);
        let selected_indices: Vec<usize> = (0..threshold as usize).collect();

        group.bench_with_input(
            BenchmarkId::new("frost_signing", format!("{}_of_{}", threshold, total)),
            &(threshold, total),
            |b, _| {
                b.iter_batched(
                    || {},
                    |_| {
                        let mut nonces = Vec::new();
                        let mut commitments = Vec::new();
                        for &idx in &selected_indices {
                            let (nonce, commitment) =
                                FrostEngine::generate_nonces(&shares[idx]).unwrap();
                            nonces.push(nonce);
                            commitments.push(commitment);
                        }

                        let mut sig_shares = Vec::new();
                        for (i, &idx) in selected_indices.iter().enumerate() {
                            let sig = FrostEngine::sign_share(
                                &shares[idx],
                                &nonces[i],
                                message,
                                &commitments,
                                &group_key,
                            )
                            .unwrap();
                            sig_shares.push(sig);
                        }

                        FrostEngine::aggregate_signatures(
                            message,
                            &commitments,
                            &sig_shares,
                            &group_key,
                        )
                        .unwrap()
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    // Test BLS signing with increasing participants
    for (threshold, total) in [(2, 3), (3, 5), (5, 9)] {
        let (_group_key, shares) = setup_bls_keys(threshold, total);
        let selected_indices: Vec<usize> = (0..threshold as usize).collect();

        group.bench_with_input(
            BenchmarkId::new("bls_signing", format!("{}_of_{}", threshold, total)),
            &(threshold, total),
            |b, _| {
                b.iter(|| {
                    let sig_shares: Vec<_> = selected_indices
                        .iter()
                        .map(|&idx| ThresholdBlsEngine::sign_share(&shares[idx], message).unwrap())
                        .collect();

                    let participants: Vec<_> = selected_indices
                        .iter()
                        .map(|&idx| shares[idx].participant_id)
                        .collect();

                    ThresholdBlsEngine::aggregate(&sig_shares, &participants).unwrap()
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Benchmark Groups
// ============================================================================

criterion_group!(
    dkg_benches,
    bench_dkg_frost_trusted_dealer,
    bench_dkg_ecdsa_p256,
    bench_dkg_ecdsa_secp256k1,
    bench_dkg_bls,
    bench_dkg_bls_trusted_dealer,
);

criterion_group!(
    signing_benches,
    bench_frost_signing,
    bench_ecdsa_p256_signing,
    bench_ecdsa_secp256k1_signing,
    bench_bls_signing,
    bench_signing_comparison,
    bench_scaling_with_participants,
);

criterion_main!(dkg_benches, signing_benches);
