//! Benchmarks for formal verification operations
//!
//! Measures performance of SMT solver-based verification for different
//! cryptographic operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hsm_verification::*;

fn bench_ed25519_verification(c: &mut Criterion) {
    c.bench_function("ed25519_signature_soundness", |b| {
        b.iter(|| black_box(ed25519::Ed25519Verifier::verify_signature_soundness()).unwrap())
    });

    c.bench_function("ed25519_scalar_mult_properties", |b| {
        b.iter(|| black_box(ed25519::Ed25519Verifier::verify_scalar_mult_properties()).unwrap())
    });

    c.bench_function("ed25519_verification_equation", |b| {
        b.iter(|| black_box(ed25519::Ed25519Verifier::verify_verification_equation()).unwrap())
    });
}

fn bench_ecdsa_verification(c: &mut Criterion) {
    c.bench_function("ecdsa_nonce_uniqueness", |b| {
        b.iter(|| black_box(ecdsa::EcdsaVerifier::verify_nonce_uniqueness()).unwrap())
    });

    c.bench_function("ecdsa_signature_equation", |b| {
        b.iter(|| black_box(ecdsa::EcdsaVerifier::verify_signature_equation()).unwrap())
    });

    c.bench_function("ecdsa_low_s_requirement", |b| {
        b.iter(|| black_box(ecdsa::EcdsaVerifier::verify_low_s_requirement()).unwrap())
    });

    c.bench_function("ecdsa_nonce_reuse_prevention", |b| {
        b.iter(|| black_box(ecdsa::EcdsaVerifier::verify_nonce_reuse_attack_prevention()).unwrap())
    });
}

fn bench_rsa_verification(c: &mut Criterion) {
    c.bench_function("rsa_correctness", |b| {
        b.iter(|| black_box(rsa::RsaVerifier::verify_rsa_correctness()).unwrap())
    });

    c.bench_function("rsa_pkcs1v15_padding", |b| {
        b.iter(|| black_box(rsa::RsaVerifier::verify_pkcs1v15_padding_format()).unwrap())
    });

    c.bench_function("rsa_constant_time_check", |b| {
        b.iter(|| black_box(rsa::RsaVerifier::verify_constant_time_padding_check()).unwrap())
    });

    c.bench_function("rsa_pss_padding", |b| {
        b.iter(|| black_box(rsa::RsaVerifier::verify_pss_padding_format()).unwrap())
    });
}

fn bench_shamir_verification(c: &mut Criterion) {
    c.bench_function("shamir_polynomial_construction", |b| {
        b.iter(|| black_box(shamir::ShamirVerifier::verify_polynomial_construction()).unwrap())
    });

    c.bench_function("shamir_lagrange_interpolation", |b| {
        b.iter(|| black_box(shamir::ShamirVerifier::verify_lagrange_interpolation()).unwrap())
    });

    c.bench_function("shamir_information_theoretic_security", |b| {
        b.iter(|| {
            black_box(shamir::ShamirVerifier::verify_information_theoretic_security()).unwrap()
        })
    });

    c.bench_function("shamir_share_consistency", |b| {
        b.iter(|| black_box(shamir::ShamirVerifier::verify_share_consistency()).unwrap())
    });
}

fn bench_smt_encoder_operations(c: &mut Criterion) {
    use hsm_verification::smt_encoder::FiniteFieldEncoder;
    use z3::{Config, Context};

    c.bench_function("smt_encoder_modular_addition", |b| {
        b.iter(|| {
            let cfg = Config::new();
            let ctx = Context::new(&cfg);
            let encoder = FiniteFieldEncoder::new(&ctx, 256);

            let a = encoder.bv_from_u64(black_box(12345));
            let b = encoder.bv_from_u64(black_box(67890));
            let m = encoder.bv_from_u64(black_box(100000));

            black_box(encoder.mod_add(&a, &b, &m))
        })
    });

    c.bench_function("smt_encoder_modular_multiplication", |b| {
        b.iter(|| {
            let cfg = Config::new();
            let ctx = Context::new(&cfg);
            let encoder = FiniteFieldEncoder::new(&ctx, 256);

            let a = encoder.bv_from_u64(black_box(123));
            let b = encoder.bv_from_u64(black_box(456));
            let m = encoder.bv_from_u64(black_box(1000));

            black_box(encoder.mod_mul(&a, &b, &m))
        })
    });

    c.bench_function("smt_encoder_constant_time_equality", |b| {
        b.iter(|| {
            let cfg = Config::new();
            let ctx = Context::new(&cfg);
            let encoder = FiniteFieldEncoder::new(&ctx, 256);

            let a = encoder.bv_from_u64(black_box(42));
            let b = encoder.bv_from_u64(black_box(42));

            black_box(encoder.ct_eq(&a, &b))
        })
    });
}

fn bench_bounded_checker(c: &mut Criterion) {
    use hsm_verification::bounded_check::BoundedChecker;
    use z3::{Config, Context};

    c.bench_function("bounded_checker_tautology_check", |b| {
        b.iter(|| {
            let cfg = Config::new();
            let ctx = Context::new(&cfg);
            let checker = BoundedChecker::new(&ctx, 8);

            let x = checker.encoder().bv_const("x");
            let property = x._eq(&x);

            black_box(checker.verify_property(&property)).unwrap()
        })
    });

    c.bench_function("bounded_checker_forall_verification", |b| {
        b.iter(|| {
            let cfg = Config::new();
            let ctx = Context::new(&cfg);
            let checker = BoundedChecker::new(&ctx, 8);

            // Property: ∀x. x + 0 = x
            let x = checker.encoder().bv_const("x");
            let zero = checker.encoder().bv_from_u64(0);
            let sum = x.bvadd(&zero);
            let property = sum._eq(&x);

            black_box(checker.verify_property_forall(&property)).unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_ed25519_verification,
    bench_ecdsa_verification,
    bench_rsa_verification,
    bench_shamir_verification,
    bench_smt_encoder_operations,
    bench_bounded_checker
);
criterion_main!(benches);
