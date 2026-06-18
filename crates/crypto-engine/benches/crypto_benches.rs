use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use hsm_crypto_engine::*;
use std::hint::black_box;

fn bench_ed25519_sign(c: &mut Criterion) {
    let (private_key, _) = asymmetric::ed25519::Ed25519Engine::generate_keypair().unwrap();
    let message = b"benchmark message";

    let mut group = c.benchmark_group("ed25519");
    group.throughput(Throughput::Elements(1));

    group.bench_function("sign", |b| {
        b.iter(|| {
            asymmetric::ed25519::Ed25519Engine::sign(black_box(&private_key), black_box(message))
        });
    });

    group.finish();
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let (private_key, public_key) = asymmetric::ed25519::Ed25519Engine::generate_keypair().unwrap();
    let message = b"benchmark message";
    let signature = asymmetric::ed25519::Ed25519Engine::sign(&private_key, message).unwrap();

    let mut group = c.benchmark_group("ed25519");
    group.throughput(Throughput::Elements(1));

    group.bench_function("verify", |b| {
        b.iter(|| {
            asymmetric::ed25519::Ed25519Engine::verify(
                black_box(&public_key),
                black_box(message),
                black_box(&signature),
            )
        });
    });

    group.finish();
}

fn bench_ecdsa_p256_sign(c: &mut Criterion) {
    let (private_key, _) = asymmetric::ecdsa::EcdsaEngine::generate_p256_keypair().unwrap();
    let message = b"benchmark message";

    let mut group = c.benchmark_group("ecdsa_p256");
    group.throughput(Throughput::Elements(1));

    group.bench_function("sign", |b| {
        b.iter(|| {
            asymmetric::ecdsa::EcdsaEngine::sign_p256(black_box(&private_key), black_box(message))
        });
    });

    group.finish();
}

fn bench_ecdsa_p256_verify(c: &mut Criterion) {
    let (private_key, public_key) =
        asymmetric::ecdsa::EcdsaEngine::generate_p256_keypair().unwrap();
    let message = b"benchmark message";
    let signature = asymmetric::ecdsa::EcdsaEngine::sign_p256(&private_key, message).unwrap();

    let mut group = c.benchmark_group("ecdsa_p256");
    group.throughput(Throughput::Elements(1));

    group.bench_function("verify", |b| {
        b.iter(|| {
            asymmetric::ecdsa::EcdsaEngine::verify_p256(
                black_box(&public_key),
                black_box(message),
                black_box(&signature),
            )
        });
    });

    group.finish();
}

fn bench_aes256_gcm_encrypt(c: &mut Criterion) {
    let key = KeyMaterial::from_bytes(vec![0x42; 32]);
    let plaintext = vec![0u8; 1024]; // 1KB

    let mut group = c.benchmark_group("aes256_gcm");
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("encrypt", |b| {
        b.iter(|| {
            symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(
                black_box(&key),
                black_box(&plaintext),
                None,
            )
        });
    });

    group.finish();
}

fn bench_aes256_gcm_decrypt(c: &mut Criterion) {
    let key = KeyMaterial::from_bytes(vec![0x42; 32]);
    let plaintext = vec![0u8; 1024]; // 1KB
    let ciphertext =
        symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(&key, &plaintext, None).unwrap();

    let mut group = c.benchmark_group("aes256_gcm");
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("decrypt", |b| {
        b.iter(|| {
            symmetric::aes_gcm::AesGcmEngine::decrypt_aes256(
                black_box(&key),
                black_box(&ciphertext),
                None,
            )
        });
    });

    group.finish();
}

fn bench_sha256(c: &mut Criterion) {
    let data = vec![0u8; 1024]; // 1KB

    let mut group = c.benchmark_group("hashing");
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("sha256", |b| {
        b.iter(|| hash::digest::hash(black_box(&data), HashAlgorithm::Sha256));
    });

    group.finish();
}

fn bench_sha512(c: &mut Criterion) {
    let data = vec![0u8; 1024]; // 1KB

    let mut group = c.benchmark_group("hashing");
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("sha512", |b| {
        b.iter(|| hash::digest::hash(black_box(&data), HashAlgorithm::Sha512));
    });

    group.finish();
}

fn bench_hkdf(c: &mut Criterion) {
    let ikm = vec![0x42; 32];
    let salt = vec![0x43; 16];
    let info = b"benchmark";

    let mut group = c.benchmark_group("kdf");
    group.throughput(Throughput::Elements(1));

    group.bench_function("hkdf", |b| {
        b.iter(|| kdf::hkdf::derive_key(black_box(&ikm), black_box(&salt), black_box(info), 32));
    });

    group.finish();
}

fn bench_pbkdf2(c: &mut Criterion) {
    let password = b"password";
    let salt = b"salt";
    let iterations = 10000;

    let mut group = c.benchmark_group("kdf");
    group.throughput(Throughput::Elements(1));

    group.bench_function("pbkdf2_10k", |b| {
        b.iter(|| kdf::pbkdf2::derive_key(black_box(password), black_box(salt), iterations, 32));
    });

    group.finish();
}

fn bench_rsa_2048_sign(c: &mut Criterion) {
    let (private_key, _) = asymmetric::rsa::RsaEngine::generate_keypair(2048).unwrap();
    let message = b"benchmark message";

    let mut group = c.benchmark_group("rsa_2048");
    group.throughput(Throughput::Elements(1));
    group.sample_size(10); // RSA is slow, use fewer samples

    group.bench_function("sign_pkcs1v15", |b| {
        b.iter(|| {
            asymmetric::rsa::RsaEngine::sign_pkcs1v15_sha256(
                black_box(&private_key),
                black_box(message),
            )
        });
    });

    group.finish();
}

fn bench_rsa_2048_verify(c: &mut Criterion) {
    let (private_key, public_key) = asymmetric::rsa::RsaEngine::generate_keypair(2048).unwrap();
    let message = b"benchmark message";
    let signature =
        asymmetric::rsa::RsaEngine::sign_pkcs1v15_sha256(&private_key, message).unwrap();

    let mut group = c.benchmark_group("rsa_2048");
    group.throughput(Throughput::Elements(1));

    group.bench_function("verify_pkcs1v15", |b| {
        b.iter(|| {
            asymmetric::rsa::RsaEngine::verify_pkcs1v15_sha256(
                black_box(&public_key),
                black_box(message),
                black_box(&signature),
            )
        });
    });

    group.finish();
}

fn bench_rsa_pss_sign(c: &mut Criterion) {
    let (private_key, _) = asymmetric::rsa::RsaEngine::generate_keypair(2048).unwrap();
    let message = b"benchmark message";

    let mut group = c.benchmark_group("rsa_2048");
    group.throughput(Throughput::Elements(1));
    group.sample_size(10);

    group.bench_function("sign_pss", |b| {
        b.iter(|| {
            asymmetric::rsa::RsaEngine::sign_pss_sha256(black_box(&private_key), black_box(message))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_ecdsa_p256_sign,
    bench_ecdsa_p256_verify,
    bench_aes256_gcm_encrypt,
    bench_aes256_gcm_decrypt,
    bench_sha256,
    bench_sha512,
    bench_hkdf,
    bench_pbkdf2,
    bench_rsa_2048_sign,
    bench_rsa_2048_verify,
    bench_rsa_pss_sign,
);
criterion_main!(benches);
