//! Benchmarks for blockchain operations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hsm_blockchain::bip::bip32::{DerivationPath, ExtendedPrivateKey};
use hsm_blockchain::bip::bip39::{Language, Mnemonic, MnemonicType};
use hsm_blockchain::ethereum::eip191::PersonalMessage;
use hsm_blockchain::ethereum::eip712::{Eip712Domain, Eip712TypedData, TypedDataHasher};
use k256::ecdsa::SigningKey;
use k256::SecretKey;
use serde_json::json;

fn bench_mnemonic_generation(c: &mut Criterion) {
    c.bench_function("mnemonic_generate_24_words", |b| {
        b.iter(|| {
            let _ =
                black_box(Mnemonic::generate(MnemonicType::Words24, Language::English).unwrap());
        })
    });

    c.bench_function("mnemonic_generate_12_words", |b| {
        b.iter(|| {
            let _ =
                black_box(Mnemonic::generate(MnemonicType::Words12, Language::English).unwrap());
        })
    });
}

fn bench_seed_derivation(c: &mut Criterion) {
    let mnemonic = Mnemonic::generate(MnemonicType::Words24, Language::English).unwrap();

    c.bench_function("mnemonic_to_seed", |b| {
        b.iter(|| {
            let _ = black_box(mnemonic.to_seed(""));
        })
    });

    c.bench_function("mnemonic_to_seed_with_passphrase", |b| {
        b.iter(|| {
            let _ = black_box(mnemonic.to_seed("my secret passphrase"));
        })
    });
}

fn bench_hd_derivation(c: &mut Criterion) {
    let mnemonic = Mnemonic::generate(MnemonicType::Words24, Language::English).unwrap();
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::from_seed(seed.as_bytes()).unwrap();

    c.bench_function("hd_derive_single_level", |b| {
        b.iter(|| {
            let path = DerivationPath::from_str("m/44'").unwrap();
            let _ = black_box(master.derive_path(&path).unwrap());
        })
    });

    c.bench_function("hd_derive_ethereum_path", |b| {
        b.iter(|| {
            let path = DerivationPath::ethereum(0, 0);
            let _ = black_box(master.derive_path(&path).unwrap());
        })
    });

    c.bench_function("hd_derive_100_addresses", |b| {
        b.iter(|| {
            for i in 0..100 {
                let path = DerivationPath::ethereum(0, i);
                let _ = black_box(master.derive_path(&path).unwrap());
            }
        })
    });
}

fn bench_eip191_signing(c: &mut Criterion) {
    let secret = SecretKey::random(&mut rand::thread_rng());
    let signing_key = SigningKey::from(secret);

    c.bench_function("eip191_hash_short_message", |b| {
        let message = PersonalMessage::from_string("Hello");
        b.iter(|| {
            let _ = black_box(message.hash());
        })
    });

    c.bench_function("eip191_hash_long_message", |b| {
        let message = PersonalMessage::new(&[0u8; 1024]);
        b.iter(|| {
            let _ = black_box(message.hash());
        })
    });

    c.bench_function("eip191_sign", |b| {
        let message = PersonalMessage::from_string("Test message for signing");
        b.iter(|| {
            let _ = black_box(message.sign(&signing_key).unwrap());
        })
    });

    c.bench_function("eip191_sign_and_recover", |b| {
        let message = PersonalMessage::from_string("Test message for signing");
        b.iter(|| {
            let sig = message.sign(&signing_key).unwrap();
            let _ = black_box(message.recover_public_key(&sig).unwrap());
        })
    });
}

fn bench_eip712_signing(c: &mut Criterion) {
    let secret = SecretKey::random(&mut rand::thread_rng());
    let signing_key = SigningKey::from(secret);

    let domain = Eip712Domain::new("Test App")
        .with_version("1")
        .with_chain_id(1);

    let types = json!({
        "Message": [
            {"name": "content", "type": "string"},
            {"name": "value", "type": "uint256"}
        ]
    });

    let message = json!({
        "content": "Hello, EIP-712!",
        "value": 12345
    });

    let typed_data = Eip712TypedData::new(domain, "Message", types, message).unwrap();

    c.bench_function("eip712_hash", |b| {
        b.iter(|| {
            let _ = black_box(TypedDataHasher::hash(&typed_data).unwrap());
        })
    });

    c.bench_function("eip712_sign", |b| {
        b.iter(|| {
            let _ = black_box(TypedDataHasher::sign(&typed_data, &signing_key).unwrap());
        })
    });
}

criterion_group!(
    benches,
    bench_mnemonic_generation,
    bench_seed_derivation,
    bench_hd_derivation,
    bench_eip191_signing,
    bench_eip712_signing,
);
criterion_main!(benches);
