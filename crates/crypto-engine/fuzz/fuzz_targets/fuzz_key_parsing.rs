#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_crypto_engine::{
    KeyMaterial,
    asymmetric::{
        ecdsa::EcdsaEngine,
        ed25519::Ed25519Engine,
        rsa::RsaEngine,
    },
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test key parsing by attempting operations with arbitrary data
    // None of these should panic, they should return errors for invalid input

    // Ed25519: try to use arbitrary data as a key
    let ed25519_key = KeyMaterial::from_bytes(data.to_vec());
    let _ = Ed25519Engine::sign(&ed25519_key, b"test message");

    // Ed25519: try to verify with arbitrary public key
    let _ = Ed25519Engine::verify(data, b"test message", &[0u8; 64]);

    // ECDSA P-256: try to use arbitrary data as a key
    let ecdsa_key = KeyMaterial::from_bytes(data.to_vec());
    let _ = EcdsaEngine::sign_p256(&ecdsa_key, b"test message");

    // ECDSA P-256: try to verify with arbitrary public key
    let _ = EcdsaEngine::verify_p256(data, b"test message", &[0u8; 64]);

    // ECDSA P-384
    let _ = EcdsaEngine::sign_p384(&ecdsa_key, b"test message");
    let _ = EcdsaEngine::verify_p384(data, b"test message", &[0u8; 96]);

    // RSA: try to use arbitrary data as a key
    let rsa_key = KeyMaterial::from_bytes(data.to_vec());
    let _ = RsaEngine::sign_pkcs1v15_sha256(&rsa_key, b"test message");
    let _ = RsaEngine::sign_pss_sha256(&rsa_key, b"test message");

    // RSA: try to verify with arbitrary public key
    let _ = RsaEngine::verify_pkcs1v15_sha256(data, b"test message", &[0u8; 256]);
    let _ = RsaEngine::verify_pss_sha256(data, b"test message", &[0u8; 256]);
});
