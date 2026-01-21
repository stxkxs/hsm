#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_crypto_engine::{KeyMaterial, asymmetric::ecdsa::EcdsaEngine};

fuzz_target!(|data: &[u8]| {
    // P-256 private key is 32 bytes
    if data.len() < 32 {
        return;
    }

    let (key_bytes, message) = data.split_at(32);
    let key = KeyMaterial::from_bytes(key_bytes.to_vec());

    // Attempt to sign with P-256 - should not panic
    let _ = EcdsaEngine::sign_p256(&key, message);
});
