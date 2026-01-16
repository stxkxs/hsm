#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_crypto_engine::{KeyMaterial, asymmetric::ed25519::Ed25519Engine};

fuzz_target!(|data: &[u8]| {
    // Only fuzz with valid key sizes
    if data.len() < 32 {
        return;
    }

    let (key_bytes, message) = data.split_at(32);
    let key = KeyMaterial::from_bytes(key_bytes.to_vec());

    // Attempt to sign - should not panic
    let _ = Ed25519Engine::sign(&key, message);
});
