#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_crypto_engine::{KeyMaterial, asymmetric::rsa::RsaEngine};

fuzz_target!(|data: &[u8]| {
    // RSA private key in PKCS#8 format is typically > 1200 bytes for 2048-bit
    // We'll try to parse whatever we get - this tests robustness of key parsing
    if data.is_empty() {
        return;
    }

    // Split data: first part as potential key, rest as message
    let split_point = data.len().saturating_sub(64).max(data.len() / 2);
    let (key_data, message) = data.split_at(split_point);

    // Create KeyMaterial and attempt to sign - should not panic
    let key = KeyMaterial::from_bytes(key_data.to_vec());
    let _ = RsaEngine::sign_pkcs1v15_sha256(&key, message);
});
