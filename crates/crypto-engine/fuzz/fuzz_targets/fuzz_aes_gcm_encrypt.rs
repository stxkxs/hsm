#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_crypto_engine::{KeyMaterial, symmetric::aes_gcm::AesGcmEngine};

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for key
    if data.len() < 32 {
        return;
    }

    let (key_bytes, plaintext) = data.split_at(32);

    // Limit plaintext size for performance
    if plaintext.len() > 65536 {
        return;
    }

    let key = KeyMaterial::from_bytes(key_bytes.to_vec());

    // Attempt to encrypt - should not panic
    let _ = AesGcmEngine::encrypt_aes256(&key, plaintext, None);
});
