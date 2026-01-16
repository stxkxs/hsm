#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_crypto_engine::{KeyMaterial, symmetric::aes_gcm::AesGcmEngine};

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for key + 28 bytes minimum ciphertext (nonce + tag)
    if data.len() < 60 {
        return;
    }

    let (key_bytes, ciphertext) = data.split_at(32);

    // Limit ciphertext size for performance
    if ciphertext.len() > 65536 {
        return;
    }

    let key = KeyMaterial::from_bytes(key_bytes.to_vec());

    // Attempt to decrypt - should not panic (but will likely fail)
    let _ = AesGcmEngine::decrypt_aes256(&key, ciphertext, None);
});
