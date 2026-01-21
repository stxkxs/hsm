#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_crypto_engine::asymmetric::ecdsa::EcdsaEngine;

fuzz_target!(|data: &[u8]| {
    // P-256: public key is 65 bytes (uncompressed) or 33 bytes (compressed)
    // Signature is 64 bytes (r + s)
    // Minimum: 33 (compressed pubkey) + 64 (sig) + 1 (msg) = 98 bytes
    if data.len() < 98 {
        return;
    }

    let (public_key, rest) = data.split_at(65.min(data.len()));
    if rest.len() < 64 {
        return;
    }
    let (signature, message) = rest.split_at(64);

    // Attempt to verify - should not panic regardless of input validity
    let _ = EcdsaEngine::verify_p256(public_key, message, signature);
});
