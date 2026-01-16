#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_crypto_engine::asymmetric::ed25519::Ed25519Engine;

fuzz_target!(|data: &[u8]| {
    // Need at least: 32 bytes pubkey + 64 bytes signature + 1 byte message
    if data.len() < 97 {
        return;
    }

    let (public_key, rest) = data.split_at(32);
    let (signature, message) = rest.split_at(64);

    // Attempt to verify - should not panic
    let _ = Ed25519Engine::verify(public_key, message, signature);
});
