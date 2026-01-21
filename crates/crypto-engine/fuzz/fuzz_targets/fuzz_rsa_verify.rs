#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_crypto_engine::asymmetric::rsa::RsaEngine;

fuzz_target!(|data: &[u8]| {
    // RSA public key + signature + message
    // Minimum meaningful input
    if data.len() < 256 {
        return;
    }

    // Try different split points to test various malformed inputs
    let key_end = data.len() / 2;
    let sig_end = key_end + 256.min(data.len() - key_end);

    let key_data = &data[..key_end];
    let signature = &data[key_end..sig_end.min(data.len())];
    let message = &data[sig_end.min(data.len())..];

    // Attempt to verify with arbitrary key data - should not panic
    let _ = RsaEngine::verify_pkcs1v15_sha256(key_data, message, signature);
});
