#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_crypto_engine::{HashAlgorithm, hash::digest::hash};

fuzz_target!(|data: &[u8]| {
    // Hash functions should never panic on any input
    let _ = hash(data, HashAlgorithm::Sha256);
    let _ = hash(data, HashAlgorithm::Sha384);
    let _ = hash(data, HashAlgorithm::Sha512);
    let _ = hash(data, HashAlgorithm::Sha3_256);
    let _ = hash(data, HashAlgorithm::Sha3_512);
});
