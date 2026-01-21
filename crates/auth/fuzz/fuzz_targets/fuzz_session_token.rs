#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_auth::{SessionToken, HashedToken};

fuzz_target!(|data: &[u8]| {
    // Test session token operations with arbitrary data
    // These should never panic

    // Convert bytes to string for token operations
    if let Ok(token_str) = std::str::from_utf8(data) {
        // Test token creation from string
        let token = SessionToken::from_string(token_str.to_string());

        // Test hashing
        let hashed = HashedToken::from_token(&token);

        // Test verification (should be constant-time)
        let _ = hashed.verify(&token);

        // Test with a different token
        let other_token = SessionToken::from_string(format!("{}x", token_str));
        let _ = hashed.verify(&other_token);
    }
});
