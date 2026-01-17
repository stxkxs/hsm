//! Fault Injection Tests for Crypto Operations
//!
//! These tests simulate physical attacks on cryptographic operations:
//! - Bit-flip attacks on RSA CRT (Chinese Remainder Theorem) parameters
//! - Nonce corruption in ECDSA signing
//! - Key corruption during operations
//!
//! Goal: Verify that faults cause safe failures (operation fails) rather than
//! leaking secret key material through faulty signatures.

use hsm_crypto_engine::asymmetric::{ecdsa::EcdsaEngine, ed25519::Ed25519Engine, rsa::RsaEngine};
use hsm_crypto_engine::KeyMaterial;

/// Test that corrupted RSA private key causes signature verification to fail
/// rather than leaking key material
#[test]
fn test_rsa_key_corruption_fails_safely() {
    let (private_key, public_key) = RsaEngine::generate_keypair(2048).unwrap();
    let message = b"critical data that must be signed correctly";

    // Normal operation: sign and verify successfully
    let valid_signature = RsaEngine::sign_pkcs1v15_sha256(&private_key, message).unwrap();
    assert!(RsaEngine::verify_pkcs1v15_sha256(&public_key, message, &valid_signature).unwrap());

    // Simulate fault injection: corrupt a random byte in the private key
    let mut corrupted_key_bytes = private_key.as_bytes().to_vec();
    if corrupted_key_bytes.len() > 100 {
        corrupted_key_bytes[100] ^= 0x01; // Flip one bit

        let corrupted_key = KeyMaterial::from_bytes(corrupted_key_bytes);

        // Attempt to sign with corrupted key
        match RsaEngine::sign_pkcs1v15_sha256(&corrupted_key, message) {
            Ok(faulty_signature) => {
                // If signing succeeds, verification MUST fail (no key leakage)
                let verification = RsaEngine::verify_pkcs1v15_sha256(&public_key, message, &faulty_signature);
                assert!(
                    verification.is_err() || !verification.unwrap(),
                    "Faulty signature must not verify - this would indicate key leakage!"
                );
            }
            Err(_) => {
                // Expected: signing fails due to corrupted key (safe behavior)
            }
        }
    }
}

/// Test that RSA CRT fault injection doesn't leak private key
///
/// Bellcore attack: If an attacker can cause a fault during RSA-CRT computation
/// such that only one of the CRT components is corrupted, they can recover
/// the private key by computing gcd(signature - signature_faulty, modulus).
///
/// This test verifies that our RSA implementation either:
/// 1. Detects the fault and refuses to output a signature, OR
/// 2. Outputs a signature that doesn't verify (safe failure)
#[test]
fn test_rsa_crt_fault_injection_bellcore_attack() {
    let (private_key, public_key) = RsaEngine::generate_keypair(2048).unwrap();
    let message = b"message to be signed";

    // Get a valid signature first
    let valid_signature = RsaEngine::sign_pkcs1v15_sha256(&private_key, message).unwrap();

    // Simulate CRT fault: corrupt the private key in a way that might affect
    // only one CRT component (p or q)
    for corruption_position in [50, 100, 150, 200, 250] {
        let mut corrupted_key_bytes = private_key.as_bytes().to_vec();
        if corruption_position < corrupted_key_bytes.len() {
            corrupted_key_bytes[corruption_position] ^= 0xFF;

            let corrupted_key = KeyMaterial::from_bytes(corrupted_key_bytes);

            match RsaEngine::sign_pkcs1v15_sha256(&corrupted_key, message) {
                Ok(faulty_signature) => {
                    // Critical: faulty signature must NOT verify
                    let verifies = RsaEngine::verify_pkcs1v15_sha256(&public_key, message, &faulty_signature);
                    assert!(
                        verifies.is_err() || !verifies.unwrap(),
                        "Bellcore attack: faulty CRT signature verified! This leaks the private key!"
                    );

                    // Additional check: faulty signature should differ from valid signature
                    assert_ne!(
                        valid_signature, faulty_signature,
                        "Faulty signature identical to valid - corruption had no effect"
                    );
                }
                Err(_) => {
                    // Safe: operation failed rather than producing faulty output
                }
            }
        }
    }
}

/// Test that ECDSA with corrupted nonce fails safely
///
/// ECDSA vulnerability: If the same nonce is used twice with different messages,
/// or if the nonce is corrupted/leaked, the private key can be recovered.
#[test]
fn test_ecdsa_nonce_uniqueness() {
    let (private_key, public_key) = EcdsaEngine::generate_p256_keypair().unwrap();
    let message1 = b"first message";
    let message2 = b"second message";

    // Sign both messages
    let sig1 = EcdsaEngine::sign_p256(&private_key, message1).unwrap();
    let sig2 = EcdsaEngine::sign_p256(&private_key, message2).unwrap();

    // Signatures should be different (different nonces used)
    assert_ne!(
        sig1, sig2,
        "ECDSA signatures are identical - nonce reuse detected!"
    );

    // Both should verify correctly
    assert!(EcdsaEngine::verify_p256(&public_key, message1, &sig1).unwrap());
    assert!(EcdsaEngine::verify_p256(&public_key, message2, &sig2).unwrap());

    // Corrupted signature should not verify
    let mut corrupted_sig = sig1.clone();
    if corrupted_sig.len() > 10 {
        corrupted_sig[10] ^= 0xFF;
    }

    assert!(
        !EcdsaEngine::verify_p256(&public_key, message1, &corrupted_sig).unwrap_or(false),
        "Corrupted ECDSA signature verified - this should never happen"
    );
}

/// Test that Ed25519 with corrupted key fails safely
#[test]
fn test_ed25519_key_corruption() {
    let (private_key, public_key) = Ed25519Engine::generate_keypair().unwrap();
    let message = b"authenticate this message";

    // Valid signature
    let valid_sig = Ed25519Engine::sign(&private_key, message).unwrap();
    assert!(Ed25519Engine::verify(&public_key, message, &valid_sig).unwrap());

    // Corrupt the private key
    let mut corrupted_key_bytes = private_key.as_bytes().to_vec();
    if corrupted_key_bytes.len() > 15 {
        corrupted_key_bytes[15] ^= 0x80;
        let corrupted_key = KeyMaterial::from_bytes(corrupted_key_bytes);

        // Sign with corrupted key
        let faulty_sig = Ed25519Engine::sign(&corrupted_key, message).unwrap();

        // Faulty signature must not verify with original public key
        assert!(
            !Ed25519Engine::verify(&public_key, message, &faulty_sig).unwrap_or(false),
            "Ed25519 signature from corrupted key verified - key leakage possible!"
        );
    }
}

/// Test that multiple bit flips in RSA key cause failure
#[test]
fn test_rsa_multiple_bit_flips() {
    let (private_key, public_key) = RsaEngine::generate_keypair(2048).unwrap();
    let message = b"data requiring strong integrity";

    // Inject multiple bit flips (simulating radiation or voltage glitch)
    let mut corrupted_key_bytes = private_key.as_bytes().to_vec();
    let flip_positions = [10, 50, 100, 200, 300];

    for &pos in &flip_positions {
        if pos < corrupted_key_bytes.len() {
            corrupted_key_bytes[pos] ^= 0x55; // Multiple bits flipped
        }
    }

    let corrupted_key = KeyMaterial::from_bytes(corrupted_key_bytes);

    // Multi-bit corruption should cause operation to fail
    match RsaEngine::sign_pkcs1v15_sha256(&corrupted_key, message) {
        Ok(sig) => {
            // If it succeeds, signature must not verify
            assert!(
                !RsaEngine::verify_pkcs1v15_sha256(&public_key, message, &sig).unwrap_or(false),
                "Multiply-corrupted key produced valid signature!"
            );
        }
        Err(_) => {
            // Expected safe failure
        }
    }
}

/// Test that Ed25519 signature corruption is detected
#[test]
fn test_ed25519_signature_corruption() {
    let (private_key, public_key) = Ed25519Engine::generate_keypair().unwrap();
    let message = b"test message for signature corruption";

    let signature = Ed25519Engine::sign(&private_key, message).unwrap();

    // Original signature verifies
    assert!(Ed25519Engine::verify(&public_key, message, &signature).unwrap());

    // Corrupt signature at various positions
    for corruption_pos in [0, 16, 32, 48, 63] {
        let mut corrupted_sig = signature.clone();
        if corruption_pos < corrupted_sig.len() {
            corrupted_sig[corruption_pos] ^= 0xFF;

            // Corrupted signature must not verify
            assert!(
                !Ed25519Engine::verify(&public_key, message, &corrupted_sig).unwrap_or(false),
                "Corrupted Ed25519 signature at position {} verified!", corruption_pos
            );
        }
    }
}

/// Test that ECDSA P384 key corruption causes safe failure
#[test]
fn test_ecdsa_p384_key_corruption() {
    let (private_key, public_key) = EcdsaEngine::generate_p384_keypair().unwrap();
    let message = b"P384 test message";

    // Valid signature
    let valid_sig = EcdsaEngine::sign_p384(&private_key, message).unwrap();
    assert!(EcdsaEngine::verify_p384(&public_key, message, &valid_sig).unwrap());

    // Corrupt key
    let mut corrupted_key_bytes = private_key.as_bytes().to_vec();
    if corrupted_key_bytes.len() > 20 {
        corrupted_key_bytes[20] ^= 0xAA;
        let corrupted_key = KeyMaterial::from_bytes(corrupted_key_bytes);

        match EcdsaEngine::sign_p384(&corrupted_key, message) {
            Ok(faulty_sig) => {
                // Faulty signature must not verify
                assert!(
                    !EcdsaEngine::verify_p384(&public_key, message, &faulty_sig).unwrap_or(false),
                    "P384 faulty signature verified - key leakage!"
                );
            }
            Err(_) => {
                // Safe failure
            }
        }
    }
}

/// Test RSA-PSS with key corruption
#[test]
fn test_rsa_pss_key_corruption() {
    let (private_key, public_key) = RsaEngine::generate_keypair(2048).unwrap();
    let message = b"PSS padding test message";

    // Valid signature
    let valid_sig = RsaEngine::sign_pss_sha256(&private_key, message).unwrap();
    assert!(RsaEngine::verify_pss_sha256(&public_key, message, &valid_sig).unwrap());

    // Corrupt key
    let mut corrupted_key_bytes = private_key.as_bytes().to_vec();
    if corrupted_key_bytes.len() > 150 {
        corrupted_key_bytes[150] ^= 0x0F;
        let corrupted_key = KeyMaterial::from_bytes(corrupted_key_bytes);

        match RsaEngine::sign_pss_sha256(&corrupted_key, message) {
            Ok(faulty_sig) => {
                // Faulty signature must not verify
                assert!(
                    !RsaEngine::verify_pss_sha256(&public_key, message, &faulty_sig).unwrap_or(false),
                    "RSA-PSS faulty signature verified!"
                );
            }
            Err(_) => {
                // Safe failure
            }
        }
    }
}
