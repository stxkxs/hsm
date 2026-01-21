use hsm_crypto_engine::*;
use proptest::prelude::*;

// Property: Any message signed with a key should verify with the corresponding public key
proptest! {
    #[test]
    fn prop_ed25519_sign_verify_roundtrip(message in prop::collection::vec(any::<u8>(), 0..1024)) {
        let (private_key, public_key) = asymmetric::ed25519::Ed25519Engine::generate_keypair()
            .expect("Ed25519 keypair generation should succeed");

        let signature = asymmetric::ed25519::Ed25519Engine::sign(&private_key, &message)
            .expect("Ed25519 signing should succeed");
        let valid = asymmetric::ed25519::Ed25519Engine::verify(&public_key, &message, &signature)
            .expect("Ed25519 verification should succeed");

        prop_assert!(valid);
    }

    #[test]
    fn prop_ed25519_different_message_fails(
        message1 in prop::collection::vec(any::<u8>(), 1..1024),
        message2 in prop::collection::vec(any::<u8>(), 1..1024)
    ) {
        prop_assume!(message1 != message2);

        let (private_key, public_key) = asymmetric::ed25519::Ed25519Engine::generate_keypair()
            .expect("Ed25519 keypair generation should succeed");
        let signature = asymmetric::ed25519::Ed25519Engine::sign(&private_key, &message1)
            .expect("Ed25519 signing should succeed");

        // Verifying with different message should fail
        let result = asymmetric::ed25519::Ed25519Engine::verify(&public_key, &message2, &signature);
        prop_assert!(result.is_err() || !result.expect("verify result should be deterministic"));
    }

    #[test]
    fn prop_aes256_gcm_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..4096)) {
        let key = KeyMaterial::from_bytes(vec![0x42; 32]);

        let ciphertext = symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(&key, &plaintext, None)
            .expect("AES-256-GCM encryption should succeed");
        let decrypted = symmetric::aes_gcm::AesGcmEngine::decrypt_aes256(&key, &ciphertext, None)
            .expect("AES-256-GCM decryption should succeed");

        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn prop_aes256_gcm_different_plaintexts_different_ciphertexts(
        plaintext1 in prop::collection::vec(any::<u8>(), 16..256),
        plaintext2 in prop::collection::vec(any::<u8>(), 16..256)
    ) {
        prop_assume!(plaintext1 != plaintext2);

        let key = KeyMaterial::from_bytes(vec![0x42; 32]);

        let ciphertext1 = symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(&key, &plaintext1, None)
            .expect("AES-256-GCM encryption of plaintext1 should succeed");
        let ciphertext2 = symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(&key, &plaintext2, None)
            .expect("AES-256-GCM encryption of plaintext2 should succeed");

        // Different plaintexts should produce different ciphertexts
        prop_assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn prop_sha256_deterministic(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let hash1 = hash::digest::hash(&data, HashAlgorithm::Sha256)
            .expect("SHA-256 hash should succeed");
        let hash2 = hash::digest::hash(&data, HashAlgorithm::Sha256)
            .expect("SHA-256 hash should succeed");

        // Same input should always produce same hash
        prop_assert_eq!(hash1, hash2);
    }

    #[test]
    fn prop_sha256_different_data_different_hash(
        data1 in prop::collection::vec(any::<u8>(), 1..1024),
        data2 in prop::collection::vec(any::<u8>(), 1..1024)
    ) {
        prop_assume!(data1 != data2);

        let hash1 = hash::digest::hash(&data1, HashAlgorithm::Sha256)
            .expect("SHA-256 hash of data1 should succeed");
        let hash2 = hash::digest::hash(&data2, HashAlgorithm::Sha256)
            .expect("SHA-256 hash of data2 should succeed");

        // Different inputs should produce different hashes
        prop_assert_ne!(hash1, hash2);
    }

    #[test]
    fn prop_sha256_fixed_output_size(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let hash = hash::digest::hash(&data, HashAlgorithm::Sha256)
            .expect("SHA-256 hash should succeed");

        // SHA-256 always produces 32 bytes
        prop_assert_eq!(hash.len(), 32);
    }

    #[test]
    fn prop_hkdf_deterministic(
        ikm in prop::collection::vec(any::<u8>(), 16..64),
        salt in prop::collection::vec(any::<u8>(), 8..32),
        info in prop::collection::vec(any::<u8>(), 0..64),
        length in 16usize..128
    ) {
        let result1 = kdf::hkdf::derive_key(&ikm, &salt, &info, length)
            .expect("HKDF key derivation should succeed");
        let result2 = kdf::hkdf::derive_key(&ikm, &salt, &info, length)
            .expect("HKDF key derivation should succeed");

        // Same inputs should produce same output
        prop_assert_eq!(result1.len(), length);
        prop_assert_eq!(result1, result2);
    }

    #[test]
    fn prop_random_bytes_different(length in 16usize..256) {
        let bytes1 = random::generate_random_bytes(length)
            .expect("random bytes generation should succeed");
        let bytes2 = random::generate_random_bytes(length)
            .expect("random bytes generation should succeed");

        prop_assert_eq!(bytes1.len(), length);
        prop_assert_eq!(bytes2.len(), length);

        // Two random generations should be different (with very high probability)
        if length >= 16 {
            prop_assert_ne!(bytes1, bytes2);
        }
    }
}

// Additional property tests for input validation
proptest! {
    #[test]
    fn prop_ed25519_rejects_invalid_key_size(key_size in 0usize..64) {
        prop_assume!(key_size != 32);

        let key = KeyMaterial::from_bytes(vec![0x42; key_size]);
        let message = b"test";

        let result = asymmetric::ed25519::Ed25519Engine::sign(&key, message);
        prop_assert!(result.is_err());
    }

    #[test]
    fn prop_aes256_rejects_invalid_key_size(key_size in 0usize..64) {
        prop_assume!(key_size != 32);

        let key = KeyMaterial::from_bytes(vec![0x42; key_size]);
        let plaintext = b"test";

        let result = symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(&key, plaintext, None);
        prop_assert!(result.is_err());
    }
}

// ECDSA P-256 property tests
proptest! {
    #[test]
    fn prop_ecdsa_p256_sign_verify_roundtrip(message in prop::collection::vec(any::<u8>(), 0..1024)) {
        let (private_key, public_key) = asymmetric::ecdsa::EcdsaEngine::generate_p256_keypair()
            .expect("ECDSA P-256 keypair generation should succeed");

        let signature = asymmetric::ecdsa::EcdsaEngine::sign_p256(&private_key, &message)
            .expect("ECDSA P-256 signing should succeed");
        let valid = asymmetric::ecdsa::EcdsaEngine::verify_p256(&public_key, &message, &signature)
            .expect("ECDSA P-256 verification should succeed");

        prop_assert!(valid);
    }

    #[test]
    fn prop_ecdsa_p256_different_message_fails(
        message1 in prop::collection::vec(any::<u8>(), 1..512),
        message2 in prop::collection::vec(any::<u8>(), 1..512)
    ) {
        prop_assume!(message1 != message2);

        let (private_key, public_key) = asymmetric::ecdsa::EcdsaEngine::generate_p256_keypair()
            .expect("ECDSA P-256 keypair generation should succeed");
        let signature = asymmetric::ecdsa::EcdsaEngine::sign_p256(&private_key, &message1)
            .expect("ECDSA P-256 signing should succeed");

        // Verifying with different message should fail
        let result = asymmetric::ecdsa::EcdsaEngine::verify_p256(&public_key, &message2, &signature);
        prop_assert!(result.is_err() || !result.expect("verify result should be deterministic"));
    }

    #[test]
    fn prop_ecdsa_p256_wrong_key_fails(message in prop::collection::vec(any::<u8>(), 1..512)) {
        let (private_key1, _) = asymmetric::ecdsa::EcdsaEngine::generate_p256_keypair()
            .expect("ECDSA P-256 keypair1 generation should succeed");
        let (_, public_key2) = asymmetric::ecdsa::EcdsaEngine::generate_p256_keypair()
            .expect("ECDSA P-256 keypair2 generation should succeed");

        let signature = asymmetric::ecdsa::EcdsaEngine::sign_p256(&private_key1, &message)
            .expect("ECDSA P-256 signing should succeed");

        // Verifying with different public key should fail
        let result = asymmetric::ecdsa::EcdsaEngine::verify_p256(&public_key2, &message, &signature);
        prop_assert!(result.is_err() || !result.expect("verify result should be deterministic"));
    }
}

// ECDSA P-384 property tests
proptest! {
    #[test]
    fn prop_ecdsa_p384_sign_verify_roundtrip(message in prop::collection::vec(any::<u8>(), 0..1024)) {
        let (private_key, public_key) = asymmetric::ecdsa::EcdsaEngine::generate_p384_keypair()
            .expect("ECDSA P-384 keypair generation should succeed");

        let signature = asymmetric::ecdsa::EcdsaEngine::sign_p384(&private_key, &message)
            .expect("ECDSA P-384 signing should succeed");
        let valid = asymmetric::ecdsa::EcdsaEngine::verify_p384(&public_key, &message, &signature)
            .expect("ECDSA P-384 verification should succeed");

        prop_assert!(valid);
    }
}

// Key generation property tests
proptest! {
    #[test]
    fn prop_ed25519_keypair_consistency(_seed in any::<u64>()) {
        // Generate two keypairs and verify they are different
        let (private1, public1) = asymmetric::ed25519::Ed25519Engine::generate_keypair()
            .expect("Ed25519 keypair1 generation should succeed");
        let (private2, public2) = asymmetric::ed25519::Ed25519Engine::generate_keypair()
            .expect("Ed25519 keypair2 generation should succeed");

        // Private key should be 32 bytes, public key should be 32 bytes
        prop_assert_eq!(private1.as_bytes().len(), 32);
        prop_assert_eq!(public1.len(), 32);

        // Different keypairs should have different keys
        prop_assert_ne!(private1.as_bytes(), private2.as_bytes());
        prop_assert_ne!(public1, public2);
    }

    #[test]
    fn prop_ecdsa_p256_keypair_sizes(_seed in any::<u64>()) {
        let (private_key, public_key) = asymmetric::ecdsa::EcdsaEngine::generate_p256_keypair()
            .expect("ECDSA P-256 keypair generation should succeed");

        // P-256 private key is 32 bytes, public key is 65 bytes (uncompressed)
        prop_assert_eq!(private_key.as_bytes().len(), 32);
        prop_assert_eq!(public_key.len(), 65);
    }
}

// AES-CBC property tests
proptest! {
    #[test]
    fn prop_aes256_cbc_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 1..4096)) {
        let key = KeyMaterial::from_bytes(vec![0x42; 32]);

        let ciphertext = symmetric::aes_cbc::AesCbcEngine::encrypt_aes256(&key, &plaintext)
            .expect("AES-256-CBC encryption should succeed");
        let decrypted = symmetric::aes_cbc::AesCbcEngine::decrypt_aes256(&key, &ciphertext)
            .expect("AES-256-CBC decryption should succeed");

        prop_assert_eq!(plaintext, decrypted);
    }
}

// Hash algorithm property tests
proptest! {
    #[test]
    fn prop_all_hash_algorithms_deterministic(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let algorithms = [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_512,
        ];

        for algo in algorithms {
            let hash1 = hash::digest::hash(&data, algo)
                .expect("hash computation should succeed");
            let hash2 = hash::digest::hash(&data, algo)
                .expect("hash computation should succeed");
            prop_assert_eq!(hash1, hash2);
        }
    }

    #[test]
    fn prop_hash_output_sizes(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        // SHA-256 and SHA3-256: 32 bytes
        let sha256 = hash::digest::hash(&data, HashAlgorithm::Sha256)
            .expect("SHA-256 hash should succeed");
        let sha3_256 = hash::digest::hash(&data, HashAlgorithm::Sha3_256)
            .expect("SHA3-256 hash should succeed");
        prop_assert_eq!(sha256.len(), 32);
        prop_assert_eq!(sha3_256.len(), 32);

        // SHA-384: 48 bytes
        let sha384 = hash::digest::hash(&data, HashAlgorithm::Sha384)
            .expect("SHA-384 hash should succeed");
        prop_assert_eq!(sha384.len(), 48);

        // SHA-512 and SHA3-512: 64 bytes
        let sha512 = hash::digest::hash(&data, HashAlgorithm::Sha512)
            .expect("SHA-512 hash should succeed");
        let sha3_512 = hash::digest::hash(&data, HashAlgorithm::Sha3_512)
            .expect("SHA3-512 hash should succeed");
        prop_assert_eq!(sha512.len(), 64);
        prop_assert_eq!(sha3_512.len(), 64);
    }
}

// Constant-time comparison property tests
proptest! {
    #[test]
    fn prop_constant_time_eq_reflexive(data in prop::collection::vec(any::<u8>(), 1..256)) {
        // Data should always equal itself
        prop_assert!(constant_time::ct_compare(&data, &data));
    }

    #[test]
    fn prop_constant_time_eq_different(
        data1 in prop::collection::vec(any::<u8>(), 1..256),
        data2 in prop::collection::vec(any::<u8>(), 1..256)
    ) {
        prop_assume!(data1 != data2);

        // Different data should not be equal
        prop_assert!(!constant_time::ct_compare(&data1, &data2));
    }
}
