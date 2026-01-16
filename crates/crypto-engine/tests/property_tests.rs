use hsm_crypto_engine::*;
use proptest::prelude::*;

// Property: Any message signed with a key should verify with the corresponding public key
proptest! {
    #[test]
    fn prop_ed25519_sign_verify_roundtrip(message in prop::collection::vec(any::<u8>(), 0..1024)) {
        let (private_key, public_key) = asymmetric::ed25519::Ed25519Engine::generate_keypair().unwrap();

        let signature = asymmetric::ed25519::Ed25519Engine::sign(&private_key, &message).unwrap();
        let valid = asymmetric::ed25519::Ed25519Engine::verify(&public_key, &message, &signature).unwrap();

        prop_assert!(valid);
    }

    #[test]
    fn prop_ed25519_different_message_fails(
        message1 in prop::collection::vec(any::<u8>(), 1..1024),
        message2 in prop::collection::vec(any::<u8>(), 1..1024)
    ) {
        prop_assume!(message1 != message2);

        let (private_key, public_key) = asymmetric::ed25519::Ed25519Engine::generate_keypair().unwrap();
        let signature = asymmetric::ed25519::Ed25519Engine::sign(&private_key, &message1).unwrap();

        // Verifying with different message should fail
        let result = asymmetric::ed25519::Ed25519Engine::verify(&public_key, &message2, &signature);
        prop_assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn prop_aes256_gcm_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..4096)) {
        let key = KeyMaterial::from_bytes(vec![0x42; 32]);

        let ciphertext = symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(&key, &plaintext, None).unwrap();
        let decrypted = symmetric::aes_gcm::AesGcmEngine::decrypt_aes256(&key, &ciphertext, None).unwrap();

        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn prop_aes256_gcm_different_plaintexts_different_ciphertexts(
        plaintext1 in prop::collection::vec(any::<u8>(), 16..256),
        plaintext2 in prop::collection::vec(any::<u8>(), 16..256)
    ) {
        prop_assume!(plaintext1 != plaintext2);

        let key = KeyMaterial::from_bytes(vec![0x42; 32]);

        let ciphertext1 = symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(&key, &plaintext1, None).unwrap();
        let ciphertext2 = symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(&key, &plaintext2, None).unwrap();

        // Different plaintexts should produce different ciphertexts
        prop_assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn prop_sha256_deterministic(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let hash1 = hash::digest::hash(&data, HashAlgorithm::Sha256).unwrap();
        let hash2 = hash::digest::hash(&data, HashAlgorithm::Sha256).unwrap();

        // Same input should always produce same hash
        prop_assert_eq!(hash1, hash2);
    }

    #[test]
    fn prop_sha256_different_data_different_hash(
        data1 in prop::collection::vec(any::<u8>(), 1..1024),
        data2 in prop::collection::vec(any::<u8>(), 1..1024)
    ) {
        prop_assume!(data1 != data2);

        let hash1 = hash::digest::hash(&data1, HashAlgorithm::Sha256).unwrap();
        let hash2 = hash::digest::hash(&data2, HashAlgorithm::Sha256).unwrap();

        // Different inputs should produce different hashes
        prop_assert_ne!(hash1, hash2);
    }

    #[test]
    fn prop_sha256_fixed_output_size(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let hash = hash::digest::hash(&data, HashAlgorithm::Sha256).unwrap();

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
        let result1 = kdf::hkdf::derive_key(&ikm, &salt, &info, length).unwrap();
        let result2 = kdf::hkdf::derive_key(&ikm, &salt, &info, length).unwrap();

        // Same inputs should produce same output
        prop_assert_eq!(result1.len(), length);
        prop_assert_eq!(result1, result2);
    }

    #[test]
    fn prop_random_bytes_different(length in 16usize..256) {
        let bytes1 = random::generate_random_bytes(length).unwrap();
        let bytes2 = random::generate_random_bytes(length).unwrap();

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
