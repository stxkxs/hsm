use hsm_crypto_engine::*;

#[test]
fn test_end_to_end_ed25519() {
    let engine = DefaultCryptoEngine;
    let (private_key, public_key) = asymmetric::ed25519::Ed25519Engine::generate_keypair().unwrap();
    let message = b"Integration test message";

    let signature = engine
        .sign(&private_key, message, SignAlgorithm::Ed25519)
        .unwrap();
    let valid = engine
        .verify(&public_key, message, &signature, SignAlgorithm::Ed25519)
        .unwrap();

    assert!(valid);

    // Test invalid signature
    let mut bad_signature = signature.clone();
    bad_signature[0] ^= 1;
    let result = engine.verify(&public_key, message, &bad_signature, SignAlgorithm::Ed25519);
    assert!(result.is_err());
}

#[test]
fn test_end_to_end_ecdsa_p256() {
    let engine = DefaultCryptoEngine;
    let (private_key, public_key) =
        asymmetric::ecdsa::EcdsaEngine::generate_p256_keypair().unwrap();
    let message = b"Integration test message";

    let signature = engine
        .sign(&private_key, message, SignAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let valid = engine
        .verify(
            &public_key,
            message,
            &signature,
            SignAlgorithm::EcdsaP256Sha256,
        )
        .unwrap();

    assert!(valid);
}

#[test]
fn test_end_to_end_ecdsa_p384() {
    let engine = DefaultCryptoEngine;
    let (private_key, public_key) =
        asymmetric::ecdsa::EcdsaEngine::generate_p384_keypair().unwrap();
    let message = b"Integration test message";

    let signature = engine
        .sign(&private_key, message, SignAlgorithm::EcdsaP384Sha384)
        .unwrap();
    let valid = engine
        .verify(
            &public_key,
            message,
            &signature,
            SignAlgorithm::EcdsaP384Sha384,
        )
        .unwrap();

    assert!(valid);
}

#[test]
fn test_end_to_end_rsa_pkcs1v15() {
    let engine = DefaultCryptoEngine;
    let (private_key, public_key) = asymmetric::rsa::RsaEngine::generate_keypair(2048).unwrap();
    let message = b"Integration test message";

    let signature = engine
        .sign(&private_key, message, SignAlgorithm::RsaPkcs1v15Sha256)
        .unwrap();
    let valid = engine
        .verify(
            &public_key,
            message,
            &signature,
            SignAlgorithm::RsaPkcs1v15Sha256,
        )
        .unwrap();

    assert!(valid);
}

#[test]
fn test_end_to_end_rsa_pss() {
    let engine = DefaultCryptoEngine;
    let (private_key, public_key) = asymmetric::rsa::RsaEngine::generate_keypair(2048).unwrap();
    let message = b"Integration test message";

    let signature = engine
        .sign(&private_key, message, SignAlgorithm::RsaPssSha256)
        .unwrap();
    let valid =
        asymmetric::rsa::RsaEngine::verify_pss_sha256(&public_key, message, &signature).unwrap();

    assert!(valid);
}

#[test]
fn test_end_to_end_aes256_gcm() {
    let engine = DefaultCryptoEngine;
    let key = KeyMaterial::from_bytes(vec![0x42; 32]);
    let plaintext = b"Secret message for encryption";
    let aad = Some(&b"additional authenticated data"[..]);

    let ciphertext = engine
        .encrypt(&key, plaintext, EncryptAlgorithm::Aes256Gcm, aad)
        .unwrap();
    let decrypted = engine
        .decrypt(&key, &ciphertext, EncryptAlgorithm::Aes256Gcm, aad)
        .unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());

    // Test AAD verification
    let wrong_aad = Some(&b"wrong aad"[..]);
    let result = engine.decrypt(&key, &ciphertext, EncryptAlgorithm::Aes256Gcm, wrong_aad);
    assert!(result.is_err());
}

#[test]
fn test_end_to_end_aes128_gcm() {
    let engine = DefaultCryptoEngine;
    let key = KeyMaterial::from_bytes(vec![0x42; 16]);
    let plaintext = b"Secret message for encryption";

    let ciphertext = engine
        .encrypt(&key, plaintext, EncryptAlgorithm::Aes128Gcm, None)
        .unwrap();
    let decrypted = engine
        .decrypt(&key, &ciphertext, EncryptAlgorithm::Aes128Gcm, None)
        .unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_end_to_end_aes256_cbc() {
    let engine = DefaultCryptoEngine;
    let key = KeyMaterial::from_bytes(vec![0x42; 32]);
    let plaintext = b"Secret message for encryption with padding";

    let ciphertext = engine
        .encrypt(&key, plaintext, EncryptAlgorithm::Aes256Cbc, None)
        .unwrap();
    let decrypted = engine
        .decrypt(&key, &ciphertext, EncryptAlgorithm::Aes256Cbc, None)
        .unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_end_to_end_aes128_cbc() {
    let engine = DefaultCryptoEngine;
    let key = KeyMaterial::from_bytes(vec![0x42; 16]);
    let plaintext = b"Secret message for encryption with padding";

    let ciphertext = engine
        .encrypt(&key, plaintext, EncryptAlgorithm::Aes128Cbc, None)
        .unwrap();
    let decrypted = engine
        .decrypt(&key, &ciphertext, EncryptAlgorithm::Aes128Cbc, None)
        .unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_hashing_all_algorithms() {
    let engine = DefaultCryptoEngine;
    let data = b"test data for hashing";

    let sha256 = engine.hash(data, HashAlgorithm::Sha256).unwrap();
    assert_eq!(sha256.len(), 32);

    let sha384 = engine.hash(data, HashAlgorithm::Sha384).unwrap();
    assert_eq!(sha384.len(), 48);

    let sha512 = engine.hash(data, HashAlgorithm::Sha512).unwrap();
    assert_eq!(sha512.len(), 64);

    let sha3_256 = engine.hash(data, HashAlgorithm::Sha3_256).unwrap();
    assert_eq!(sha3_256.len(), 32);

    let sha3_512 = engine.hash(data, HashAlgorithm::Sha3_512).unwrap();
    assert_eq!(sha3_512.len(), 64);
}

#[test]
fn test_hkdf() {
    let ikm = b"input key material";
    let salt = b"salt";
    let info = b"application info";

    let key = kdf::hkdf::derive_key(ikm, salt, info, 32).unwrap();
    assert_eq!(key.len(), 32);

    // Verify determinism
    let key2 = kdf::hkdf::derive_key(ikm, salt, info, 32).unwrap();
    assert_eq!(key, key2);
}

#[test]
fn test_pbkdf2() {
    let password = b"user password";
    let salt = b"random salt";
    let iterations = 100000;

    let key = kdf::pbkdf2::derive_key(password, salt, iterations, 32).unwrap();
    assert_eq!(key.len(), 32);

    // Verify determinism
    let key2 = kdf::pbkdf2::derive_key(password, salt, iterations, 32).unwrap();
    assert_eq!(key, key2);
}

#[test]
fn test_argon2() {
    let password = b"user password";
    let salt = b"randomsaltrandomsalt"; // 20 bytes

    let key = kdf::argon2::derive_key(password, Some(salt), 4096, 3, 1, 32).unwrap();
    assert_eq!(key.len(), 32);

    // Verify determinism
    let key2 = kdf::argon2::derive_key(password, Some(salt), 4096, 3, 1, 32).unwrap();
    assert_eq!(key, key2);
}

#[test]
fn test_random_generation() {
    let bytes1 = random::generate_random_bytes(32).unwrap();
    let bytes2 = random::generate_random_bytes(32).unwrap();

    assert_eq!(bytes1.len(), 32);
    assert_eq!(bytes2.len(), 32);
    assert_ne!(bytes1, bytes2);
}

#[test]
fn test_key_material_zeroization() {
    let sensitive_data = vec![0xFF; 32];
    let key = KeyMaterial::from_bytes(sensitive_data);

    // Use the key
    assert_eq!(key.as_bytes().len(), 32);

    // Drop the key - it should be zeroized automatically
    drop(key);

    // Note: We can't actually verify zeroization occurred since the memory is freed,
    // but the zeroize(drop) attribute ensures it happens
}
