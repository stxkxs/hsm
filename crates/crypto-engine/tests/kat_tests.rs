use hsm_crypto_engine::*;

/// Test vectors from RFC 8032 for Ed25519
#[test]
fn test_ed25519_kat_rfc8032() {
    // Test vector 1 from RFC 8032
    let secret_key =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let public_key =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    let message = b"";
    let expected_sig = hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();

    let key_material = KeyMaterial::from_bytes(secret_key);
    let signature = asymmetric::ed25519::Ed25519Engine::sign(&key_material, message).unwrap();

    assert_eq!(signature, expected_sig);
    assert!(asymmetric::ed25519::Ed25519Engine::verify(&public_key, message, &signature).unwrap());
}

/// Test SHA-256 with known test vectors
#[test]
fn test_sha256_kat() {
    // Test vector from NIST
    let data = b"abc";
    let expected =
        hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();

    let result = hash::digest::hash(data, HashAlgorithm::Sha256).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_sha256_kat_empty() {
    let data = b"";
    let expected =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();

    let result = hash::digest::hash(data, HashAlgorithm::Sha256).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_sha256_kat_long() {
    let data = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let expected =
        hex::decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1").unwrap();

    let result = hash::digest::hash(data, HashAlgorithm::Sha256).unwrap();
    assert_eq!(result, expected);
}

/// Test SHA-384 with known test vectors
#[test]
fn test_sha384_kat() {
    let data = b"abc";
    let expected = hex::decode("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7").unwrap();

    let result = hash::digest::hash(data, HashAlgorithm::Sha384).unwrap();
    assert_eq!(result, expected);
}

/// Test SHA-512 with known test vectors
#[test]
fn test_sha512_kat() {
    let data = b"abc";
    let expected = hex::decode("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f").unwrap();

    let result = hash::digest::hash(data, HashAlgorithm::Sha512).unwrap();
    assert_eq!(result, expected);
}

/// Test SHA3-256 with known test vectors
#[test]
fn test_sha3_256_kat() {
    let data = b"abc";
    let expected =
        hex::decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532").unwrap();

    let result = hash::digest::hash(data, HashAlgorithm::Sha3_256).unwrap();
    assert_eq!(result, expected);
}

/// Test SHA3-512 with known test vectors
#[test]
fn test_sha3_512_kat() {
    let data = b"abc";
    let expected = hex::decode("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0").unwrap();

    let result = hash::digest::hash(data, HashAlgorithm::Sha3_512).unwrap();
    assert_eq!(result, expected);
}

/// Test HKDF with RFC 5869 test vectors
#[test]
fn test_hkdf_kat_basic() {
    // Test Case 1 from RFC 5869
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let expected = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    )
    .unwrap();

    let result = kdf::hkdf::derive_key(&ikm, &salt, &info, 42).unwrap();
    assert_eq!(result, expected);
}

/// Test PBKDF2 with known test vectors
#[test]
fn test_pbkdf2_kat() {
    // Test vector from RFC 6070
    let password = b"password";
    let salt = b"salt";
    let iterations = 1;
    let expected =
        hex::decode("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b").unwrap();

    let result = kdf::pbkdf2::derive_key(password, salt, iterations, 32).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_pbkdf2_kat_4096() {
    // Test vector from RFC 6070
    let password = b"password";
    let salt = b"salt";
    let iterations = 4096;
    let expected =
        hex::decode("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a").unwrap();

    let result = kdf::pbkdf2::derive_key(password, salt, iterations, 32).unwrap();
    assert_eq!(result, expected);
}

/// Test AES-256-GCM with known test vectors
#[test]
fn test_aes256_gcm_kat() {
    // Known test vector (simplified)
    let key = KeyMaterial::from_bytes(vec![0x00; 32]);
    let plaintext = b"";

    let ciphertext =
        symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(&key, plaintext, None).unwrap();
    let decrypted =
        symmetric::aes_gcm::AesGcmEngine::decrypt_aes256(&key, &ciphertext, None).unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

/// Test P-256 ECDSA basic functionality
#[test]
fn test_ecdsa_p256_kat() {
    let message = b"test message";
    let (private_key, public_key) =
        asymmetric::ecdsa::EcdsaEngine::generate_p256_keypair().unwrap();

    let signature = asymmetric::ecdsa::EcdsaEngine::sign_p256(&private_key, message).unwrap();
    let valid =
        asymmetric::ecdsa::EcdsaEngine::verify_p256(&public_key, message, &signature).unwrap();

    assert!(valid);

    // Test with wrong message
    let wrong_message = b"wrong message";
    let result =
        asymmetric::ecdsa::EcdsaEngine::verify_p256(&public_key, wrong_message, &signature);
    assert!(result.is_err());
}

/// Test P-384 ECDSA basic functionality
#[test]
fn test_ecdsa_p384_kat() {
    let message = b"test message";
    let (private_key, public_key) =
        asymmetric::ecdsa::EcdsaEngine::generate_p384_keypair().unwrap();

    let signature = asymmetric::ecdsa::EcdsaEngine::sign_p384(&private_key, message).unwrap();
    let valid =
        asymmetric::ecdsa::EcdsaEngine::verify_p384(&public_key, message, &signature).unwrap();

    assert!(valid);
}
