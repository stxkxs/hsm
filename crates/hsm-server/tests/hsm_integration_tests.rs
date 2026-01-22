//! HSM Integration Tests
//!
//! These tests verify the complete HSM workflow across multiple modules:
//! - Key management (generation, import, rotation, deletion)
//! - Cryptographic operations (signing, verification, encryption, decryption)
//! - Secrets management (encrypted storage, versioning)
//!
//! The tests exercise the integration between:
//! - hsm-key-manager
//! - hsm-crypto-engine
//! - hsm-secrets

// =============================================================================
// Key Manager + Crypto Engine Integration
// =============================================================================

mod key_crypto_integration {
    use hsm_crypto_engine::asymmetric::{ecdsa, ed25519, rsa};
    use hsm_key_manager::{DefaultKeyManager, KeyManager, KeySpec, KeyType, KeyUsagePolicy};
    use std::collections::HashMap;

    #[test]
    fn test_generate_and_sign_ed25519() {
        let manager = DefaultKeyManager::new();

        // Generate Ed25519 key
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "crypto-test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: HashMap::new(),
        };

        let key_id = manager.generate_key(spec).unwrap();
        let key = manager.get_key(&key_id, "crypto-test").unwrap();

        // Extract key material and sign
        let private_key = key.private_material.as_ref().unwrap();
        let message = b"Test message for Ed25519 signature";

        let signature = ed25519::Ed25519Engine::sign(private_key, message).unwrap();
        assert_eq!(signature.len(), 64); // Ed25519 signature is 64 bytes

        // Verify signature
        let public_key = key.public_material.as_ref().unwrap();
        let is_valid = ed25519::Ed25519Engine::verify(public_key, message, &signature).unwrap();
        assert!(is_valid);

        // Verify wrong message fails (returns error, not Ok(false))
        let wrong_message = b"Wrong message";
        let result = ed25519::Ed25519Engine::verify(public_key, wrong_message, &signature);
        assert!(result.is_err());

        // Cleanup
        manager.delete_key(&key_id, "crypto-test").unwrap();
    }

    #[test]
    fn test_generate_and_sign_ecdsa_p256() {
        let manager = DefaultKeyManager::new();

        // Generate ECDSA P-256 key
        let spec = KeySpec {
            key_type: KeyType::EcdsaP256,
            namespace: "crypto-test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: HashMap::new(),
        };

        let key_id = manager.generate_key(spec).unwrap();
        let key = manager.get_key(&key_id, "crypto-test").unwrap();

        // Extract key material and sign
        let private_key = key.private_material.as_ref().unwrap();
        let message = b"Test message for ECDSA P-256 signature";

        let signature = ecdsa::EcdsaEngine::sign_p256(private_key, message).unwrap();
        assert!(!signature.is_empty());

        // Verify signature
        let public_key = key.public_material.as_ref().unwrap();
        let is_valid = ecdsa::EcdsaEngine::verify_p256(public_key, message, &signature).unwrap();
        assert!(is_valid);

        // Cleanup
        manager.delete_key(&key_id, "crypto-test").unwrap();
    }

    #[test]
    fn test_generate_and_sign_rsa() {
        let manager = DefaultKeyManager::new();

        // Generate RSA 2048 key
        let spec = KeySpec {
            key_type: KeyType::Rsa2048,
            namespace: "crypto-test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: HashMap::new(),
        };

        let key_id = manager.generate_key(spec).unwrap();
        let key = manager.get_key(&key_id, "crypto-test").unwrap();

        // Extract key material and sign
        let private_key = key.private_material.as_ref().unwrap();
        let message = b"Test message for RSA signature";

        let signature = rsa::RsaEngine::sign_pkcs1v15_sha256(private_key, message).unwrap();
        assert!(!signature.is_empty());

        // Verify signature
        let public_key = key.public_material.as_ref().unwrap();
        let is_valid =
            rsa::RsaEngine::verify_pkcs1v15_sha256(public_key, message, &signature).unwrap();
        assert!(is_valid);

        // Cleanup
        manager.delete_key(&key_id, "crypto-test").unwrap();
    }

    #[test]
    fn test_key_rotation_maintains_crypto_capability() {
        let manager = DefaultKeyManager::new();

        // Generate initial key
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "rotation-test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: HashMap::new(),
        };

        let old_key_id = manager.generate_key(spec).unwrap();
        let old_key = manager.get_key(&old_key_id, "rotation-test").unwrap();

        // Sign with old key
        let message = b"Message signed with v1 key";
        let old_private = old_key.private_material.as_ref().unwrap();
        let old_public = old_key.public_material.as_ref().unwrap().clone();
        let old_signature = ed25519::Ed25519Engine::sign(old_private, message).unwrap();

        // Rotate key
        let new_key_id = manager.rotate_key(&old_key_id, "rotation-test").unwrap();
        let new_key = manager.get_key(&new_key_id, "rotation-test").unwrap();

        // New key should have different material
        let new_public = new_key.public_material.as_ref().unwrap();
        assert_ne!(&old_public, new_public);

        // Old signature should still verify with old public key
        let is_valid =
            ed25519::Ed25519Engine::verify(&old_public, message, &old_signature).unwrap();
        assert!(is_valid);

        // New key can sign new messages
        let new_message = b"Message signed with v2 key";
        let new_private = new_key.private_material.as_ref().unwrap();
        let new_signature = ed25519::Ed25519Engine::sign(new_private, new_message).unwrap();

        let is_valid =
            ed25519::Ed25519Engine::verify(new_public, new_message, &new_signature).unwrap();
        assert!(is_valid);

        // Cleanup
        manager.delete_key(&old_key_id, "rotation-test").unwrap();
        manager.delete_key(&new_key_id, "rotation-test").unwrap();
    }

    #[test]
    fn test_multi_namespace_key_isolation() {
        let manager = DefaultKeyManager::new();

        // Create keys in different namespaces
        let spec1 = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "namespace-a".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: HashMap::new(),
        };

        let spec2 = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "namespace-b".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: HashMap::new(),
        };

        let key_a = manager.generate_key(spec1).unwrap();
        let key_b = manager.generate_key(spec2).unwrap();

        // Key A should not be accessible from namespace B
        assert!(manager.get_key(&key_a, "namespace-b").is_err());
        assert!(manager.get_key(&key_b, "namespace-a").is_err());

        // Keys should be accessible from their own namespace
        assert!(manager.get_key(&key_a, "namespace-a").is_ok());
        assert!(manager.get_key(&key_b, "namespace-b").is_ok());

        // Cleanup
        manager.delete_key(&key_a, "namespace-a").unwrap();
        manager.delete_key(&key_b, "namespace-b").unwrap();
    }
}

// =============================================================================
// Crypto Engine Standalone Tests
// =============================================================================

mod crypto_engine_tests {
    use hsm_crypto_engine::hash::digest::hash;
    use hsm_crypto_engine::symmetric::aes_gcm::AesGcmEngine;
    use hsm_crypto_engine::{HashAlgorithm, KeyMaterial};

    #[test]
    fn test_aes_gcm_encrypt_decrypt_roundtrip() {
        // Generate a random 256-bit key
        let key_bytes: Vec<u8> = (0..32).map(|i| (i * 13 + 7) as u8).collect();
        let key = KeyMaterial::from_bytes(key_bytes);

        let plaintext = b"This is a secret message that should be encrypted";
        let aad = Some(b"Additional authenticated data".as_slice());

        // Encrypt
        let ciphertext = AesGcmEngine::encrypt_aes256(&key, plaintext, aad).unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(&ciphertext[..], plaintext);

        // Decrypt
        let decrypted = AesGcmEngine::decrypt_aes256(&key, &ciphertext, aad).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_tamper_detection() {
        let key_bytes: Vec<u8> = (0..32).map(|i| (i * 17 + 3) as u8).collect();
        let key = KeyMaterial::from_bytes(key_bytes);

        let plaintext = b"Original message";
        let ciphertext = AesGcmEngine::encrypt_aes256(&key, plaintext, None).unwrap();

        // Tamper with ciphertext
        let mut tampered = ciphertext.clone();
        if !tampered.is_empty() {
            tampered[0] ^= 0xFF;
        }

        // Decryption should fail
        let result = AesGcmEngine::decrypt_aes256(&key, &tampered, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_algorithms() {
        let data = b"Test data for hashing";

        // SHA-256
        let sha256 = hash(data, HashAlgorithm::Sha256).unwrap();
        assert_eq!(sha256.len(), 32);

        // SHA-384
        let sha384 = hash(data, HashAlgorithm::Sha384).unwrap();
        assert_eq!(sha384.len(), 48);

        // SHA-512
        let sha512 = hash(data, HashAlgorithm::Sha512).unwrap();
        assert_eq!(sha512.len(), 64);

        // Different data should produce different hashes
        let other_data = b"Different data";
        let other_sha256 = hash(other_data, HashAlgorithm::Sha256).unwrap();
        assert_ne!(sha256, other_sha256);
    }
}

// =============================================================================
// Secrets Store Tests
// =============================================================================

mod secrets_store_tests {
    use hsm_secrets::{
        EncryptedSecretStore, SecretData, SecretMetadata, SecretPath, SecretStore, SecretValue,
    };

    #[tokio::test]
    async fn test_encrypted_secret_lifecycle() {
        let store = EncryptedSecretStore::new();

        // Create a secret
        let path = SecretPath::new("/app/database/credentials").unwrap();
        let mut data = SecretData::new();
        data.insert("username", SecretValue::string("admin"));
        data.insert("password", SecretValue::string("super-secret-123"));
        data.insert("port", SecretValue::string("5432"));

        let metadata = SecretMetadata::new()
            .with_description("Database credentials")
            .with_owner("dba-team");

        let secret = store.create(path.clone(), data, metadata).await.unwrap();
        assert_eq!(secret.current_version, 1);

        // Read and verify
        let (_, retrieved_data) = store.get(&path).await.unwrap();
        assert_eq!(
            retrieved_data.get("username").unwrap().as_str(),
            Some("admin")
        );
        assert_eq!(
            retrieved_data.get("password").unwrap().as_str(),
            Some("super-secret-123")
        );

        // Update secret
        let mut new_data = SecretData::new();
        new_data.insert("username", SecretValue::string("admin"));
        new_data.insert("password", SecretValue::string("new-password-456"));
        new_data.insert("port", SecretValue::string("5432"));

        let updated = store.update(&path, new_data).await.unwrap();
        assert_eq!(updated.current_version, 2);

        // Verify latest version
        let (_, latest) = store.get(&path).await.unwrap();
        assert_eq!(
            latest.get("password").unwrap().as_str(),
            Some("new-password-456")
        );

        // Verify old version still accessible
        let (_, v1) = store.get_version(&path, 1).await.unwrap();
        assert_eq!(
            v1.get("password").unwrap().as_str(),
            Some("super-secret-123")
        );

        // Delete
        store.delete(&path).await.unwrap();
        assert!(store.get(&path).await.is_err());
    }

    #[tokio::test]
    async fn test_encrypted_secret_path_hierarchy() {
        let store = EncryptedSecretStore::new();

        // Create secrets in a hierarchy
        let paths = [
            "/app/web/api-key",
            "/app/web/jwt-secret",
            "/app/database/postgres",
            "/app/database/redis",
            "/infrastructure/aws/access-key",
        ];

        for p in &paths {
            let path = SecretPath::new(*p).unwrap();
            store
                .create(path, SecretData::new(), SecretMetadata::default())
                .await
                .unwrap();
        }

        // List by prefix
        let app_secrets = store.list(&SecretPath::new("/app").unwrap()).await.unwrap();
        assert_eq!(app_secrets.len(), 4);

        let web_secrets = store
            .list(&SecretPath::new("/app/web").unwrap())
            .await
            .unwrap();
        assert_eq!(web_secrets.len(), 2);

        let db_secrets = store
            .list(&SecretPath::new("/app/database").unwrap())
            .await
            .unwrap();
        assert_eq!(db_secrets.len(), 2);

        let infra_secrets = store
            .list(&SecretPath::new("/infrastructure").unwrap())
            .await
            .unwrap();
        assert_eq!(infra_secrets.len(), 1);
    }

    #[tokio::test]
    async fn test_encrypted_secret_binary_data() {
        let store = EncryptedSecretStore::new();

        let path = SecretPath::new("/certs/server").unwrap();

        // Create a secret with binary data (simulating a certificate)
        let cert_data: Vec<u8> = (0..256).map(|i| i as u8).collect();

        let mut data = SecretData::new();
        data.insert("certificate", SecretValue::binary(cert_data.clone()));

        store
            .create(path.clone(), data, SecretMetadata::default())
            .await
            .unwrap();

        // Retrieve and verify
        let (_, retrieved) = store.get(&path).await.unwrap();
        let retrieved_cert = retrieved.get("certificate").unwrap().as_bytes();
        assert_eq!(retrieved_cert, cert_data);
    }
}

// =============================================================================
// End-to-End Workflow Tests
// =============================================================================

mod e2e_workflow_tests {
    use hsm_crypto_engine::asymmetric::ed25519;
    use hsm_key_manager::{DefaultKeyManager, KeyManager, KeySpec, KeyType, KeyUsagePolicy};
    use hsm_secrets::{
        EncryptedSecretStore, SecretData, SecretMetadata, SecretPath, SecretStore, SecretValue,
    };
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_key_generation_sign_and_store_signature() {
        // This test simulates a complete workflow:
        // 1. Generate a signing key
        // 2. Sign some data
        // 3. Store the signature in the secrets store

        let key_manager = DefaultKeyManager::new();
        let secret_store = EncryptedSecretStore::new();

        // Step 1: Generate signing key
        let spec = KeySpec {
            key_type: KeyType::Ed25519,
            namespace: "e2e-test".to_string(),
            policy: KeyUsagePolicy::default(),
            labels: HashMap::new(),
        };
        let key_id = key_manager.generate_key(spec).unwrap();
        let key = key_manager.get_key(&key_id, "e2e-test").unwrap();

        // Step 2: Sign data
        let document = b"Important document to be signed";
        let private_key = key.private_material.as_ref().unwrap();
        let signature = ed25519::Ed25519Engine::sign(private_key, document).unwrap();

        // Step 3: Store signature and metadata
        let path = SecretPath::new("/signatures/doc-001").unwrap();
        let mut data = SecretData::new();
        data.insert(
            "document_hash",
            SecretValue::binary(
                hsm_crypto_engine::hash::digest::hash(
                    document,
                    hsm_crypto_engine::HashAlgorithm::Sha256,
                )
                .unwrap(),
            ),
        );
        data.insert("signature", SecretValue::binary(signature.clone()));
        data.insert("key_id", SecretValue::string(key_id.to_string()));
        data.insert("algorithm", SecretValue::string("Ed25519"));

        let metadata = SecretMetadata::new()
            .with_description("Document signature")
            .with_owner("signing-service");

        secret_store
            .create(path.clone(), data, metadata)
            .await
            .unwrap();

        // Verify we can retrieve and verify the signature
        let (_, stored) = secret_store.get(&path).await.unwrap();
        let stored_signature = stored.get("signature").unwrap().as_bytes();

        let public_key = key.public_material.as_ref().unwrap();
        let is_valid =
            ed25519::Ed25519Engine::verify(public_key, document, &stored_signature).unwrap();
        assert!(is_valid);

        // Cleanup
        key_manager.delete_key(&key_id, "e2e-test").unwrap();
    }

    #[tokio::test]
    async fn test_multi_tenant_workflow() {
        // Simulate multiple tenants with isolated keys and secrets

        let key_manager = DefaultKeyManager::new();

        let tenants = ["tenant-alpha", "tenant-beta", "tenant-gamma"];

        // Each tenant generates keys and stores secrets
        for tenant in &tenants {
            // Generate tenant-specific signing key
            let spec = KeySpec {
                key_type: KeyType::Ed25519,
                namespace: tenant.to_string(),
                policy: KeyUsagePolicy::default(),
                labels: HashMap::new(),
            };
            let key_id = key_manager.generate_key(spec).unwrap();

            // Use the key
            let key = key_manager.get_key(&key_id, tenant).unwrap();
            let message = format!("Message from {}", tenant);
            let private_key = key.private_material.as_ref().unwrap();
            let signature = ed25519::Ed25519Engine::sign(private_key, message.as_bytes()).unwrap();

            // Verify tenant isolation
            for other_tenant in &tenants {
                if *other_tenant != *tenant {
                    assert!(key_manager.get_key(&key_id, other_tenant).is_err());
                }
            }

            // Verify signature works
            let public_key = key.public_material.as_ref().unwrap();
            let is_valid =
                ed25519::Ed25519Engine::verify(public_key, message.as_bytes(), &signature).unwrap();
            assert!(is_valid);

            // Cleanup
            key_manager.delete_key(&key_id, tenant).unwrap();
        }
    }
}
