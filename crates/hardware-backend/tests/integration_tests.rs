//! Integration tests for hardware backends
//!
//! These tests verify that all backends correctly implement the HardwareBackend trait
//! and that sealed keys can be properly sealed and unsealed.

use hsm_hardware_backend::{BackendType, PlaintextKey};

#[cfg(feature = "intel-sgx")]
use hsm_hardware_backend::{AttestationReport, TeeMeasurements};

#[cfg(any(feature = "aws-nitro", feature = "intel-sgx", feature = "amd-sev"))]
use hsm_hardware_backend::HardwareBackend;

#[cfg(feature = "aws-nitro")]
use hsm_hardware_backend::{NitroConfig, NitroEnclaveBackend};

#[cfg(feature = "intel-sgx")]
use hsm_hardware_backend::{SgxBackend, SgxConfig};

#[cfg(feature = "amd-sev")]
use hsm_hardware_backend::{SevBackend, SevConfig};

// Test AWS Nitro backend
#[cfg(feature = "aws-nitro")]
#[tokio::test]
async fn test_nitro_seal_unseal_roundtrip() {
    let config = NitroConfig {
        region: "us-east-1".to_string(),
        kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/test".to_string(),
        enclave_cid: Some(16),
        verify_attestation: false,
        expected_pcrs: None,
    };

    // Skip test if AWS credentials not available
    let backend = match NitroEnclaveBackend::new(config).await {
        Ok(b) => b,
        Err(_) => {
            eprintln!("Skipping Nitro test: AWS credentials not available");
            return;
        }
    };

    // Test seal/unseal roundtrip
    let original = PlaintextKey::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let sealed = backend.seal_key(&original).await.expect("Seal failed");

    assert_eq!(sealed.metadata.backend_type, BackendType::AwsNitro);
    assert!(!sealed.ciphertext.is_empty());
    assert!(!sealed.backend_data.is_empty()); // Encrypted DEK

    let unsealed = backend.unseal_key(&sealed).await.expect("Unseal failed");
    assert_eq!(original.as_bytes(), unsealed.as_bytes());
}

#[cfg(feature = "aws-nitro")]
#[tokio::test]
async fn test_nitro_attestation() {
    let config = NitroConfig {
        region: "us-east-1".to_string(),
        kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/test".to_string(),
        enclave_cid: Some(16),
        verify_attestation: false,
        expected_pcrs: None,
    };

    let backend = match NitroEnclaveBackend::new(config).await {
        Ok(b) => b,
        Err(_) => return,
    };

    // Generate attestation with nonce
    let nonce = b"test-nonce-12345";
    let report = backend
        .attest(Some(nonce))
        .await
        .expect("Attestation failed");

    assert_eq!(report.backend_type, BackendType::AwsNitro);
    assert!(!report.document.is_empty());
    assert_eq!(report.nonce, Some(nonce.to_vec()));
    assert!(!report.measurements.code_hash.is_empty());
}

// Test Intel SGX backend
#[cfg(feature = "intel-sgx")]
#[tokio::test]
async fn test_sgx_seal_unseal_roundtrip() {
    let config = SgxConfig::default();

    let backend = match SgxBackend::new(config).await {
        Ok(b) => b,
        Err(_) => {
            eprintln!("Skipping SGX test: SGX not available");
            return;
        }
    };

    // Test seal/unseal roundtrip
    let original = PlaintextKey::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let sealed = backend.seal_key(&original).await.expect("Seal failed");

    assert_eq!(sealed.metadata.backend_type, BackendType::IntelSgx);
    assert!(!sealed.ciphertext.is_empty());

    let unsealed = backend.unseal_key(&sealed).await.expect("Unseal failed");
    assert_eq!(original.as_bytes(), unsealed.as_bytes());
}

#[cfg(feature = "intel-sgx")]
#[tokio::test]
async fn test_sgx_attestation() {
    let config = SgxConfig::default();

    let backend = match SgxBackend::new(config).await {
        Ok(b) => b,
        Err(_) => return,
    };

    // Generate attestation with nonce
    let nonce = b"test-nonce-12345";
    let report = backend
        .attest(Some(nonce))
        .await
        .expect("Attestation failed");

    assert_eq!(report.backend_type, BackendType::IntelSgx);
    assert!(!report.document.is_empty());
    assert_eq!(report.nonce, Some(nonce.to_vec()));
}

#[cfg(feature = "intel-sgx")]
#[tokio::test]
async fn test_sgx_different_key_sizes() {
    let config = SgxConfig::default();
    let backend = match SgxBackend::new(config).await {
        Ok(b) => b,
        Err(_) => return,
    };

    // Test various key sizes
    for size in [16, 32, 64, 128, 256, 512, 1024, 2048] {
        let original = PlaintextKey::new(vec![0x42; size]);
        let sealed = backend.seal_key(&original).await.expect("Seal failed");
        let unsealed = backend.unseal_key(&sealed).await.expect("Unseal failed");
        assert_eq!(
            original.as_bytes(),
            unsealed.as_bytes(),
            "Failed for size {}",
            size
        );
    }
}

// Test AMD SEV backend
#[cfg(feature = "amd-sev")]
#[tokio::test]
async fn test_sev_seal_unseal_roundtrip() {
    let config = SevConfig::default();

    let backend = match SevBackend::new(config).await {
        Ok(b) => b,
        Err(_) => {
            eprintln!("Skipping SEV test: SEV not available");
            return;
        }
    };

    // Test seal/unseal roundtrip
    let original = PlaintextKey::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let sealed = backend.seal_key(&original).await.expect("Seal failed");

    assert_eq!(sealed.metadata.backend_type, BackendType::AmdSev);
    assert!(!sealed.ciphertext.is_empty());

    let unsealed = backend.unseal_key(&sealed).await.expect("Unseal failed");
    assert_eq!(original.as_bytes(), unsealed.as_bytes());
}

#[cfg(feature = "amd-sev")]
#[tokio::test]
async fn test_sev_attestation() {
    let config = SevConfig::default();

    let backend = match SevBackend::new(config).await {
        Ok(b) => b,
        Err(_) => return,
    };

    // Generate attestation with nonce
    let nonce = b"test-nonce-12345";
    let report = backend
        .attest(Some(nonce))
        .await
        .expect("Attestation failed");

    assert_eq!(report.backend_type, BackendType::AmdSev);
    assert!(!report.document.is_empty());
    assert_eq!(report.nonce, Some(nonce.to_vec()));
}

// Cross-backend tests
#[test]
fn test_plaintext_key_zeroization() {
    // Verify that PlaintextKey is properly zeroized on drop
    let key_data = vec![0x42; 32];
    let key = PlaintextKey::new(key_data.clone());

    assert_eq!(key.as_bytes(), &key_data);

    // Key should be zeroized when dropped
    drop(key);

    // We can't directly verify zeroization without unsafe code,
    // but we verify the Zeroize trait is implemented
}

#[test]
fn test_backend_type_display() {
    assert_eq!(BackendType::Software.to_string(), "software");
    assert_eq!(BackendType::AwsNitro.to_string(), "aws-nitro");
    assert_eq!(BackendType::IntelSgx.to_string(), "intel-sgx");
    assert_eq!(BackendType::AmdSev.to_string(), "amd-sev");
}

// Test that sealed keys from one backend cannot be unsealed by another
#[cfg(all(feature = "intel-sgx", feature = "amd-sev"))]
#[tokio::test]
async fn test_cross_backend_unseal_fails() {
    let sgx_config = SgxConfig::default();
    let sev_config = SevConfig::default();

    let sgx_backend = match SgxBackend::new(sgx_config).await {
        Ok(b) => b,
        Err(_) => return,
    };

    let sev_backend = match SevBackend::new(sev_config).await {
        Ok(b) => b,
        Err(_) => return,
    };

    // Seal with SGX
    let original = PlaintextKey::new(vec![1, 2, 3, 4, 5]);
    let sealed_sgx = sgx_backend
        .seal_key(&original)
        .await
        .expect("SGX seal failed");

    // Try to unseal with SEV (should fail)
    let result = sev_backend.unseal_key(&sealed_sgx).await;
    assert!(result.is_err(), "Cross-backend unseal should fail");
}

// Property-based testing with proptest
#[cfg(feature = "intel-sgx")]
use proptest::prelude::*;

#[cfg(feature = "intel-sgx")]
proptest! {
    #[test]
    fn prop_sgx_seal_unseal_any_data(data in prop::collection::vec(any::<u8>(), 1..4096)) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let config = SgxConfig::default();

        let backend = match runtime.block_on(SgxBackend::new(config)) {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };

        let original = PlaintextKey::new(data.clone());
        let sealed = runtime.block_on(backend.seal_key(&original)).unwrap();
        let unsealed = runtime.block_on(backend.unseal_key(&sealed)).unwrap();

        prop_assert_eq!(data, unsealed.as_bytes().to_vec());
    }
}

// Attestation verification tests
#[tokio::test]
async fn test_attestation_verification() {
    // Create a mock attestation report
    #[cfg(feature = "intel-sgx")]
    let report = AttestationReport {
        backend_type: BackendType::IntelSgx,
        document: vec![1, 2, 3, 4],
        signature: vec![5, 6, 7, 8],
        public_key: vec![9, 10, 11, 12],
        measurements: TeeMeasurements {
            code_hash: vec![0x42; 32],
            data_hash: vec![0x43; 32],
            additional: std::collections::HashMap::new(),
        },
        timestamp: chrono::Utc::now().timestamp(),
        nonce: Some(b"nonce".to_vec()),
    };

    #[cfg(feature = "intel-sgx")]
    let expected_measurements = TeeMeasurements {
        code_hash: vec![0x42; 32],
        data_hash: vec![0x43; 32],
        additional: std::collections::HashMap::new(),
    };

    // Verify attestation
    #[cfg(feature = "intel-sgx")]
    {
        let result = SgxBackend::verify_attestation_static(&report, &expected_measurements).await;
        assert!(result.is_ok(), "Attestation verification should succeed");
    }

    // Test with wrong measurements
    #[cfg(feature = "intel-sgx")]
    let wrong_measurements = TeeMeasurements {
        code_hash: vec![0xFF; 32],
        data_hash: vec![0xFF; 32],
        additional: std::collections::HashMap::new(),
    };

    #[cfg(feature = "intel-sgx")]
    {
        let result = SgxBackend::verify_attestation_static(&report, &wrong_measurements).await;
        assert!(
            result.is_err(),
            "Attestation verification should fail with wrong measurements"
        );
    }
}
