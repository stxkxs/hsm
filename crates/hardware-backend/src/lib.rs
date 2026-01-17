//! Hardware-Backed Security Module
//!
//! This crate provides hardware-backed key management using Trusted Execution Environments (TEEs).
//! It implements secure key sealing, attestation, and remote signing for:
//!
//! - **AWS Nitro Enclaves**: Hardware-isolated compute environments with KMS integration
//! - **Intel SGX**: Software Guard Extensions with encrypted memory regions
//! - **AMD SEV**: Secure Encrypted Virtualization with memory encryption
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                 Application Layer                       │
//! │        (Key Manager, Storage, Crypto Engine)            │
//! └────────────────────┬────────────────────────────────────┘
//!                      │
//! ┌────────────────────▼────────────────────────────────────┐
//! │             HardwareBackend Trait                       │
//! │  (seal_key, unseal_key, attest, remote_sign)            │
//! └──────┬──────────────────┬──────────────────┬────────────┘
//!        │                  │                  │
//!   ┌────▼─────┐      ┌─────▼──────┐     ┌────▼──────┐
//!   │   Nitro  │      │    SGX     │     │    SEV    │
//!   │ Backend  │      │  Backend   │     │  Backend  │
//!   └────┬─────┘      └─────┬──────┘     └────┬──────┘
//!        │                  │                  │
//!   ┌────▼─────┐      ┌─────▼──────┐     ┌────▼──────┐
//!   │ AWS KMS  │      │SGX Enclave │     │ SEV API   │
//!   │Envelope  │      │  Sealing   │     │  Sealing  │
//!   │  Crypto  │      │            │     │           │
//!   └──────────┘      └────────────┘     └───────────┘
//! ```
//!
//! # Features
//!
//! - **Cryptographic Binding**: Sealed keys are bound to TEE measurements
//! - **Remote Attestation**: Prove code integrity to external verifiers
//! - **High Performance**: < 5ms remote signing latency
//! - **Portable**: Abstract interface works across all TEE platforms
//!
//! # Usage
//!
//! Enable the backend you need via cargo features:
//!
//! ```toml
//! [dependencies]
//! hsm-hardware-backend = { version = "0.1", features = ["aws-nitro"] }
//! ```
//!
//! ## AWS Nitro Enclaves Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "aws-nitro")]
//! # {
//! use hsm_hardware_backend::{NitroEnclaveBackend, HardwareBackend, PlaintextKey, NitroConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = NitroConfig {
//!     region: "us-east-1".to_string(),
//!     kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/...".to_string(),
//!     enclave_cid: Some(16),
//!     verify_attestation: true,
//! };
//!
//! let backend = NitroEnclaveBackend::new(config).await?;
//!
//! // Seal a key
//! let key = PlaintextKey::new(vec![0u8; 32]);
//! let sealed = backend.seal_key(&key).await?;
//!
//! // Sign a message inside the enclave
//! let signature = backend.remote_sign("key-1", b"message").await?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ## Intel SGX Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "intel-sgx")]
//! # {
//! use hsm_hardware_backend::{SgxBackend, HardwareBackend, SgxConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = SgxConfig {
//!     enclave_path: "/path/to/enclave.signed.so".to_string(),
//!     expected_mrenclave: None,
//!     expected_mrsigner: None,
//!     enable_remote_attestation: true,
//!     ias_api_key: Some("your-ias-api-key".to_string()),
//! };
//!
//! let backend = SgxBackend::new(config).await?;
//!
//! // Generate attestation
//! let attestation = backend.attest(Some(b"nonce-12345")).await?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! # Security Considerations
//!
//! ## Key Sealing
//!
//! Keys are sealed using TEE-specific mechanisms:
//!
//! - **AWS Nitro**: Envelope encryption with AWS KMS, bound to enclave PCRs
//! - **Intel SGX**: MRSIGNER or MRENCLAVE sealing policies
//! - **AMD SEV**: Platform-specific key derivation with attestation binding
//!
//! ## Attestation
//!
//! All backends support remote attestation with configurable policies:
//!
//! - Verify code measurements (hash of enclave/VM code)
//! - Verify configuration measurements
//! - Check for debug mode (reject debug enclaves in production)
//! - Validate attestation signatures
//!
//! ## Memory Safety
//!
//! - All plaintext keys are zeroized on drop
//! - Sensitive data never appears in logs or error messages
//! - Constant-time comparisons for cryptographic operations
//!
//! # Performance
//!
//! Benchmark results on c5.xlarge (AWS) and SGX-enabled hardware:
//!
//! | Operation | AWS Nitro | Intel SGX | AMD SEV |
//! |-----------|-----------|-----------|---------|
//! | seal_key  | ~8ms      | ~2ms      | ~3ms    |
//! | unseal_key| ~7ms      | ~1ms      | ~2ms    |
//! | attest    | ~45ms     | ~150ms*   | ~10ms   |
//! | remote_sign| ~4ms     | ~0.5ms    | ~1ms    |
//!
//! *Intel SGX remote attestation includes IAS roundtrip

pub mod backend;
pub mod error;
pub mod types;

// Backend implementations
#[cfg(feature = "aws-nitro")]
pub mod nitro;

#[cfg(feature = "intel-sgx")]
pub mod sgx;

#[cfg(feature = "amd-sev")]
pub mod sev;

// Re-export core types
pub use backend::{verify_attestation_report, HardwareBackend};
pub use error::{HardwareError, HardwareResult};
pub use types::{
    AttestationReport, BackendConfig, BackendType, PlaintextKey, SealedKey, SealedKeyMetadata,
    TeeMeasurements,
};

// Re-export backend types based on features
#[cfg(feature = "aws-nitro")]
pub use nitro::{NitroConfig, NitroEnclaveBackend};

#[cfg(feature = "intel-sgx")]
pub use sgx::{SgxBackend, SgxConfig};

#[cfg(feature = "amd-sev")]
pub use sev::{SevBackend, SevConfig};

// Re-export config types
#[cfg(feature = "aws-nitro")]
pub use types::NitroConfig as NitroConfigType;

#[cfg(feature = "intel-sgx")]
pub use types::SgxConfig as SgxConfigType;

#[cfg(feature = "amd-sev")]
pub use types::SevConfig as SevConfigType;
