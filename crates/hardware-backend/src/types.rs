//! Common types for hardware backends

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A key that has been sealed (encrypted) by a hardware backend
///
/// Sealed keys are cryptographically bound to the TEE and can only be unsealed
/// within the same TEE environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKey {
    /// The sealed (encrypted) key material
    pub ciphertext: Vec<u8>,

    /// Encryption metadata (algorithm, key ID, etc.)
    pub metadata: SealedKeyMetadata,

    /// Backend-specific data (e.g., KMS key ARN, SGX seal key policy)
    pub backend_data: Vec<u8>,
}

/// Metadata for a sealed key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKeyMetadata {
    /// Encryption algorithm used for sealing
    pub algorithm: String,

    /// Version of the sealing format
    pub version: u32,

    /// Timestamp when the key was sealed (Unix timestamp)
    pub sealed_at: i64,

    /// Backend type that sealed this key
    pub backend_type: BackendType,

    /// Additional backend-specific metadata
    #[serde(default)]
    pub additional: std::collections::HashMap<String, String>,
}

/// Type of hardware backend
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendType {
    /// Software-only backend (for testing/development)
    Software,

    /// AWS Nitro Enclaves
    AwsNitro,

    /// Intel SGX
    IntelSgx,

    /// AMD SEV
    AmdSev,
}

impl std::fmt::Display for BackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendType::Software => write!(f, "software"),
            BackendType::AwsNitro => write!(f, "aws-nitro"),
            BackendType::IntelSgx => write!(f, "intel-sgx"),
            BackendType::AmdSev => write!(f, "amd-sev"),
        }
    }
}

/// Attestation report from a TEE
///
/// Attestation reports provide cryptographic proof that code is running in a
/// trusted execution environment with specific measurements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// The type of backend that generated this attestation
    pub backend_type: BackendType,

    /// The raw attestation document (backend-specific format)
    pub document: Vec<u8>,

    /// Signature over the attestation document
    pub signature: Vec<u8>,

    /// Public key that can verify the signature
    pub public_key: Vec<u8>,

    /// Measurements of the TEE (hashes of code, config, etc.)
    pub measurements: TeeMeasurements,

    /// Timestamp when attestation was generated
    pub timestamp: i64,

    /// Nonce for freshness (prevents replay attacks)
    pub nonce: Option<Vec<u8>>,
}

/// Measurements that identify a TEE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeMeasurements {
    /// Platform Configuration Registers (PCRs) for AWS Nitro
    /// or MRENCLAVE for SGX
    pub code_hash: Vec<u8>,

    /// Configuration/data hash (PCR for Nitro, MRSIGNER for SGX)
    pub data_hash: Vec<u8>,

    /// Additional measurements (backend-specific)
    #[serde(default)]
    pub additional: std::collections::HashMap<String, Vec<u8>>,
}

/// Plaintext key material (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PlaintextKey {
    /// The raw key bytes
    bytes: Vec<u8>,
}

impl PlaintextKey {
    /// Create a new plaintext key
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get a reference to the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the key bytes (consumes self)
    pub fn into_bytes(mut self) -> Vec<u8> {
        // Take ownership of bytes before drop
        std::mem::take(&mut self.bytes)
    }
}

impl std::fmt::Debug for PlaintextKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaintextKey")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Configuration for hardware backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// The backend type to use
    pub backend_type: BackendType,

    /// AWS Nitro Enclaves configuration
    #[cfg(feature = "aws-nitro")]
    pub nitro_config: Option<NitroConfig>,

    /// Intel SGX configuration
    #[cfg(feature = "intel-sgx")]
    pub sgx_config: Option<SgxConfig>,

    /// AMD SEV configuration
    #[cfg(feature = "amd-sev")]
    pub sev_config: Option<SevConfig>,
}

/// AWS Nitro Enclaves configuration
#[cfg(feature = "aws-nitro")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NitroConfig {
    /// AWS region
    pub region: String,

    /// KMS key ARN for envelope encryption
    pub kms_key_arn: String,

    /// Enclave CID (Cryptographic Identifier)
    pub enclave_cid: Option<u32>,

    /// Enable attestation verification
    pub verify_attestation: bool,
}

/// Intel SGX configuration
#[cfg(feature = "intel-sgx")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SgxConfig {
    /// Enclave file path
    pub enclave_path: String,

    /// Expected MRENCLAVE (code hash)
    pub expected_mrenclave: Option<Vec<u8>>,

    /// Expected MRSIGNER (signer hash)
    pub expected_mrsigner: Option<Vec<u8>>,

    /// Enable remote attestation
    pub enable_remote_attestation: bool,

    /// IAS (Intel Attestation Service) API key
    pub ias_api_key: Option<String>,
}

/// AMD SEV configuration
#[cfg(feature = "amd-sev")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SevConfig {
    /// SEV device path
    pub device_path: String,

    /// Expected measurement
    pub expected_measurement: Option<Vec<u8>>,

    /// Enable remote attestation
    pub enable_remote_attestation: bool,
}
