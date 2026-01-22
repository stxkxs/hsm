//! Hardware backend trait definition
//!
//! This module defines the core `HardwareBackend` trait that all TEE implementations must provide.

use crate::{error::HardwareResult, AttestationReport, PlaintextKey, SealedKey, TeeMeasurements};
use async_trait::async_trait;

/// Core hardware backend trait for TEE operations
///
/// This trait provides a uniform interface for key sealing, unsealing, attestation,
/// and remote signing across different TEE platforms (AWS Nitro, Intel SGX, AMD SEV).
///
/// # Security Properties
///
/// Implementations must guarantee:
///
/// 1. **Binding**: Sealed keys can only be unsealed within the same TEE with the same measurements
/// 2. **Confidentiality**: Key material never leaves the TEE in plaintext
/// 3. **Integrity**: Attestation reports are cryptographically signed and verifiable
/// 4. **Freshness**: Attestation includes nonces to prevent replay attacks
///
/// # Performance
///
/// Target latencies (production deployment):
/// - `seal_key`: < 10ms
/// - `unseal_key`: < 10ms
/// - `attest`: < 50ms (includes network roundtrip for remote attestation)
/// - `remote_sign`: < 5ms (critical path for transaction signing)
///
/// # Examples
///
/// ```rust,no_run
/// use hsm_hardware_backend::{HardwareBackend, PlaintextKey};
///
/// async fn example(backend: &dyn HardwareBackend) -> Result<(), Box<dyn std::error::Error>> {
///     // Seal a key inside the TEE
///     let plaintext = PlaintextKey::new(vec![0u8; 32]);
///     let sealed = backend.seal_key(&plaintext).await?;
///
///     // Later, unseal it (only works inside the same TEE)
///     let unsealed = backend.unseal_key(&sealed).await?;
///
///     // Generate attestation proof
///     let attestation = backend.attest(Some(b"challenge-nonce")).await?;
///
///     // Remote sign a message inside the TEE
///     let signature = backend.remote_sign("key-id", b"message to sign").await?;
///
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait HardwareBackend: Send + Sync {
    /// Seal (encrypt) a plaintext key using the TEE's sealing capabilities
    ///
    /// The sealed key is cryptographically bound to the TEE's measurements and
    /// can only be unsealed within the same TEE environment.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The key material to seal
    ///
    /// # Returns
    ///
    /// A `SealedKey` containing the encrypted key and metadata
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The TEE is not available
    /// - Sealing operation fails
    /// - Internal encryption error
    ///
    /// # Security
    ///
    /// - The plaintext key is zeroized from memory after sealing
    /// - The sealed key can only be unsealed by this TEE instance
    /// - Sealed keys are portable across restarts (saved to disk)
    async fn seal_key(&self, plaintext: &PlaintextKey) -> HardwareResult<SealedKey>;

    /// Unseal (decrypt) a sealed key using the TEE's unsealing capabilities
    ///
    /// # Arguments
    ///
    /// * `sealed` - The sealed key to unseal
    ///
    /// # Returns
    ///
    /// The plaintext key material
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The sealed key was sealed by a different TEE
    /// - TEE measurements have changed (code update, config change)
    /// - Decryption fails
    /// - Sealed key format is invalid
    ///
    /// # Security
    ///
    /// - The plaintext key is zeroized when dropped
    /// - Unsealing verifies the TEE measurements match
    /// - Tampering with sealed keys is detected
    async fn unseal_key(&self, sealed: &SealedKey) -> HardwareResult<PlaintextKey>;

    /// Generate an attestation report proving code is running in a TEE
    ///
    /// Attestation reports provide cryptographic proof of:
    /// - The code running in the TEE (code hash)
    /// - The configuration/data loaded (data hash)
    /// - The TEE platform and version
    ///
    /// # Arguments
    ///
    /// * `nonce` - Optional nonce for freshness (prevents replay)
    ///
    /// # Returns
    ///
    /// An `AttestationReport` with measurements and signature
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Attestation service is unavailable
    /// - TEE is not properly initialized
    /// - Signature generation fails
    ///
    /// # Performance
    ///
    /// This may involve network communication with attestation services:
    /// - AWS Nitro: Communicates with KMS for signature
    /// - Intel SGX: May communicate with IAS (Intel Attestation Service)
    /// - AMD SEV: Local attestation (no network)
    async fn attest(&self, nonce: Option<&[u8]>) -> HardwareResult<AttestationReport>;

    /// Verify an attestation report from another TEE
    ///
    /// # Arguments
    ///
    /// * `report` - The attestation report to verify
    /// * `expected_measurements` - The expected TEE measurements
    ///
    /// # Returns
    ///
    /// `Ok(())` if verification succeeds
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Signature verification fails
    /// - Measurements don't match expected values
    /// - Attestation document is malformed
    /// - Attestation has expired or nonce is replayed
    async fn verify_attestation(
        &self,
        report: &AttestationReport,
        expected_measurements: &TeeMeasurements,
    ) -> HardwareResult<()>;

    /// Perform a cryptographic signing operation inside the TEE
    ///
    /// This is the critical path for transaction signing in applications like
    /// cryptocurrency wallets. Keys never leave the TEE.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Identifier of the key to use for signing
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// The signature bytes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key not found
    /// - Signing operation fails
    /// - TEE is not available
    ///
    /// # Performance
    ///
    /// **Target: < 5ms latency** (critical for high-throughput signing)
    ///
    /// Optimizations:
    /// - Keys are cached in TEE memory (no disk I/O)
    /// - Signing uses hardware acceleration when available
    /// - Minimal network communication
    async fn remote_sign(&self, key_id: &str, message: &[u8]) -> HardwareResult<Vec<u8>>;

    /// Get the backend type
    fn backend_type(&self) -> crate::BackendType;

    /// Check if the backend is available and functional
    ///
    /// This can be used for health checks and backend selection.
    async fn is_available(&self) -> bool;
}

/// Verify an attestation report against expected measurements
///
/// This is a convenience function that works across different backend types.
///
/// # Arguments
///
/// * `report` - The attestation report to verify
/// * `expected_measurements` - The expected TEE measurements
///
/// # Returns
///
/// `Ok(())` if verification succeeds
///
/// # Errors
///
/// Returns an error if verification fails or backend type is unsupported
pub async fn verify_attestation_report(
    report: &AttestationReport,
    _expected_measurements: &TeeMeasurements,
) -> HardwareResult<()> {
    use crate::BackendType;

    match report.backend_type {
        #[cfg(feature = "aws-nitro")]
        BackendType::AwsNitro => {
            crate::nitro::NitroEnclaveBackend::verify_attestation_static(
                report,
                _expected_measurements,
            )
            .await
        }

        #[cfg(feature = "intel-sgx")]
        BackendType::IntelSgx => {
            crate::sgx::SgxBackend::verify_attestation_static(report, _expected_measurements).await
        }

        #[cfg(feature = "amd-sev")]
        BackendType::AmdSev => {
            crate::sev::SevBackend::verify_attestation_static(report, _expected_measurements).await
        }

        BackendType::Software => Err(crate::error::HardwareError::NotImplemented(
            "Software backend does not support attestation".to_string(),
        )),

        #[allow(unreachable_patterns)]
        _ => Err(crate::error::HardwareError::BackendNotAvailable(format!(
            "Backend type {:?} not compiled in",
            report.backend_type
        ))),
    }
}
