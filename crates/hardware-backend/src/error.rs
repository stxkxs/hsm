//! Error types for hardware backend operations

use thiserror::Error;

/// Result type for hardware backend operations
pub type HardwareResult<T> = Result<T, HardwareError>;

/// Errors that can occur during hardware backend operations
#[derive(Error, Debug)]
pub enum HardwareError {
    /// Backend not available or not initialized
    #[error("Backend not available: {0}")]
    BackendNotAvailable(String),

    /// Sealing operation failed
    #[error("Sealing failed: {0}")]
    SealingFailed(String),

    /// Unsealing operation failed
    #[error("Unsealing failed: {0}")]
    UnsealingFailed(String),

    /// Attestation failed
    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    /// Attestation verification failed
    #[error("Attestation verification failed: {0}")]
    AttestationVerificationFailed(String),

    /// Remote signing operation failed
    #[error("Remote signing failed: {0}")]
    RemoteSigningFailed(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Decryption error
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// AWS KMS error
    #[cfg(feature = "aws-nitro")]
    #[error("AWS KMS error: {0}")]
    AwsKmsError(String),

    /// AWS Nitro Enclaves error
    #[cfg(feature = "aws-nitro")]
    #[error("AWS Nitro Enclaves error: {0}")]
    NitroEnclaveError(String),

    /// Intel SGX error
    #[cfg(feature = "intel-sgx")]
    #[error("Intel SGX error: {0}")]
    SgxError(String),

    /// AMD SEV error
    #[cfg(feature = "amd-sev")]
    #[error("AMD SEV error: {0}")]
    SevError(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Not implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

#[cfg(feature = "aws-nitro")]
impl<E> From<aws_sdk_kms::error::SdkError<E>> for HardwareError
where
    E: std::error::Error + 'static,
{
    fn from(err: aws_sdk_kms::error::SdkError<E>) -> Self {
        HardwareError::AwsKmsError(err.to_string())
    }
}
