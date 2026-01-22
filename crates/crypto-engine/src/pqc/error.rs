//! PQC-specific error types.
//!
//! Provides detailed error information for post-quantum cryptographic operations.

use thiserror::Error;

/// Errors specific to post-quantum cryptographic operations.
#[derive(Error, Debug)]
pub enum PqcError {
    /// Invalid key size for the specified algorithm.
    #[error("Invalid key size for {algorithm}: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Algorithm name
        algorithm: &'static str,
        /// Expected key size in bytes
        expected: usize,
        /// Actual key size in bytes
        actual: usize,
    },

    /// Invalid ciphertext size for the specified algorithm.
    #[error("Invalid ciphertext size for {algorithm}: expected {expected}, got {actual}")]
    InvalidCiphertextSize {
        /// Algorithm name
        algorithm: &'static str,
        /// Expected ciphertext size in bytes
        expected: usize,
        /// Actual ciphertext size in bytes
        actual: usize,
    },

    /// Invalid signature size for the specified algorithm.
    #[error("Invalid signature size for {algorithm}: expected {expected}, got {actual}")]
    InvalidSignatureSize {
        /// Algorithm name
        algorithm: &'static str,
        /// Expected signature size in bytes
        expected: usize,
        /// Actual signature size in bytes
        actual: usize,
    },

    /// Decapsulation operation failed.
    #[error("Decapsulation failed: shared secrets do not match")]
    DecapsulationFailed,

    /// Signature verification failed.
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Key generation failed.
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Encapsulation operation failed.
    #[error("Encapsulation failed: {0}")]
    EncapsulationFailed(String),

    /// Signing operation failed.
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Invalid public key format.
    #[error("Invalid public key format for {algorithm}")]
    InvalidPublicKey {
        /// Algorithm name
        algorithm: &'static str,
    },

    /// Invalid secret key format.
    #[error("Invalid secret key format for {algorithm}")]
    InvalidSecretKey {
        /// Algorithm name
        algorithm: &'static str,
    },
}

impl From<PqcError> for crate::CryptoError {
    fn from(err: PqcError) -> Self {
        crate::CryptoError::Internal(err.to_string())
    }
}
