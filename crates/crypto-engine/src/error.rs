//! Error types for cryptographic operations.

use thiserror::Error;

/// Cryptographic operation errors.
///
/// All cryptographic operations return this error type for failures.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Invalid key format or encoding.
    #[error("Invalid key format: {0}")]
    InvalidKey(String),

    /// Key size doesn't match algorithm requirements.
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected key size in bytes
        expected: usize,
        /// Actual key size in bytes
        actual: usize,
    },

    /// Signature size doesn't match algorithm requirements.
    #[error("Invalid signature size: expected {expected}, got {actual}")]
    InvalidSignatureSize {
        /// Expected signature size in bytes
        expected: usize,
        /// Actual signature size in bytes
        actual: usize,
    },

    /// Signature verification failed (signature is invalid).
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Message exceeds maximum size for algorithm.
    #[error("Message too large: {0} bytes (max allowed varies by algorithm)")]
    MessageTooLarge(usize),

    /// Plaintext exceeds maximum size for encryption.
    #[error("Plaintext too large: {0} bytes")]
    PlaintextTooLarge(usize),

    /// Ciphertext is too small to be valid.
    #[error("Ciphertext too small: expected at least {expected}, got {actual}")]
    CiphertextTooSmall {
        /// Minimum expected size in bytes
        expected: usize,
        /// Actual size in bytes
        actual: usize,
    },

    /// Nonce/IV size is invalid for algorithm.
    #[error("Invalid nonce size: expected {expected}, got {actual}")]
    InvalidNonceSize {
        /// Expected nonce size in bytes
        expected: usize,
        /// Actual nonce size in bytes
        actual: usize,
    },

    /// Encryption operation failed.
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption or authentication failed.
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Requested algorithm is not supported or implemented.
    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),

    /// Insufficient system entropy for cryptographic operations.
    #[error("Insufficient entropy")]
    InsufficientEntropy,

    /// Internal cryptographic library error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for cryptographic operations.
pub type Result<T> = std::result::Result<T, CryptoError>;
