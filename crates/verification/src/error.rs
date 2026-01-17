//! Error types for formal verification operations.

use thiserror::Error;

/// Result type for verification operations
pub type Result<T> = std::result::Result<T, VerificationError>;

/// Errors that can occur during formal verification
#[derive(Error, Debug)]
pub enum VerificationError {
    /// SMT solver returned unsatisfiable (property violated)
    #[error("Verification failed: property does not hold - {0}")]
    PropertyViolation(String),

    /// SMT solver timeout
    #[error("Verification timeout: solver exceeded time limit")]
    Timeout,

    /// SMT solver returned unknown
    #[error("Verification inconclusive: solver returned unknown - {0}")]
    Unknown(String),

    /// Invalid input to verification
    #[error("Invalid verification input: {0}")]
    InvalidInput(String),

    /// Encoding error when converting to SMT
    #[error("SMT encoding error: {0}")]
    EncodingError(String),

    /// Bounded model checking exceeded bounds
    #[error("Bounded verification limit exceeded: {0}")]
    BoundExceeded(String),

    /// Shamir's Secret Sharing verification error
    #[error("Shamir verification error: {0}")]
    ShamirError(String),

    /// Ed25519 verification error
    #[error("Ed25519 verification error: {0}")]
    Ed25519Error(String),

    /// ECDSA verification error
    #[error("ECDSA verification error: {0}")]
    EcdsaError(String),

    /// RSA verification error
    #[error("RSA verification error: {0}")]
    RsaError(String),

    /// Generic verification error
    #[error("Verification error: {0}")]
    Other(String),
}
