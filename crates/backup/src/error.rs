//! Error types for the backup module.

use thiserror::Error;

/// Result type for backup operations
pub type Result<T> = std::result::Result<T, BackupError>;

/// Errors that can occur during backup operations
#[derive(Error, Debug)]
pub enum BackupError {
    /// Empty data provided
    #[error("Empty data provided")]
    EmptyData,

    /// Weak or empty password
    #[error("Weak or empty password")]
    WeakPassword,

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    Decryption(String),

    /// Serialization failed
    #[error("Serialization failed: {0}")]
    Serialization(String),

    /// Deserialization failed
    #[error("Deserialization failed: {0}")]
    Deserialization(String),

    /// Invalid password
    #[error("Invalid password")]
    InvalidPassword,

    /// Invalid backup format
    #[error("Invalid backup format: {0}")]
    InvalidFormat(String),

    /// Unsupported backup version
    #[error("Unsupported backup version: {0}")]
    UnsupportedVersion(u32),

    /// Invalid threshold
    #[error("Invalid threshold")]
    InvalidThreshold,

    /// Invalid share count
    #[error("Invalid share count")]
    InvalidShareCount,

    /// Threshold exceeds total shares
    #[error("Threshold exceeds total shares")]
    ThresholdExceedsShares,

    /// Share generation failed
    #[error("Share generation failed")]
    ShareGenerationFailed,

    /// Insufficient shares for recovery
    #[error("Insufficient shares for recovery")]
    InsufficientShares,

    /// Inconsistent share metadata
    #[error("Inconsistent share metadata")]
    InconsistentShares,

    /// Invalid share
    #[error("Invalid share: {0}")]
    InvalidShare(String),

    /// Secret recovery failed
    #[error("Secret recovery failed: {0}")]
    RecoveryFailed(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Compression failed
    #[error("Compression failed: {0}")]
    CompressionFailed(String),

    /// Decompression failed
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),

    /// Integrity check failed
    #[error("Integrity check failed")]
    IntegrityCheckFailed,

    /// No full backup found
    #[error("No full backup found")]
    NoFullBackup,

    /// Invalid key size
    #[error("Invalid key size")]
    InvalidKeySize,

    /// Share recovery failed
    #[error("Share recovery failed")]
    ShareRecoveryFailed,

    /// Share validation failed
    #[error("Share validation failed")]
    ShareValidationFailed,

    /// Key derivation failed (generic)
    #[error("Key derivation failed")]
    KeyDerivationFailed,

    /// Encryption operation failed (generic)
    #[error("Encryption failed")]
    EncryptionFailed,

    /// Restore verification failed
    #[error("Restore verification failed")]
    RestoreVerificationFailed,

    /// Insufficient shares with specific counts
    #[error("Insufficient shares: provided {provided}, required {required}")]
    InsufficientSharesWithCount { provided: usize, required: usize },
}
