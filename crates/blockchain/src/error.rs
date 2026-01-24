//! Error types for the blockchain module

use thiserror::Error;

/// Result type for blockchain operations
pub type Result<T> = std::result::Result<T, BlockchainError>;

/// Blockchain-specific errors
#[derive(Debug, Error)]
pub enum BlockchainError {
    /// Invalid mnemonic phrase
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Invalid derivation path
    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),

    /// Invalid seed length
    #[error("Invalid seed length: expected {expected}, got {actual}")]
    InvalidSeedLength { expected: usize, actual: usize },

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Invalid address length
    #[error("Invalid address length: expected {expected}, got {actual}")]
    InvalidAddressLength { expected: usize, actual: usize },

    /// Invalid signature length
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },

    /// Invalid hex string
    #[error("Invalid hex: {0}")]
    InvalidHex(String),

    /// Signing operation failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Invalid private key
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid address format
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid typed data
    #[error("Invalid typed data: {0}")]
    InvalidTypedData(String),

    /// Invalid message format
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// Invalid transaction
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Unsupported operation
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

impl From<bip32::Error> for BlockchainError {
    fn from(err: bip32::Error) -> Self {
        BlockchainError::DerivationFailed(err.to_string())
    }
}

impl From<k256::ecdsa::Error> for BlockchainError {
    fn from(err: k256::ecdsa::Error) -> Self {
        BlockchainError::CryptoError(err.to_string())
    }
}

impl From<hex::FromHexError> for BlockchainError {
    fn from(err: hex::FromHexError) -> Self {
        BlockchainError::InvalidMessage(err.to_string())
    }
}
