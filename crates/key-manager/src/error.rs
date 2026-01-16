use crate::key::{KeyId, KeyType};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Key not found: {0}")]
    KeyNotFound(KeyId),

    #[error("Key already exists: {0}")]
    KeyAlreadyExists(KeyId),

    #[error("Namespace not found: {0}")]
    NamespaceNotFound(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Key is not in a usable state: {0}")]
    KeyNotUsable(KeyId),

    #[error("Key has reached maximum operations: {0}")]
    MaxOperationsReached(KeyId),

    #[error("Unsupported key type: {0:?}")]
    UnsupportedKeyType(KeyType),

    #[error("Invalid key data: {0}")]
    InvalidKeyData(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Namespace violation: expected {expected}, got {actual}")]
    NamespaceViolation { expected: String, actual: String },

    #[error("Crypto engine error: {0}")]
    CryptoEngine(#[from] hsm_crypto_engine::CryptoError),
}

pub type Result<T> = std::result::Result<T, Error>;
