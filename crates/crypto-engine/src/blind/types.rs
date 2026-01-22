//! Types for blind signature operations.
//!
//! This module provides the core types used by blind signature schemes,
//! including blinded messages, unblinding factors, and error types.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A blinded message ready for signing.
///
/// The blinded message hides the actual content from the signer while
/// still allowing them to produce a valid signature on the underlying message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedMessage {
    /// The blinded message bytes.
    pub bytes: Vec<u8>,
}

/// Factor used to unblind the signature.
///
/// This must be kept secret by the requester and is used to convert
/// the blind signature into a valid signature on the original message.
///
/// # Security
///
/// The unblinding factor is automatically zeroized on drop to prevent
/// sensitive data from remaining in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnblindingFactor {
    pub(crate) bytes: Vec<u8>,
}

impl UnblindingFactor {
    /// Creates a new unblinding factor from bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A blind signature (before unblinding).
///
/// This signature is produced by the signer on a blinded message.
/// It must be unblinded by the requester to obtain a valid signature
/// on the original message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSignature {
    /// The blind signature bytes.
    pub bytes: Vec<u8>,
}

/// Metadata visible to signer in partially blind signatures.
///
/// In partially blind signature schemes, the signer can see and verify
/// certain metadata (like expiration dates or credential types) while
/// the actual message content remains hidden.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindMetadata {
    /// Visible info (e.g., expiration date, issuer, credential type).
    pub info: Vec<u8>,
}

impl BlindMetadata {
    /// Creates new blind metadata from bytes.
    pub fn new(info: Vec<u8>) -> Self {
        Self { info }
    }

    /// Creates blind metadata from a string.
    pub fn from_string(s: &str) -> Self {
        Self {
            info: s.as_bytes().to_vec(),
        }
    }
}

/// Errors specific to blind signature operations.
#[derive(Debug, thiserror::Error)]
pub enum BlindError {
    /// Message is too long for the key size.
    #[error("Message too long for key size")]
    MessageTooLong,

    /// The blinding factor is invalid (not coprime with modulus).
    #[error("Invalid blinding factor")]
    InvalidBlindingFactor,

    /// Blinding operation failed.
    #[error("Blinding failed: {0}")]
    BlindingFailed(String),

    /// Unblinding operation failed.
    #[error("Unblinding failed: {0}")]
    UnblindingFailed(String),

    /// The signature is invalid.
    #[error("Invalid signature")]
    InvalidSignature,

    /// Key error (invalid format, size, etc.).
    #[error("Key error: {0}")]
    KeyError(String),

    /// Metadata validation failed.
    #[error("Metadata validation failed: {0}")]
    MetadataValidationFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blinded_message_serialize() {
        let msg = BlindedMessage {
            bytes: vec![1, 2, 3, 4],
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: BlindedMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg.bytes, decoded.bytes);
    }

    #[test]
    fn test_blind_metadata_from_string() {
        let metadata = BlindMetadata::from_string("expires:2025-12-31");
        assert_eq!(metadata.info, b"expires:2025-12-31");
    }

    #[test]
    fn test_unblinding_factor_zeroize() {
        let factor = UnblindingFactor::new(vec![0x42; 32]);
        assert_eq!(factor.as_bytes().len(), 32);
        // Zeroization happens on drop
    }
}
