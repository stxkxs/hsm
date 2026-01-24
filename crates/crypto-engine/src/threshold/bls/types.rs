//! BLS-specific types for threshold cryptography
//!
//! This module defines types specific to BLS12-381 threshold signatures,
//! including key shares, signature shares, and related structures.
//!
//! # Security
//!
//! All secret key material is zeroized on drop to prevent memory leakage.
//! The blst crate's SecretKey type must be handled carefully as it doesn't
//! implement Zeroize directly - we store the raw bytes and zeroize those.

use crate::threshold::types::{ParticipantId, ThresholdConfig, ThresholdError};
use blst::min_pk::{PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Domain separation tag for BLS signatures (Ethereum 2.0 compatible)
pub const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// A participant's BLS secret key share.
///
/// This contains the participant's share of the group's signing key.
/// The share must be kept confidential. The secret bytes are automatically
/// zeroized when dropped.
#[derive(Clone)]
pub struct BlsKeyShare {
    /// The participant's identifier.
    pub participant_id: ParticipantId,
    /// The threshold configuration.
    pub config: ThresholdConfig,
    /// The secret key share bytes (32 bytes scalar).
    /// This is zeroized on drop.
    secret_share_bytes: Vec<u8>,
    /// The public key share (48 bytes compressed G1 point).
    pub public_share: Vec<u8>,
    /// The group's combined public key (48 bytes compressed G1 point).
    pub group_public_key: Vec<u8>,
}

impl BlsKeyShare {
    /// Create a new BLS key share.
    pub fn new(
        participant_id: ParticipantId,
        config: ThresholdConfig,
        secret_share_bytes: Vec<u8>,
        public_share: Vec<u8>,
        group_public_key: Vec<u8>,
    ) -> Self {
        Self {
            participant_id,
            config,
            secret_share_bytes,
            public_share,
            group_public_key,
        }
    }

    /// Get the secret key from this share.
    ///
    /// # Errors
    ///
    /// Returns error if the stored bytes are not a valid BLS secret key.
    pub fn secret_key(&self) -> Result<SecretKey, ThresholdError> {
        SecretKey::from_bytes(&self.secret_share_bytes).map_err(|_| ThresholdError::InvalidKeyShare)
    }

    /// Get the public key share.
    ///
    /// # Errors
    ///
    /// Returns error if the stored bytes are not a valid BLS public key.
    pub fn public_key_share(&self) -> Result<PublicKey, ThresholdError> {
        PublicKey::from_bytes(&self.public_share).map_err(|_| ThresholdError::InvalidPublicKey)
    }

    /// Get the raw secret share bytes.
    /// Used internally for key refresh and resharing operations.
    pub fn secret_share_bytes(&self) -> &[u8] {
        &self.secret_share_bytes
    }
}

impl Zeroize for BlsKeyShare {
    fn zeroize(&mut self) {
        self.secret_share_bytes.zeroize();
    }
}

impl Drop for BlsKeyShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for BlsKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlsKeyShare")
            .field("participant_id", &self.participant_id)
            .field("config", &self.config)
            .field("secret_share_bytes", &"<redacted>")
            .field(
                "public_share",
                &format!("[{} bytes]", self.public_share.len()),
            )
            .field(
                "group_public_key",
                &format!("[{} bytes]", self.group_public_key.len()),
            )
            .finish()
    }
}

/// A BLS signature share from a participant.
///
/// Each participant generates a signature share by signing the message
/// with their secret key share. These shares are aggregated to produce
/// the final threshold signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsSignatureShare {
    /// The participant who created this share.
    pub participant_id: ParticipantId,
    /// The signature share (96 bytes compressed G2 point).
    pub share: Vec<u8>,
}

impl BlsSignatureShare {
    /// Create a new BLS signature share.
    pub fn new(participant_id: ParticipantId, share: Vec<u8>) -> Self {
        Self {
            participant_id,
            share,
        }
    }

    /// Get the signature from this share.
    ///
    /// # Errors
    ///
    /// Returns error if the stored bytes are not a valid BLS signature.
    pub fn signature(&self) -> Result<Signature, ThresholdError> {
        Signature::from_bytes(&self.share).map_err(|_| ThresholdError::InvalidSignature)
    }
}

/// BLS group public key.
///
/// This is the combined public key for the threshold group.
/// Signatures produced by the threshold scheme verify against this key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsGroupPublicKey {
    /// The serialized public key bytes (48 bytes compressed G1).
    pub bytes: Vec<u8>,
    /// The threshold configuration.
    pub config: ThresholdConfig,
}

impl BlsGroupPublicKey {
    /// Create a new BLS group public key.
    pub fn new(bytes: Vec<u8>, config: ThresholdConfig) -> Self {
        Self { bytes, config }
    }

    /// Get the public key.
    ///
    /// # Errors
    ///
    /// Returns error if the stored bytes are not a valid BLS public key.
    pub fn public_key(&self) -> Result<PublicKey, ThresholdError> {
        PublicKey::from_bytes(&self.bytes).map_err(|_| ThresholdError::InvalidPublicKey)
    }

    /// Get the public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Complete threshold BLS signature.
///
/// This is the aggregated signature from threshold participants.
/// It can be verified against the group public key using standard
/// BLS verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsThresholdSignature {
    /// The serialized signature bytes (96 bytes compressed G2).
    pub bytes: Vec<u8>,
}

impl BlsThresholdSignature {
    /// Create a new BLS threshold signature.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the signature.
    ///
    /// # Errors
    ///
    /// Returns error if the stored bytes are not a valid BLS signature.
    pub fn signature(&self) -> Result<Signature, ThresholdError> {
        Signature::from_bytes(&self.bytes).map_err(|_| ThresholdError::InvalidSignature)
    }

    /// Get the signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_key_share_debug_redacts_secret() {
        let share = BlsKeyShare::new(
            ParticipantId(1),
            ThresholdConfig::new(2, 3).unwrap(),
            vec![0x42; 32],
            vec![0x00; 48],
            vec![0x00; 48],
        );
        let debug_str = format!("{:?}", share);
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("0x42"));
    }

    #[test]
    fn test_bls_key_share_zeroize() {
        let mut share = BlsKeyShare::new(
            ParticipantId(1),
            ThresholdConfig::new(2, 3).unwrap(),
            vec![0x42; 32],
            vec![0x00; 48],
            vec![0x00; 48],
        );

        // Zeroize and verify
        share.zeroize();
        assert!(share.secret_share_bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_bls_signature_share_creation() {
        let share = BlsSignatureShare::new(ParticipantId(1), vec![0x00; 96]);

        assert_eq!(share.participant_id, ParticipantId(1));
        assert_eq!(share.share.len(), 96);
    }
}
