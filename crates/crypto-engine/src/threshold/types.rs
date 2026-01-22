//! Shared types for threshold cryptography
//!
//! This module defines the core types used throughout the threshold
//! cryptography implementation, including participant identifiers,
//! configuration, key shares, and signing-related structures.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Identifier for a participant in the threshold scheme.
///
/// Participant IDs must be non-zero and unique within a threshold group.
/// They are used to identify which participant contributed a key share
/// or signature share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub u16);

impl ParticipantId {
    /// Create a new participant ID.
    ///
    /// # Errors
    ///
    /// Returns error if the ID is zero (FROST requires non-zero identifiers).
    pub fn new(id: u16) -> Result<Self, ThresholdError> {
        if id == 0 {
            return Err(ThresholdError::InvalidParticipant(
                "Participant ID must be non-zero".into(),
            ));
        }
        Ok(Self(id))
    }

    /// Get the raw ID value.
    pub fn value(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for ParticipantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Participant({})", self.0)
    }
}

/// Configuration for a threshold scheme.
///
/// Defines the threshold (minimum signers) and total number of participants.
/// For example, a 2-of-3 scheme has threshold=2 and total_participants=3.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThresholdConfig {
    /// Minimum number of participants required to sign (t).
    pub threshold: u16,
    /// Total number of participants (n).
    pub total_participants: u16,
}

impl ThresholdConfig {
    /// Create a new threshold configuration.
    ///
    /// # Arguments
    ///
    /// * `threshold` - Minimum number of signers required (t)
    /// * `total_participants` - Total number of participants (n)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - threshold is 0
    /// - threshold exceeds total_participants
    /// - total_participants exceeds 65535
    pub fn new(threshold: u16, total_participants: u16) -> Result<Self, ThresholdError> {
        if threshold == 0 {
            return Err(ThresholdError::InvalidThreshold(
                "threshold must be > 0".into(),
            ));
        }
        if threshold > total_participants {
            return Err(ThresholdError::InvalidThreshold(
                "threshold cannot exceed total participants".into(),
            ));
        }
        if total_participants < 2 {
            return Err(ThresholdError::InvalidThreshold(
                "total participants must be >= 2".into(),
            ));
        }
        Ok(Self {
            threshold,
            total_participants,
        })
    }

    /// Check if a number of participants meets the threshold.
    pub fn meets_threshold(&self, num_participants: usize) -> bool {
        num_participants >= self.threshold as usize
    }
}

impl fmt::Display for ThresholdConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-of-{}", self.threshold, self.total_participants)
    }
}

/// A participant's secret key share.
///
/// This contains the secret share of the group's signing key. It must be
/// kept confidential by the participant. The share is automatically zeroized
/// when dropped to prevent secret leakage.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyShare {
    /// The participant's identifier.
    #[zeroize(skip)]
    pub participant_id: ParticipantId,
    /// The threshold configuration.
    #[zeroize(skip)]
    pub config: ThresholdConfig,
    /// The secret signing share (serialized FROST SigningShare).
    pub(crate) secret_share: Vec<u8>,
    /// The public verifying share (serialized FROST VerifyingShare).
    #[zeroize(skip)]
    pub public_key_share: Vec<u8>,
}

impl KeyShare {
    /// Create a new key share.
    pub fn new(
        participant_id: ParticipantId,
        config: ThresholdConfig,
        secret_share: Vec<u8>,
        public_key_share: Vec<u8>,
    ) -> Self {
        Self {
            participant_id,
            config,
            secret_share,
            public_key_share,
        }
    }

    /// Get the secret share bytes (internal use only).
    pub(crate) fn secret_share_bytes(&self) -> &[u8] {
        &self.secret_share
    }
}

impl fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyShare")
            .field("participant_id", &self.participant_id)
            .field("config", &self.config)
            .field("secret_share", &"<redacted>")
            .field(
                "public_key_share",
                &format!("[{} bytes]", self.public_key_share.len()),
            )
            .finish()
    }
}

/// The group's combined public key.
///
/// This is the public key that corresponds to the split private key.
/// Signatures produced by the threshold scheme will verify against this key.
/// This key is equivalent to a standard Ed25519 public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPublicKey {
    /// The serialized verifying key bytes.
    pub bytes: Vec<u8>,
    /// The threshold configuration.
    pub config: ThresholdConfig,
    /// Serialized public key package for verification.
    pub(crate) pubkey_package: Vec<u8>,
}

impl GroupPublicKey {
    /// Create a new group public key.
    pub fn new(bytes: Vec<u8>, config: ThresholdConfig, pubkey_package: Vec<u8>) -> Self {
        Self {
            bytes,
            config,
            pubkey_package,
        }
    }

    /// Get the public key bytes (standard Ed25519 format).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Commitment from a participant during signing (Round 1).
///
/// Each participant generates a commitment containing hiding and binding
/// nonce commitments. These are shared with the coordinator/other participants
/// before generating signature shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningCommitment {
    /// The participant who created this commitment.
    pub participant_id: ParticipantId,
    /// Serialized signing commitments (FROST SigningCommitments).
    pub commitment_bytes: Vec<u8>,
}

impl SigningCommitment {
    /// Create a new signing commitment.
    pub fn new(participant_id: ParticipantId, commitment_bytes: Vec<u8>) -> Self {
        Self {
            participant_id,
            commitment_bytes,
        }
    }
}

/// Nonce used during signing (must be kept secret).
///
/// Nonces are generated fresh for each signing session and must never be reused.
/// Reusing nonces allows key extraction attacks. The nonce is automatically
/// zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningNonce {
    /// Serialized signing nonces (FROST SigningNonces).
    pub(crate) nonce_bytes: Vec<u8>,
}

impl SigningNonce {
    /// Create a new signing nonce from serialized bytes.
    pub fn new(nonce_bytes: Vec<u8>) -> Self {
        Self { nonce_bytes }
    }
}

impl fmt::Debug for SigningNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningNonce")
            .field("nonce_bytes", &"<redacted>")
            .finish()
    }
}

/// Signature share from a participant (Round 2).
///
/// After receiving all commitments, each participant generates a signature
/// share. These shares are aggregated by the coordinator to produce the
/// final threshold signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureShare {
    /// The participant who created this share.
    pub participant_id: ParticipantId,
    /// The serialized signature share.
    pub share: Vec<u8>,
}

impl SignatureShare {
    /// Create a new signature share.
    pub fn new(participant_id: ParticipantId, share: Vec<u8>) -> Self {
        Self {
            participant_id,
            share,
        }
    }
}

/// Complete threshold signature.
///
/// This is the final aggregated signature that verifies as a standard
/// Ed25519 signature against the group public key. It is indistinguishable
/// from a regular Ed25519 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignature {
    /// The serialized signature bytes (64 bytes for Ed25519).
    pub bytes: Vec<u8>,
}

impl ThresholdSignature {
    /// Create a new threshold signature.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Threshold cryptography errors.
#[derive(Debug, thiserror::Error)]
pub enum ThresholdError {
    /// Invalid threshold configuration.
    #[error("Invalid threshold configuration: {0}")]
    InvalidThreshold(String),

    /// Not enough participants for the operation.
    #[error("Not enough participants: need {required}, got {provided}")]
    InsufficientParticipants {
        /// Number of participants required.
        required: u16,
        /// Number of participants provided.
        provided: u16,
    },

    /// Invalid participant identifier or data.
    #[error("Invalid participant: {0}")]
    InvalidParticipant(String),

    /// Distributed key generation failed.
    #[error("DKG round {round} failed: {reason}")]
    DkgFailed {
        /// The round that failed.
        round: u8,
        /// The reason for failure.
        reason: String,
    },

    /// Signing operation failed.
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Invalid signature share from a participant.
    #[error("Invalid signature share from {0}")]
    InvalidSignatureShare(ParticipantId),

    /// Signature verification failed.
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Serialization or deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Internal FROST library error.
    #[error("FROST error: {0}")]
    FrostError(String),

    /// Session state error.
    #[error("Session error: {0}")]
    SessionError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_participant_id_valid() {
        let id = ParticipantId::new(1).unwrap();
        assert_eq!(id.value(), 1);
    }

    #[test]
    fn test_participant_id_zero_invalid() {
        let result = ParticipantId::new(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_config_valid() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        assert_eq!(config.threshold, 2);
        assert_eq!(config.total_participants, 3);
        assert!(config.meets_threshold(2));
        assert!(config.meets_threshold(3));
        assert!(!config.meets_threshold(1));
    }

    #[test]
    fn test_threshold_config_zero_threshold() {
        let result = ThresholdConfig::new(0, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_config_threshold_exceeds_total() {
        let result = ThresholdConfig::new(4, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_config_single_participant() {
        let result = ThresholdConfig::new(1, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_config_display() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        assert_eq!(format!("{}", config), "2-of-3");
    }

    #[test]
    fn test_key_share_debug_redacts_secret() {
        let share = KeyShare::new(
            ParticipantId(1),
            ThresholdConfig::new(2, 3).unwrap(),
            vec![0x42; 32],
            vec![0x00; 32],
        );
        let debug_str = format!("{:?}", share);
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("0x42"));
    }
}
