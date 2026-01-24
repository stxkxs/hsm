//! Shared types for threshold cryptography
//!
//! This module defines the core types used throughout the threshold
//! cryptography implementation, including participant identifiers,
//! configuration, key shares, and signing-related structures.
//!
//! # Supported Schemes
//!
//! - **FROST Ed25519**: Schnorr threshold signatures on Curve25519
//! - **Threshold ECDSA P-256**: FIPS-approved threshold ECDSA
//! - **Threshold ECDSA secp256k1**: Bitcoin/Ethereum compatible (non-FIPS)
//! - **Threshold BLS12-381**: Ethereum 2.0 validator signatures

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Supported threshold cryptography schemes.
///
/// Each scheme has different performance characteristics, security properties,
/// and FIPS compliance status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThresholdScheme {
    /// FROST Ed25519 - Schnorr threshold signatures
    /// - FIPS approved (Ed25519 is in FIPS 186-5)
    /// - 2-round signing protocol
    /// - ~30,000 signs/sec
    FrostEd25519,

    /// Threshold ECDSA on NIST P-256 curve
    /// - FIPS approved (NIST curve)
    /// - 3-round signing protocol (with pre-signing optimization)
    /// - ~4,000 signs/sec
    ThresholdEcdsaP256,

    /// Threshold ECDSA on secp256k1 curve
    /// - NOT FIPS approved (non-NIST curve)
    /// - Bitcoin/Ethereum compatible
    /// - 3-round signing protocol
    ThresholdEcdsaSecp256k1,

    /// Threshold BLS on BLS12-381 curve
    /// - Under NIST evaluation (not yet approved)
    /// - Single-round signing (BLS native aggregation)
    /// - Ethereum 2.0 validator compatible
    /// - ~10,000 signs/sec
    ThresholdBls12381,
}

impl ThresholdScheme {
    /// Check if this scheme is FIPS 140-3 approved.
    pub fn is_fips_approved(&self) -> bool {
        matches!(
            self,
            ThresholdScheme::FrostEd25519 | ThresholdScheme::ThresholdEcdsaP256
        )
    }

    /// Get the signature size in bytes.
    pub fn signature_size(&self) -> usize {
        match self {
            ThresholdScheme::FrostEd25519 => 64,
            ThresholdScheme::ThresholdEcdsaP256 => 64, // DER encoded can be up to 72
            ThresholdScheme::ThresholdEcdsaSecp256k1 => 64, // DER encoded can be up to 72
            ThresholdScheme::ThresholdBls12381 => 96,  // Compressed G2
        }
    }

    /// Get the public key size in bytes.
    pub fn public_key_size(&self) -> usize {
        match self {
            ThresholdScheme::FrostEd25519 => 32,
            ThresholdScheme::ThresholdEcdsaP256 => 33, // Compressed
            ThresholdScheme::ThresholdEcdsaSecp256k1 => 33, // Compressed
            ThresholdScheme::ThresholdBls12381 => 48,  // Compressed G1
        }
    }

    /// Get the number of signing rounds required.
    pub fn signing_rounds(&self) -> u8 {
        match self {
            ThresholdScheme::FrostEd25519 => 2,
            ThresholdScheme::ThresholdEcdsaP256 => 3,
            ThresholdScheme::ThresholdEcdsaSecp256k1 => 3,
            ThresholdScheme::ThresholdBls12381 => 1, // BLS is single-round!
        }
    }
}

impl fmt::Display for ThresholdScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThresholdScheme::FrostEd25519 => write!(f, "FROST-Ed25519"),
            ThresholdScheme::ThresholdEcdsaP256 => write!(f, "Threshold-ECDSA-P256"),
            ThresholdScheme::ThresholdEcdsaSecp256k1 => write!(f, "Threshold-ECDSA-secp256k1"),
            ThresholdScheme::ThresholdBls12381 => write!(f, "Threshold-BLS12-381"),
        }
    }
}

/// ECDSA curve selection for threshold ECDSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EcdsaCurve {
    /// NIST P-256 curve (secp256r1) - FIPS approved
    P256,
    /// secp256k1 curve - Bitcoin/Ethereum (not FIPS approved)
    Secp256k1,
}

impl EcdsaCurve {
    /// Check if this curve is FIPS approved.
    pub fn is_fips_approved(&self) -> bool {
        matches!(self, EcdsaCurve::P256)
    }

    /// Get the scalar field size in bytes.
    pub fn scalar_size(&self) -> usize {
        32 // Both curves have 256-bit scalars
    }

    /// Get the compressed point size in bytes.
    pub fn point_size(&self) -> usize {
        33 // Both curves: 1 byte prefix + 32 bytes x-coordinate
    }
}

impl fmt::Display for EcdsaCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EcdsaCurve::P256 => write!(f, "P-256"),
            EcdsaCurve::Secp256k1 => write!(f, "secp256k1"),
        }
    }
}

/// Unique identifier for a signing session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    /// Create a new random session ID.
    pub fn new() -> Self {
        use rand::Rng;
        let id: [u8; 16] = rand::thread_rng().gen();
        // Convert to hex manually to avoid extra dependency
        let hex_chars: Vec<String> = id.iter().map(|b| format!("{:02x}", b)).collect();
        Self(hex_chars.join(""))
    }

    /// Create a session ID from a string.
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the session ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for SessionId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SessionId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Key share type that can hold shares for different threshold schemes.
#[derive(Clone)]
pub enum KeyShareType {
    /// FROST Ed25519 key share
    FrostEd25519(Vec<u8>),
    /// Threshold ECDSA P-256 key share
    EcdsaP256(Vec<u8>),
    /// Threshold ECDSA secp256k1 key share
    EcdsaSecp256k1(Vec<u8>),
    /// Threshold BLS12-381 key share
    Bls12381(Vec<u8>),
}

impl KeyShareType {
    /// Get the scheme for this key share type.
    pub fn scheme(&self) -> ThresholdScheme {
        match self {
            KeyShareType::FrostEd25519(_) => ThresholdScheme::FrostEd25519,
            KeyShareType::EcdsaP256(_) => ThresholdScheme::ThresholdEcdsaP256,
            KeyShareType::EcdsaSecp256k1(_) => ThresholdScheme::ThresholdEcdsaSecp256k1,
            KeyShareType::Bls12381(_) => ThresholdScheme::ThresholdBls12381,
        }
    }

    /// Get the raw bytes of the key share.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KeyShareType::FrostEd25519(b) => b,
            KeyShareType::EcdsaP256(b) => b,
            KeyShareType::EcdsaSecp256k1(b) => b,
            KeyShareType::Bls12381(b) => b,
        }
    }
}

impl Zeroize for KeyShareType {
    fn zeroize(&mut self) {
        match self {
            KeyShareType::FrostEd25519(b) => b.zeroize(),
            KeyShareType::EcdsaP256(b) => b.zeroize(),
            KeyShareType::EcdsaSecp256k1(b) => b.zeroize(),
            KeyShareType::Bls12381(b) => b.zeroize(),
        }
    }
}

impl Drop for KeyShareType {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for KeyShareType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyShareType::FrostEd25519(_) => {
                write!(f, "KeyShareType::FrostEd25519(<redacted>)")
            }
            KeyShareType::EcdsaP256(_) => write!(f, "KeyShareType::EcdsaP256(<redacted>)"),
            KeyShareType::EcdsaSecp256k1(_) => {
                write!(f, "KeyShareType::EcdsaSecp256k1(<redacted>)")
            }
            KeyShareType::Bls12381(_) => write!(f, "KeyShareType::Bls12381(<redacted>)"),
        }
    }
}

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

    // ===== New error types for extended MPC support =====
    /// Unsupported threshold scheme.
    #[error("Unsupported threshold scheme: {0}")]
    UnsupportedScheme(ThresholdScheme),

    /// DKG round timeout.
    #[error("DKG round {round} timed out after {timeout_ms}ms")]
    DkgRoundTimeout {
        /// The round that timed out.
        round: u8,
        /// Timeout in milliseconds.
        timeout_ms: u64,
    },

    /// Key refresh operation failed.
    #[error("Key refresh failed: {0}")]
    KeyRefreshFailed(String),

    /// Invalid commitment during key refresh.
    #[error("Invalid refresh commitment from participant {0}")]
    KeyRefreshInvalidCommitment(ParticipantId),

    /// Missing commitments during key refresh.
    #[error("Missing refresh commitments")]
    KeyRefreshMissingCommitments,

    /// Invalid share during key refresh.
    #[error("Invalid refresh share from participant {0}")]
    KeyRefreshInvalidShare(ParticipantId),

    /// Resharing operation failed.
    #[error("Resharing failed: {0}")]
    ResharingFailed(String),

    /// Invalid resharing configuration.
    #[error("Invalid resharing config: {0}")]
    ResharingInvalidConfig(String),

    /// Insufficient shares for resharing.
    #[error("Insufficient shares for resharing: need {required}, got {provided}")]
    ResharingInsufficientShares {
        /// Number of shares required.
        required: usize,
        /// Number of shares provided.
        provided: usize,
    },

    /// Invalid share during resharing.
    #[error("Invalid resharing share from participant {0}")]
    ResharingInvalidShare(ParticipantId),

    /// Operation not approved in FIPS mode.
    #[error("Operation not FIPS approved: {0}")]
    FipsNotApproved(String),

    /// Session expired.
    #[error("Session {0} has expired")]
    SessionExpired(SessionId),

    /// Session not found.
    #[error("Session {0} not found")]
    SessionNotFound(SessionId),

    /// Invalid commitment.
    #[error("Invalid commitment from participant {0}")]
    InvalidCommitment(ParticipantId),

    /// Missing commitment from participant.
    #[error("Missing commitment from participant {0}")]
    MissingCommitment(ParticipantId),

    /// Invalid key share.
    #[error("Invalid key share")]
    InvalidKeyShare,

    /// Invalid public key.
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid signature.
    #[error("Invalid signature")]
    InvalidSignature,

    /// Invalid DKG state for operation.
    #[error("Invalid DKG state for this operation")]
    DkgInvalidState,

    /// Missing DKG commitments.
    #[error("Missing DKG commitments from participant {0}")]
    DkgMissingCommitments(ParticipantId),

    /// Invalid share during DKG.
    #[error("Invalid DKG share from participant {0}")]
    DkgInvalidShare(ParticipantId),

    /// Cryptographic operation failed.
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// Pre-signature generation failed.
    #[error("Pre-signature generation failed: {0}")]
    PreSignatureFailed(String),

    /// Aggregation failed.
    #[error("Signature aggregation failed: {0}")]
    AggregationFailed(String),
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
