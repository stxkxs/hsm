//! ECDSA-specific types for threshold cryptography
//!
//! This module defines the core types used in threshold ECDSA operations,
//! including key shares, signing commitments, signature shares, and pre-signatures.
//!
//! # Supported Curves
//!
//! - **P-256 (secp256r1)**: FIPS 140-3 approved, used in TLS, PIV, etc.
//! - **secp256k1**: Bitcoin/Ethereum compatible (not FIPS approved)
//!
//! # Security
//!
//! All secret material implements `Zeroize` and `ZeroizeOnDrop` to ensure
//! sensitive data is cleared from memory when no longer needed.

use crate::threshold::types::{EcdsaCurve, ParticipantId, ThresholdConfig, ThresholdError};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A participant's ECDSA key share.
///
/// Contains the secret scalar share and associated public information.
/// The secret share is automatically zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaKeyShare {
    /// The participant's identifier (1-indexed).
    #[zeroize(skip)]
    pub participant_id: ParticipantId,

    /// The threshold configuration.
    #[zeroize(skip)]
    pub config: ThresholdConfig,

    /// The secret scalar share (32 bytes).
    pub(crate) secret_share: Vec<u8>,

    /// The public key share (33 bytes compressed point).
    #[zeroize(skip)]
    pub public_share: Vec<u8>,

    /// The group's combined public key (33 bytes compressed point).
    #[zeroize(skip)]
    pub group_public_key: Vec<u8>,

    /// The elliptic curve used.
    #[zeroize(skip)]
    pub curve: EcdsaCurve,
}

impl EcdsaKeyShare {
    /// Create a new ECDSA key share.
    pub fn new(
        participant_id: ParticipantId,
        config: ThresholdConfig,
        secret_share: Vec<u8>,
        public_share: Vec<u8>,
        group_public_key: Vec<u8>,
        curve: EcdsaCurve,
    ) -> Self {
        Self {
            participant_id,
            config,
            secret_share,
            public_share,
            group_public_key,
            curve,
        }
    }

    /// Get the secret share bytes (internal use only).
    pub(crate) fn secret_share_bytes(&self) -> &[u8] {
        &self.secret_share
    }

    /// Check if this key share is for a FIPS-approved curve.
    pub fn is_fips_approved(&self) -> bool {
        self.curve.is_fips_approved()
    }
}

impl fmt::Debug for EcdsaKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaKeyShare")
            .field("participant_id", &self.participant_id)
            .field("config", &self.config)
            .field("secret_share", &"<redacted>")
            .field(
                "public_share",
                &format!("[{} bytes]", self.public_share.len()),
            )
            .field(
                "group_public_key",
                &format!("[{} bytes]", self.group_public_key.len()),
            )
            .field("curve", &self.curve)
            .finish()
    }
}

/// Signing nonce for ECDSA threshold signing.
///
/// Contains the secret nonces (k, gamma) that must never be reused.
/// Automatically zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EcdsaSigningNonce {
    /// The nonce k share (32 bytes).
    pub(crate) k_share: Vec<u8>,

    /// The gamma nonce for MtA (32 bytes).
    pub(crate) gamma_share: Vec<u8>,

    /// The curve this nonce is for.
    #[zeroize(skip)]
    pub(crate) curve: EcdsaCurve,
}

impl EcdsaSigningNonce {
    /// Create a new signing nonce.
    pub(crate) fn new(k_share: Vec<u8>, gamma_share: Vec<u8>, curve: EcdsaCurve) -> Self {
        Self {
            k_share,
            gamma_share,
            curve,
        }
    }
}

impl fmt::Debug for EcdsaSigningNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSigningNonce")
            .field("k_share", &"<redacted>")
            .field("gamma_share", &"<redacted>")
            .field("curve", &self.curve)
            .finish()
    }
}

/// Commitment from a participant during ECDSA signing.
///
/// Contains Pedersen commitments to the nonces (D_i, E_i).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdsaSigningCommitment {
    /// The participant who created this commitment.
    pub participant_id: ParticipantId,

    /// Commitment to k_i * G (33 bytes compressed point).
    pub commitment_d: Vec<u8>,

    /// Commitment to gamma_i * G (33 bytes compressed point).
    pub commitment_e: Vec<u8>,

    /// The curve this commitment is for.
    pub curve: EcdsaCurve,
}

impl EcdsaSigningCommitment {
    /// Create a new signing commitment.
    pub fn new(
        participant_id: ParticipantId,
        commitment_d: Vec<u8>,
        commitment_e: Vec<u8>,
        curve: EcdsaCurve,
    ) -> Self {
        Self {
            participant_id,
            commitment_d,
            commitment_e,
            curve,
        }
    }
}

/// Signature share from a participant in ECDSA threshold signing.
///
/// Contains the s_i value that will be aggregated with other shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdsaSignatureShare {
    /// The participant who created this share.
    pub participant_id: ParticipantId,

    /// The signature share s_i (32 bytes).
    pub share: Vec<u8>,

    /// The curve this share is for.
    pub curve: EcdsaCurve,
}

impl EcdsaSignatureShare {
    /// Create a new signature share.
    pub fn new(participant_id: ParticipantId, share: Vec<u8>, curve: EcdsaCurve) -> Self {
        Self {
            participant_id,
            share,
            curve,
        }
    }
}

/// Pre-signature data for ECDSA threshold signing.
///
/// The pre-signature can be computed before the message is known,
/// enabling faster signing when the message arrives.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaPreSignature {
    /// The participant this pre-signature belongs to.
    #[zeroize(skip)]
    pub(crate) participant_id: ParticipantId,

    /// The R point x-coordinate (r value in signature).
    #[zeroize(skip)]
    pub(crate) r: Vec<u8>,

    /// The k inverse share (for computing s_i).
    pub(crate) k_inv_share: Vec<u8>,

    /// The chi share (x_i * k_inv_i mod n).
    pub(crate) chi_share: Vec<u8>,

    /// The curve this pre-signature is for.
    #[zeroize(skip)]
    pub(crate) curve: EcdsaCurve,
}

impl EcdsaPreSignature {
    /// Create a new pre-signature.
    pub(crate) fn new(
        participant_id: ParticipantId,
        r: Vec<u8>,
        k_inv_share: Vec<u8>,
        chi_share: Vec<u8>,
        curve: EcdsaCurve,
    ) -> Self {
        Self {
            participant_id,
            r,
            k_inv_share,
            chi_share,
            curve,
        }
    }

    /// Get the r value (x-coordinate of R).
    pub fn r(&self) -> &[u8] {
        &self.r
    }
}

impl fmt::Debug for EcdsaPreSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaPreSignature")
            .field("participant_id", &self.participant_id)
            .field("r", &format!("[{} bytes]", self.r.len()))
            .field("k_inv_share", &"<redacted>")
            .field("chi_share", &"<redacted>")
            .field("curve", &self.curve)
            .finish()
    }
}

/// Complete threshold ECDSA signature.
///
/// This is a standard ECDSA signature (r, s) that verifies against
/// the group public key using any standard ECDSA verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdsaThresholdSignature {
    /// The r component (32 bytes).
    pub r: Vec<u8>,

    /// The s component (32 bytes).
    pub s: Vec<u8>,

    /// The curve this signature is for.
    pub curve: EcdsaCurve,
}

impl EcdsaThresholdSignature {
    /// Create a new threshold signature.
    pub fn new(r: Vec<u8>, s: Vec<u8>, curve: EcdsaCurve) -> Self {
        Self { r, s, curve }
    }

    /// Get the signature as raw bytes (r || s, 64 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.r);
        bytes.extend_from_slice(&self.s);
        bytes
    }

    /// Create from raw bytes (expects 64 bytes: r || s).
    pub fn from_bytes(bytes: &[u8], curve: EcdsaCurve) -> Result<Self, ThresholdError> {
        if bytes.len() != 64 {
            return Err(ThresholdError::SerializationError(format!(
                "Invalid signature length: expected 64, got {}",
                bytes.len()
            )));
        }

        Ok(Self {
            r: bytes[0..32].to_vec(),
            s: bytes[32..64].to_vec(),
            curve,
        })
    }
}

/// ECDSA group public key with associated metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdsaGroupPublicKey {
    /// The compressed public key bytes (33 bytes).
    pub bytes: Vec<u8>,

    /// The threshold configuration.
    pub config: ThresholdConfig,

    /// The curve this key is for.
    pub curve: EcdsaCurve,
}

impl EcdsaGroupPublicKey {
    /// Create a new group public key.
    pub fn new(bytes: Vec<u8>, config: ThresholdConfig, curve: EcdsaCurve) -> Self {
        Self {
            bytes,
            config,
            curve,
        }
    }

    /// Get the public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Check if this key is for a FIPS-approved curve.
    pub fn is_fips_approved(&self) -> bool {
        self.curve.is_fips_approved()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_key_share_debug_redacts_secret() {
        let share = EcdsaKeyShare::new(
            ParticipantId(1),
            ThresholdConfig::new(2, 3).unwrap(),
            vec![0x42; 32],
            vec![0x02; 33],
            vec![0x03; 33],
            EcdsaCurve::P256,
        );
        let debug_str = format!("{:?}", share);
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("0x42"));
    }

    #[test]
    fn test_ecdsa_key_share_fips_approval() {
        let p256_share = EcdsaKeyShare::new(
            ParticipantId(1),
            ThresholdConfig::new(2, 3).unwrap(),
            vec![0; 32],
            vec![0; 33],
            vec![0; 33],
            EcdsaCurve::P256,
        );
        assert!(p256_share.is_fips_approved());

        let secp256k1_share = EcdsaKeyShare::new(
            ParticipantId(1),
            ThresholdConfig::new(2, 3).unwrap(),
            vec![0; 32],
            vec![0; 33],
            vec![0; 33],
            EcdsaCurve::Secp256k1,
        );
        assert!(!secp256k1_share.is_fips_approved());
    }

    #[test]
    fn test_ecdsa_signature_roundtrip() {
        let sig = EcdsaThresholdSignature::new(vec![1; 32], vec![2; 32], EcdsaCurve::P256);

        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 64);

        let recovered = EcdsaThresholdSignature::from_bytes(&bytes, EcdsaCurve::P256).unwrap();
        assert_eq!(recovered.r, sig.r);
        assert_eq!(recovered.s, sig.s);
    }

    #[test]
    fn test_ecdsa_signature_invalid_length() {
        let result = EcdsaThresholdSignature::from_bytes(&[0; 63], EcdsaCurve::P256);
        assert!(result.is_err());
    }

    #[test]
    fn test_signing_nonce_debug_redacts() {
        let nonce = EcdsaSigningNonce::new(vec![0x42; 32], vec![0x43; 32], EcdsaCurve::P256);
        let debug_str = format!("{:?}", nonce);
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("0x42"));
        assert!(!debug_str.contains("0x43"));
    }

    #[test]
    fn test_presignature_debug_redacts() {
        let presig = EcdsaPreSignature::new(
            ParticipantId(1),
            vec![0x01; 32],
            vec![0x42; 32],
            vec![0x43; 32],
            EcdsaCurve::P256,
        );
        let debug_str = format!("{:?}", presig);
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("0x42"));
        assert!(!debug_str.contains("0x43"));
    }
}
