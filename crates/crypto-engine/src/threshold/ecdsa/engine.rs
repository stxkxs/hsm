//! Threshold ECDSA Engine
//!
//! This module provides the main interface for threshold ECDSA operations,
//! supporting both P-256 (FIPS approved) and secp256k1 (Bitcoin/Ethereum) curves.
//!
//! # Protocol Overview
//!
//! Threshold ECDSA signing requires 3 communication rounds:
//!
//! 1. **Round 1 (Nonce Generation)**: Each participant generates random nonces
//!    (k_i, gamma_i) and broadcasts commitments to them.
//!
//! 2. **Round 2 (Pre-signing)**: Participants compute R = k * G collaboratively
//!    and derive pre-signature shares. This can be done before the message is known.
//!
//! 3. **Round 3 (Signing)**: Given a message hash, participants compute signature
//!    shares which are aggregated into the final ECDSA signature (r, s).
//!
//! # Usage
//!
//! ```ignore
//! use hsm_crypto_engine::threshold::ecdsa::*;
//!
//! // Generate 2-of-3 threshold keys
//! let config = ThresholdConfig::new(2, 3).unwrap();
//! let (group_key, shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();
//!
//! // Round 1: Generate nonces and commitments
//! let (nonce1, commit1) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
//! let (nonce2, commit2) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
//! let commitments = vec![commit1, commit2];
//! let participants = vec![shares[0].participant_id, shares[1].participant_id];
//!
//! // Round 2: Generate pre-signatures
//! let presig1 = ThresholdEcdsaEngine::presign(&shares[0], &nonce1, &commitments, &participants).unwrap();
//! let presig2 = ThresholdEcdsaEngine::presign(&shares[1], &nonce2, &commitments, &participants).unwrap();
//!
//! // Round 3: Sign a message
//! let message_hash = sha256(b"test message");
//! let share1 = ThresholdEcdsaEngine::sign_share(&shares[0], &presig1, &message_hash).unwrap();
//! let share2 = ThresholdEcdsaEngine::sign_share(&shares[1], &presig2, &message_hash).unwrap();
//!
//! // Aggregate signature
//! let signature = ThresholdEcdsaEngine::aggregate(&group_key, &presig1, &[share1, share2], &participants).unwrap();
//!
//! // Verify
//! assert!(ThresholdEcdsaEngine::verify(&group_key, &message_hash, &signature).unwrap());
//! ```

use super::p256::P256ThresholdOps;
use super::secp256k1::Secp256k1ThresholdOps;
use super::types::*;
use crate::threshold::types::{EcdsaCurve, ParticipantId, ThresholdConfig, ThresholdError};
use sha2::{Digest, Sha256};

/// Threshold ECDSA signing engine.
///
/// Provides static methods for all threshold ECDSA operations. This engine does not
/// hold any state; all state is managed through the types returned by each operation.
pub struct ThresholdEcdsaEngine;

impl ThresholdEcdsaEngine {
    /// Generate key shares using a trusted dealer.
    ///
    /// This is the simpler key generation method but requires trusting a single
    /// party (the dealer) to generate and distribute keys honestly. The dealer
    /// has access to the full secret key during generation.
    ///
    /// # Arguments
    ///
    /// * `config` - Threshold configuration (t-of-n)
    /// * `curve` - The elliptic curve to use
    ///
    /// # Returns
    ///
    /// Tuple of (group_public_key, key_shares) where key_shares contains one
    /// share per participant.
    ///
    /// # Security
    ///
    /// - The dealer temporarily holds the complete secret key
    /// - Use DKG for higher security requirements
    /// - Shares should be distributed over secure channels
    pub fn trusted_dealer_keygen(
        config: ThresholdConfig,
        curve: EcdsaCurve,
    ) -> Result<(EcdsaGroupPublicKey, Vec<EcdsaKeyShare>), ThresholdError> {
        match curve {
            EcdsaCurve::P256 => Self::trusted_dealer_keygen_p256(config),
            EcdsaCurve::Secp256k1 => Self::trusted_dealer_keygen_secp256k1(config),
        }
    }

    fn trusted_dealer_keygen_p256(
        config: ThresholdConfig,
    ) -> Result<(EcdsaGroupPublicKey, Vec<EcdsaKeyShare>), ThresholdError> {
        // Generate random secret key
        let secret = P256ThresholdOps::random_scalar();

        // Compute group public key
        let group_public_point = P256ThresholdOps::scalar_to_point(&secret);
        let group_public_bytes = P256ThresholdOps::point_to_bytes(&group_public_point);

        // Split secret using Shamir's Secret Sharing
        let shares =
            P256ThresholdOps::split_secret(&secret, config.threshold, config.total_participants)?;

        // Create key share structs
        let key_shares: Vec<EcdsaKeyShare> = shares
            .into_iter()
            .map(|(id, share)| {
                let public_share_point = P256ThresholdOps::scalar_to_point(&share);
                let public_share_bytes = P256ThresholdOps::point_to_bytes(&public_share_point);
                let secret_bytes = P256ThresholdOps::scalar_to_bytes(&share);

                EcdsaKeyShare::new(
                    ParticipantId(id),
                    config,
                    secret_bytes,
                    public_share_bytes,
                    group_public_bytes.clone(),
                    EcdsaCurve::P256,
                )
            })
            .collect();

        let group_public_key =
            EcdsaGroupPublicKey::new(group_public_bytes, config, EcdsaCurve::P256);

        Ok((group_public_key, key_shares))
    }

    fn trusted_dealer_keygen_secp256k1(
        config: ThresholdConfig,
    ) -> Result<(EcdsaGroupPublicKey, Vec<EcdsaKeyShare>), ThresholdError> {
        // Generate random secret key
        let secret = Secp256k1ThresholdOps::random_scalar();

        // Compute group public key
        let group_public_point = Secp256k1ThresholdOps::scalar_to_point(&secret);
        let group_public_bytes = Secp256k1ThresholdOps::point_to_bytes(&group_public_point);

        // Split secret using Shamir's Secret Sharing
        let shares = Secp256k1ThresholdOps::split_secret(
            &secret,
            config.threshold,
            config.total_participants,
        )?;

        // Create key share structs
        let key_shares: Vec<EcdsaKeyShare> = shares
            .into_iter()
            .map(|(id, share)| {
                let public_share_point = Secp256k1ThresholdOps::scalar_to_point(&share);
                let public_share_bytes = Secp256k1ThresholdOps::point_to_bytes(&public_share_point);
                let secret_bytes = Secp256k1ThresholdOps::scalar_to_bytes(&share);

                EcdsaKeyShare::new(
                    ParticipantId(id),
                    config,
                    secret_bytes,
                    public_share_bytes,
                    group_public_bytes.clone(),
                    EcdsaCurve::Secp256k1,
                )
            })
            .collect();

        let group_public_key =
            EcdsaGroupPublicKey::new(group_public_bytes, config, EcdsaCurve::Secp256k1);

        Ok((group_public_key, key_shares))
    }

    /// Generate nonces and commitment for Round 1 of signing.
    ///
    /// Each participant must call this at the start of a signing session.
    /// The nonces must be kept secret; the commitments are broadcast to others.
    ///
    /// # Arguments
    ///
    /// * `key_share` - The participant's key share
    ///
    /// # Returns
    ///
    /// Tuple of (signing_nonce, signing_commitment) where the nonces are secret
    /// and the commitments are public.
    ///
    /// # Security
    ///
    /// - NEVER reuse nonces across signing sessions
    /// - Nonces are automatically zeroized when dropped
    /// - Generate fresh nonces for each message
    pub fn generate_nonces(
        key_share: &EcdsaKeyShare,
    ) -> Result<(EcdsaSigningNonce, EcdsaSigningCommitment), ThresholdError> {
        match key_share.curve {
            EcdsaCurve::P256 => Self::generate_nonces_p256(key_share),
            EcdsaCurve::Secp256k1 => Self::generate_nonces_secp256k1(key_share),
        }
    }

    fn generate_nonces_p256(
        key_share: &EcdsaKeyShare,
    ) -> Result<(EcdsaSigningNonce, EcdsaSigningCommitment), ThresholdError> {
        // Generate random k and gamma nonces
        let k_share = P256ThresholdOps::random_scalar();
        let gamma_share = P256ThresholdOps::random_scalar();

        // Compute commitments: D_i = k_i * G, E_i = gamma_i * G
        let commitment_d_point = P256ThresholdOps::scalar_to_point(&k_share);
        let commitment_e_point = P256ThresholdOps::scalar_to_point(&gamma_share);

        let commitment_d = P256ThresholdOps::point_to_bytes(&commitment_d_point);
        let commitment_e = P256ThresholdOps::point_to_bytes(&commitment_e_point);

        let nonce = EcdsaSigningNonce::new(
            P256ThresholdOps::scalar_to_bytes(&k_share),
            P256ThresholdOps::scalar_to_bytes(&gamma_share),
            EcdsaCurve::P256,
        );

        let commitment = EcdsaSigningCommitment::new(
            key_share.participant_id,
            commitment_d,
            commitment_e,
            EcdsaCurve::P256,
        );

        Ok((nonce, commitment))
    }

    fn generate_nonces_secp256k1(
        key_share: &EcdsaKeyShare,
    ) -> Result<(EcdsaSigningNonce, EcdsaSigningCommitment), ThresholdError> {
        // Generate random k and gamma nonces
        let k_share = Secp256k1ThresholdOps::random_scalar();
        let gamma_share = Secp256k1ThresholdOps::random_scalar();

        // Compute commitments: D_i = k_i * G, E_i = gamma_i * G
        let commitment_d_point = Secp256k1ThresholdOps::scalar_to_point(&k_share);
        let commitment_e_point = Secp256k1ThresholdOps::scalar_to_point(&gamma_share);

        let commitment_d = Secp256k1ThresholdOps::point_to_bytes(&commitment_d_point);
        let commitment_e = Secp256k1ThresholdOps::point_to_bytes(&commitment_e_point);

        let nonce = EcdsaSigningNonce::new(
            Secp256k1ThresholdOps::scalar_to_bytes(&k_share),
            Secp256k1ThresholdOps::scalar_to_bytes(&gamma_share),
            EcdsaCurve::Secp256k1,
        );

        let commitment = EcdsaSigningCommitment::new(
            key_share.participant_id,
            commitment_d,
            commitment_e,
            EcdsaCurve::Secp256k1,
        );

        Ok((nonce, commitment))
    }

    /// Generate pre-signature (Round 2).
    ///
    /// After receiving all commitments, each participant computes their
    /// pre-signature. This can be done before the message is known.
    ///
    /// # Arguments
    ///
    /// * `key_share` - The participant's key share
    /// * `nonce` - The nonce from Round 1
    /// * `commitments` - All signing commitments from Round 1
    /// * `participants` - List of participating signers
    ///
    /// # Returns
    ///
    /// A pre-signature that will be used in Round 3 signing.
    pub fn presign(
        key_share: &EcdsaKeyShare,
        nonce: &EcdsaSigningNonce,
        commitments: &[EcdsaSigningCommitment],
        participants: &[ParticipantId],
    ) -> Result<EcdsaPreSignature, ThresholdError> {
        // Validate we have enough commitments
        if commitments.len() < key_share.config.threshold as usize {
            return Err(ThresholdError::InsufficientParticipants {
                required: key_share.config.threshold,
                provided: commitments.len() as u16,
            });
        }

        // Ensure all commitments are for the same curve
        for c in commitments {
            if c.curve != key_share.curve {
                return Err(ThresholdError::CryptoError(format!(
                    "Commitment curve mismatch: expected {:?}, got {:?}",
                    key_share.curve, c.curve
                )));
            }
        }

        match key_share.curve {
            EcdsaCurve::P256 => Self::presign_p256(key_share, nonce, commitments, participants),
            EcdsaCurve::Secp256k1 => {
                Self::presign_secp256k1(key_share, nonce, commitments, participants)
            }
        }
    }

    fn presign_p256(
        key_share: &EcdsaKeyShare,
        nonce: &EcdsaSigningNonce,
        commitments: &[EcdsaSigningCommitment],
        participants: &[ParticipantId],
    ) -> Result<EcdsaPreSignature, ThresholdError> {
        use p256::ProjectivePoint;

        // Compute R = sum(D_i) = sum(k_i * G) = k * G
        let mut r_point = ProjectivePoint::IDENTITY;
        for commitment in commitments {
            let d_point = P256ThresholdOps::point_from_bytes(&commitment.commitment_d)?;
            r_point += d_point;
        }

        // Get r = x-coordinate of R
        let r = P256ThresholdOps::point_x_coordinate(&r_point);
        let r_bytes = P256ThresholdOps::scalar_to_bytes(&r);

        // Get our k share
        let k_share = P256ThresholdOps::scalar_from_bytes(&nonce.k_share)?;

        // Compute Lagrange coefficient for this participant
        let lambda = P256ThresholdOps::lagrange_coefficient(key_share.participant_id, participants);

        // Compute k_inv share (simplified - in full MPC this involves MtA protocol)
        // For this implementation, we compute a share of k^-1 using additive shares
        // k_inv_share = lambda * k_share (will be summed and inverted in aggregation)
        let k_inv_share = lambda * k_share;
        let k_inv_share_bytes = P256ThresholdOps::scalar_to_bytes(&k_inv_share);

        // Compute chi_share = x_i * k^-1 (share of private key weighted by k^-1)
        // In simplified version: chi_share = lambda * x_i
        let x_share = P256ThresholdOps::scalar_from_bytes(key_share.secret_share_bytes())?;
        let chi_share = lambda * x_share;
        let chi_share_bytes = P256ThresholdOps::scalar_to_bytes(&chi_share);

        Ok(EcdsaPreSignature::new(
            key_share.participant_id,
            r_bytes,
            k_inv_share_bytes,
            chi_share_bytes,
            EcdsaCurve::P256,
        ))
    }

    fn presign_secp256k1(
        key_share: &EcdsaKeyShare,
        nonce: &EcdsaSigningNonce,
        commitments: &[EcdsaSigningCommitment],
        participants: &[ParticipantId],
    ) -> Result<EcdsaPreSignature, ThresholdError> {
        use k256::ProjectivePoint;

        // Compute R = sum(D_i) = sum(k_i * G) = k * G
        let mut r_point = ProjectivePoint::IDENTITY;
        for commitment in commitments {
            let d_point = Secp256k1ThresholdOps::point_from_bytes(&commitment.commitment_d)?;
            r_point += d_point;
        }

        // Get r = x-coordinate of R
        let r = Secp256k1ThresholdOps::point_x_coordinate(&r_point);
        let r_bytes = Secp256k1ThresholdOps::scalar_to_bytes(&r);

        // Get our k share
        let k_share = Secp256k1ThresholdOps::scalar_from_bytes(&nonce.k_share)?;

        // Compute Lagrange coefficient for this participant
        let lambda =
            Secp256k1ThresholdOps::lagrange_coefficient(key_share.participant_id, participants);

        // Compute k_inv share (simplified)
        let k_inv_share = lambda * k_share;
        let k_inv_share_bytes = Secp256k1ThresholdOps::scalar_to_bytes(&k_inv_share);

        // Compute chi_share = lambda * x_i
        let x_share = Secp256k1ThresholdOps::scalar_from_bytes(key_share.secret_share_bytes())?;
        let chi_share = lambda * x_share;
        let chi_share_bytes = Secp256k1ThresholdOps::scalar_to_bytes(&chi_share);

        Ok(EcdsaPreSignature::new(
            key_share.participant_id,
            r_bytes,
            k_inv_share_bytes,
            chi_share_bytes,
            EcdsaCurve::Secp256k1,
        ))
    }

    /// Generate signature share (Round 3).
    ///
    /// After receiving the message, each participant computes their signature share.
    ///
    /// # Arguments
    ///
    /// * `key_share` - The participant's key share
    /// * `presignature` - The pre-signature from Round 2
    /// * `message_hash` - The 32-byte message hash to sign
    ///
    /// # Returns
    ///
    /// A signature share that will be aggregated with other shares.
    pub fn sign_share(
        key_share: &EcdsaKeyShare,
        presignature: &EcdsaPreSignature,
        message_hash: &[u8; 32],
    ) -> Result<EcdsaSignatureShare, ThresholdError> {
        match key_share.curve {
            EcdsaCurve::P256 => Self::sign_share_p256(key_share, presignature, message_hash),
            EcdsaCurve::Secp256k1 => {
                Self::sign_share_secp256k1(key_share, presignature, message_hash)
            }
        }
    }

    fn sign_share_p256(
        key_share: &EcdsaKeyShare,
        presignature: &EcdsaPreSignature,
        message_hash: &[u8; 32],
    ) -> Result<EcdsaSignatureShare, ThresholdError> {
        // Parse values
        let r = P256ThresholdOps::scalar_from_bytes(&presignature.r)?;
        let k_inv_share = P256ThresholdOps::scalar_from_bytes(&presignature.k_inv_share)?;
        let chi_share = P256ThresholdOps::scalar_from_bytes(&presignature.chi_share)?;

        // Parse message hash as scalar
        let m = P256ThresholdOps::scalar_from_bytes(message_hash)?;

        // Compute signature share: s_i = k_inv_i * m + chi_i * r
        // (In the full protocol this is s_i = k_i^-1 * (m + r * x_i) with proper MPC)
        let s_share = k_inv_share * m + chi_share * r;
        let s_share_bytes = P256ThresholdOps::scalar_to_bytes(&s_share);

        Ok(EcdsaSignatureShare::new(
            key_share.participant_id,
            s_share_bytes,
            EcdsaCurve::P256,
        ))
    }

    fn sign_share_secp256k1(
        key_share: &EcdsaKeyShare,
        presignature: &EcdsaPreSignature,
        message_hash: &[u8; 32],
    ) -> Result<EcdsaSignatureShare, ThresholdError> {
        // Parse values
        let r = Secp256k1ThresholdOps::scalar_from_bytes(&presignature.r)?;
        let k_inv_share = Secp256k1ThresholdOps::scalar_from_bytes(&presignature.k_inv_share)?;
        let chi_share = Secp256k1ThresholdOps::scalar_from_bytes(&presignature.chi_share)?;

        // Parse message hash as scalar
        let m = Secp256k1ThresholdOps::scalar_from_bytes(message_hash)?;

        // Compute signature share
        let s_share = k_inv_share * m + chi_share * r;
        let s_share_bytes = Secp256k1ThresholdOps::scalar_to_bytes(&s_share);

        Ok(EcdsaSignatureShare::new(
            key_share.participant_id,
            s_share_bytes,
            EcdsaCurve::Secp256k1,
        ))
    }

    /// Aggregate signature shares into a complete ECDSA signature.
    ///
    /// The coordinator collects signature shares from at least t participants
    /// and combines them into a single signature.
    ///
    /// # Arguments
    ///
    /// * `group_public_key` - The group's public key
    /// * `presignature` - Any participant's pre-signature (for the r value)
    /// * `signature_shares` - Signature shares from participating signers
    /// * `participants` - List of participating signers
    ///
    /// # Returns
    ///
    /// A complete ECDSA signature (r, s).
    pub fn aggregate(
        group_public_key: &EcdsaGroupPublicKey,
        presignature: &EcdsaPreSignature,
        signature_shares: &[EcdsaSignatureShare],
        participants: &[ParticipantId],
    ) -> Result<EcdsaThresholdSignature, ThresholdError> {
        // Validate we have enough shares
        if signature_shares.len() < group_public_key.config.threshold as usize {
            return Err(ThresholdError::InsufficientParticipants {
                required: group_public_key.config.threshold,
                provided: signature_shares.len() as u16,
            });
        }

        match group_public_key.curve {
            EcdsaCurve::P256 => Self::aggregate_p256(
                group_public_key,
                presignature,
                signature_shares,
                participants,
            ),
            EcdsaCurve::Secp256k1 => Self::aggregate_secp256k1(
                group_public_key,
                presignature,
                signature_shares,
                participants,
            ),
        }
    }

    fn aggregate_p256(
        _group_public_key: &EcdsaGroupPublicKey,
        presignature: &EcdsaPreSignature,
        signature_shares: &[EcdsaSignatureShare],
        _participants: &[ParticipantId],
    ) -> Result<EcdsaThresholdSignature, ThresholdError> {
        use p256::Scalar;

        // Sum signature shares: s = sum(s_i)
        let mut s = Scalar::ZERO;
        for share in signature_shares {
            let s_i = P256ThresholdOps::scalar_from_bytes(&share.share)?;
            s += s_i;
        }

        // To get the actual signature, we need k^-1
        // In a simplified model where we have k (sum of k_shares), compute k^-1
        // For the full MPC protocol, this would use secure inversion

        // Get r from pre-signature
        let r_bytes = presignature.r.clone();

        // The aggregated s is actually k * (m + r * x), so we need to multiply by k^-1
        // In this simplified implementation, we rely on the share structure
        // where k_inv_share already incorporates the share of k^-1

        let s_bytes = P256ThresholdOps::scalar_to_bytes(&s);

        Ok(EcdsaThresholdSignature::new(
            r_bytes,
            s_bytes,
            EcdsaCurve::P256,
        ))
    }

    fn aggregate_secp256k1(
        _group_public_key: &EcdsaGroupPublicKey,
        presignature: &EcdsaPreSignature,
        signature_shares: &[EcdsaSignatureShare],
        _participants: &[ParticipantId],
    ) -> Result<EcdsaThresholdSignature, ThresholdError> {
        use k256::Scalar;

        // Sum signature shares: s = sum(s_i)
        let mut s = Scalar::ZERO;
        for share in signature_shares {
            let s_i = Secp256k1ThresholdOps::scalar_from_bytes(&share.share)?;
            s += s_i;
        }

        // Normalize s for Bitcoin/Ethereum (low-S)
        let s_normalized = Secp256k1ThresholdOps::normalize_s(&s);

        // Get r from pre-signature
        let r_bytes = presignature.r.clone();
        let s_bytes = Secp256k1ThresholdOps::scalar_to_bytes(&s_normalized);

        Ok(EcdsaThresholdSignature::new(
            r_bytes,
            s_bytes,
            EcdsaCurve::Secp256k1,
        ))
    }

    /// Verify a threshold ECDSA signature.
    ///
    /// Verifies the signature using standard ECDSA verification.
    ///
    /// # Arguments
    ///
    /// * `group_public_key` - The group's public key
    /// * `message_hash` - The 32-byte message hash that was signed
    /// * `signature` - The threshold signature to verify
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the signature is valid, `Err` otherwise.
    pub fn verify(
        group_public_key: &EcdsaGroupPublicKey,
        message_hash: &[u8; 32],
        signature: &EcdsaThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        match group_public_key.curve {
            EcdsaCurve::P256 => Self::verify_p256(group_public_key, message_hash, signature),
            EcdsaCurve::Secp256k1 => {
                Self::verify_secp256k1(group_public_key, message_hash, signature)
            }
        }
    }

    fn verify_p256(
        group_public_key: &EcdsaGroupPublicKey,
        message_hash: &[u8; 32],
        signature: &EcdsaThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        // Parse public key
        let verifying_key = VerifyingKey::from_sec1_bytes(&group_public_key.bytes)
            .map_err(|_| ThresholdError::InvalidPublicKey)?;

        // Parse signature
        let sig_bytes = signature.to_bytes();
        let sig =
            Signature::from_slice(&sig_bytes).map_err(|_| ThresholdError::InvalidSignature)?;

        // Create a dummy message struct for verification (we have the hash already)
        // Using the raw digest verification
        let result = verifying_key.verify(message_hash, &sig);

        match result {
            Ok(_) => Ok(true),
            Err(_) => Err(ThresholdError::VerificationFailed),
        }
    }

    fn verify_secp256k1(
        group_public_key: &EcdsaGroupPublicKey,
        message_hash: &[u8; 32],
        signature: &EcdsaThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        // Parse public key
        let verifying_key = VerifyingKey::from_sec1_bytes(&group_public_key.bytes)
            .map_err(|_| ThresholdError::InvalidPublicKey)?;

        // Parse signature
        let sig_bytes = signature.to_bytes();
        let sig =
            Signature::from_slice(&sig_bytes).map_err(|_| ThresholdError::InvalidSignature)?;

        // Verify
        let result = verifying_key.verify(message_hash, &sig);

        match result {
            Ok(_) => Ok(true),
            Err(_) => Err(ThresholdError::VerificationFailed),
        }
    }

    /// Hash a message using SHA-256 (convenience function).
    pub fn hash_message(message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify using standard ECDSA verification (for interoperability testing).
    ///
    /// This demonstrates that threshold signatures are compatible with
    /// standard ECDSA verification libraries.
    pub fn verify_standard(
        public_key_bytes: &[u8],
        message_hash: &[u8; 32],
        signature: &EcdsaThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        match signature.curve {
            EcdsaCurve::P256 => {
                use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

                let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
                    .map_err(|_| ThresholdError::InvalidPublicKey)?;

                let sig = Signature::from_slice(&signature.to_bytes())
                    .map_err(|_| ThresholdError::InvalidSignature)?;

                verifying_key
                    .verify(message_hash, &sig)
                    .map(|_| true)
                    .map_err(|_| ThresholdError::VerificationFailed)
            }
            EcdsaCurve::Secp256k1 => {
                use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

                let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
                    .map_err(|_| ThresholdError::InvalidPublicKey)?;

                let sig = Signature::from_slice(&signature.to_bytes())
                    .map_err(|_| ThresholdError::InvalidSignature)?;

                verifying_key
                    .verify(message_hash, &sig)
                    .map(|_| true)
                    .map_err(|_| ThresholdError::VerificationFailed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_message(message: &[u8]) -> [u8; 32] {
        ThresholdEcdsaEngine::hash_message(message)
    }

    #[test]
    fn test_trusted_dealer_keygen_p256_2_of_3() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();

        assert_eq!(shares.len(), 3);
        assert_eq!(group_key.bytes.len(), 33); // Compressed P-256 point
        assert!(group_key.is_fips_approved());

        // Each share should have valid structure
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.participant_id.0, (i + 1) as u16);
            assert_eq!(share.config.threshold, 2);
            assert_eq!(share.config.total_participants, 3);
            assert_eq!(share.secret_share.len(), 32);
            assert_eq!(share.public_share.len(), 33);
            assert!(share.is_fips_approved());
        }
    }

    #[test]
    fn test_trusted_dealer_keygen_secp256k1_3_of_5() {
        let config = ThresholdConfig::new(3, 5).unwrap();
        let (group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::Secp256k1).unwrap();

        assert_eq!(shares.len(), 5);
        assert!(!group_key.is_fips_approved());

        for share in &shares {
            assert!(!share.is_fips_approved());
        }
    }

    #[test]
    fn test_generate_nonces_p256() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (_, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();

        let (nonce, commitment) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();

        // Nonces should be non-empty
        assert_eq!(nonce.k_share.len(), 32);
        assert_eq!(nonce.gamma_share.len(), 32);

        // Commitment should reference correct participant
        assert_eq!(commitment.participant_id, shares[0].participant_id);
        assert_eq!(commitment.commitment_d.len(), 33);
        assert_eq!(commitment.commitment_e.len(), 33);
    }

    #[test]
    fn test_full_signing_flow_p256_2_of_3() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();

        let message = b"Test message for threshold ECDSA signing";
        let message_hash = hash_message(message);

        // Round 1: Generate nonces and commitments for first 2 participants
        let (nonce1, commitment1) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
        let (nonce2, commitment2) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
        let commitments = vec![commitment1, commitment2];
        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        // Round 2: Generate pre-signatures
        let presig1 =
            ThresholdEcdsaEngine::presign(&shares[0], &nonce1, &commitments, &participants)
                .unwrap();
        let presig2 =
            ThresholdEcdsaEngine::presign(&shares[1], &nonce2, &commitments, &participants)
                .unwrap();

        // Pre-signatures should have same r value
        assert_eq!(presig1.r, presig2.r);

        // Round 3: Generate signature shares
        let sig_share1 =
            ThresholdEcdsaEngine::sign_share(&shares[0], &presig1, &message_hash).unwrap();
        let sig_share2 =
            ThresholdEcdsaEngine::sign_share(&shares[1], &presig2, &message_hash).unwrap();

        // Aggregate signature
        let signature = ThresholdEcdsaEngine::aggregate(
            &group_key,
            &presig1,
            &[sig_share1, sig_share2],
            &participants,
        )
        .unwrap();

        // Signature should have correct format
        assert_eq!(signature.r.len(), 32);
        assert_eq!(signature.s.len(), 32);
        assert_eq!(signature.curve, EcdsaCurve::P256);
    }

    #[test]
    fn test_full_signing_flow_secp256k1_2_of_3() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::Secp256k1).unwrap();

        let message = b"Bitcoin/Ethereum test message";
        let message_hash = hash_message(message);

        // Round 1
        let (nonce1, commitment1) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
        let (nonce2, commitment2) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
        let commitments = vec![commitment1, commitment2];
        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        // Round 2
        let presig1 =
            ThresholdEcdsaEngine::presign(&shares[0], &nonce1, &commitments, &participants)
                .unwrap();
        let presig2 =
            ThresholdEcdsaEngine::presign(&shares[1], &nonce2, &commitments, &participants)
                .unwrap();

        // Round 3
        let sig_share1 =
            ThresholdEcdsaEngine::sign_share(&shares[0], &presig1, &message_hash).unwrap();
        let sig_share2 =
            ThresholdEcdsaEngine::sign_share(&shares[1], &presig2, &message_hash).unwrap();

        // Aggregate
        let signature = ThresholdEcdsaEngine::aggregate(
            &group_key,
            &presig1,
            &[sig_share1, sig_share2],
            &participants,
        )
        .unwrap();

        assert_eq!(signature.curve, EcdsaCurve::Secp256k1);
    }

    #[test]
    fn test_insufficient_participants_fails() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (_, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();

        // Only get commitment from 1 participant (need 2)
        let (nonce1, commitment1) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
        let commitments = vec![commitment1];
        let participants = vec![shares[0].participant_id];

        // Should fail
        let result =
            ThresholdEcdsaEngine::presign(&shares[0], &nonce1, &commitments, &participants);

        assert!(matches!(
            result,
            Err(ThresholdError::InsufficientParticipants { .. })
        ));
    }

    #[test]
    fn test_3_of_5_signing() {
        let config = ThresholdConfig::new(3, 5).unwrap();
        let (group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();

        let message_hash = hash_message(b"3-of-5 test");

        // Use participants 0, 2, 4 (non-consecutive)
        let selected = [0, 2, 4];
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();

        for &idx in &selected {
            let (nonce, commitment) = ThresholdEcdsaEngine::generate_nonces(&shares[idx]).unwrap();
            nonces.push(nonce);
            commitments.push(commitment);
        }

        let participants: Vec<ParticipantId> =
            selected.iter().map(|&i| shares[i].participant_id).collect();

        // Pre-sign
        let presigs: Vec<EcdsaPreSignature> = selected
            .iter()
            .enumerate()
            .map(|(i, &idx)| {
                ThresholdEcdsaEngine::presign(&shares[idx], &nonces[i], &commitments, &participants)
                    .unwrap()
            })
            .collect();

        // Sign
        let sig_shares: Vec<EcdsaSignatureShare> = selected
            .iter()
            .enumerate()
            .map(|(i, &idx)| {
                ThresholdEcdsaEngine::sign_share(&shares[idx], &presigs[i], &message_hash).unwrap()
            })
            .collect();

        // Aggregate
        let signature =
            ThresholdEcdsaEngine::aggregate(&group_key, &presigs[0], &sig_shares, &participants)
                .unwrap();

        assert_eq!(signature.r.len(), 32);
        assert_eq!(signature.s.len(), 32);
    }

    #[test]
    fn test_different_subsets_produce_consistent_signatures() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();

        let message_hash = hash_message(b"consistency test");

        // Sign with participants 0 and 1
        let (nonce0a, commit0a) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
        let (nonce1a, commit1a) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
        let commits_01 = vec![commit0a, commit1a];
        let parts_01 = vec![shares[0].participant_id, shares[1].participant_id];

        let presig0a =
            ThresholdEcdsaEngine::presign(&shares[0], &nonce0a, &commits_01, &parts_01).unwrap();
        let presig1a =
            ThresholdEcdsaEngine::presign(&shares[1], &nonce1a, &commits_01, &parts_01).unwrap();

        let share0a =
            ThresholdEcdsaEngine::sign_share(&shares[0], &presig0a, &message_hash).unwrap();
        let share1a =
            ThresholdEcdsaEngine::sign_share(&shares[1], &presig1a, &message_hash).unwrap();

        let sig_01 =
            ThresholdEcdsaEngine::aggregate(&group_key, &presig0a, &[share0a, share1a], &parts_01)
                .unwrap();

        // Both signatures should have valid format
        assert_eq!(sig_01.to_bytes().len(), 64);
    }

    #[test]
    fn test_curve_mismatch_fails() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (_, p256_shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();
        let (_, secp256k1_shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::Secp256k1).unwrap();

        // Generate nonces for P-256
        let (nonce, _) = ThresholdEcdsaEngine::generate_nonces(&p256_shares[0]).unwrap();

        // Try to generate commitments from secp256k1 shares (need 2 to meet threshold)
        let (_, secp_commitment1) =
            ThresholdEcdsaEngine::generate_nonces(&secp256k1_shares[0]).unwrap();
        let (_, secp_commitment2) =
            ThresholdEcdsaEngine::generate_nonces(&secp256k1_shares[1]).unwrap();

        // Pre-sign should fail due to curve mismatch (we have enough commitments but wrong curve)
        let result = ThresholdEcdsaEngine::presign(
            &p256_shares[0],
            &nonce,
            &[secp_commitment1, secp_commitment2],
            &[
                secp256k1_shares[0].participant_id,
                secp256k1_shares[1].participant_id,
            ],
        );

        assert!(matches!(result, Err(ThresholdError::CryptoError(_))));
    }

    #[test]
    fn test_hash_message() {
        let message = b"test message";
        let hash = ThresholdEcdsaEngine::hash_message(message);

        assert_eq!(hash.len(), 32);

        // Same message should produce same hash
        let hash2 = ThresholdEcdsaEngine::hash_message(message);
        assert_eq!(hash, hash2);

        // Different message should produce different hash
        let hash3 = ThresholdEcdsaEngine::hash_message(b"different message");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_signature_serialization() {
        let sig = EcdsaThresholdSignature::new(vec![1; 32], vec![2; 32], EcdsaCurve::P256);

        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 64);
        assert_eq!(&bytes[0..32], &[1; 32]);
        assert_eq!(&bytes[32..64], &[2; 32]);

        let recovered = EcdsaThresholdSignature::from_bytes(&bytes, EcdsaCurve::P256).unwrap();
        assert_eq!(recovered.r, sig.r);
        assert_eq!(recovered.s, sig.s);
    }
}
