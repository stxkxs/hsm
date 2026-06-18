//! Threshold ECDSA Engine
//!
//! This module provides the main interface for threshold ECDSA operations,
//! supporting both P-256 (FIPS approved) and secp256k1 (Bitcoin/Ethereum) curves.
//!
//! # Status: NOT production-ready (fails closed)
//!
//! The signing path ([`ThresholdEcdsaEngine::presign`], [`ThresholdEcdsaEngine::sign_share`],
//! and [`ThresholdEcdsaEngine::aggregate`]) currently returns
//! [`ThresholdError::NotImplemented`] instead of producing a signature. The
//! implemented math forms `s = k * (m + r * x)` because it never computes the
//! modular inverse `k^-1`; a correct threshold ECDSA protocol (e.g. GG18/GG20 with
//! MtA) is required to obtain additive/multiplicative shares of `k^-1` without
//! reconstructing `k`. Rather than emit signatures that fail every verifier, these
//! entrypoints refuse. Key generation, nonce generation and verification remain
//! usable. The `# Usage` example below documents the intended (future) flow.
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

        // FAIL CLOSED: the threshold-ECDSA signing path is NOT production-ready.
        //
        // The pre-signing math below computes additive shares of `lambda * k` and
        // `lambda * x`, and `sign_share` then forms `s_i = k_inv_i * m + chi_i * r`.
        // Because the modular inverse `k^-1` is never computed, the aggregated `s`
        // equals `k * (m + r * x)` instead of the required `k^-1 * (m + r * x)`, so
        // every emitted signature FAILS standard ECDSA verification. Correct
        // threshold ECDSA requires a real MtA / GG18-GG20 protocol to obtain shares
        // of `k^-1` without reconstructing `k`. Until that is implemented we refuse
        // to run rather than silently produce invalid signatures.
        let _ = (nonce, participants);
        Err(ThresholdError::NotImplemented(
            "threshold ECDSA signing is not production-ready: protocol does not compute k^-1 \
             (requires correct GG20/MtA); see EcdsaThresholdSignature docs"
                .into(),
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
        // FAIL CLOSED: see [`Self::presign`]. The signing path cannot produce a
        // verifiable signature because `k^-1` is never computed, so we refuse here
        // too (a caller could otherwise hand-craft a pre-signature and reach this).
        let _ = (key_share, presignature, message_hash);
        Err(ThresholdError::NotImplemented(
            "threshold ECDSA signing is not production-ready: protocol does not compute k^-1 \
             (requires correct GG20/MtA)"
                .into(),
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

        // FAIL CLOSED: see [`Self::presign`]. Summing the shares yields
        // `s = k * (m + r * x)`, not `s = k^-1 * (m + r * x)`, so the result would
        // never verify. Refuse rather than emit an invalid signature.
        let _ = (presignature, participants);
        Err(ThresholdError::NotImplemented(
            "threshold ECDSA aggregation is not production-ready: protocol does not compute k^-1 \
             (requires correct GG20/MtA)"
                .into(),
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

    /// FAIL-CLOSED regression: the threshold-ECDSA signing path must NOT silently
    /// produce a signature. Before the fix, `presign` -> `sign_share` -> `aggregate`
    /// returned `Ok` with a signature whose `s = k * (m + r*x)` (k^-1 never computed),
    /// so it failed every verifier. Now `presign` returns `NotImplemented`.
    #[test]
    fn test_presign_fails_closed_p256() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (_group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();

        let (nonce1, commitment1) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
        let (_nonce2, commitment2) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
        let commitments = vec![commitment1, commitment2];
        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        // Enough commitments / matching curve -> would previously succeed.
        let result =
            ThresholdEcdsaEngine::presign(&shares[0], &nonce1, &commitments, &participants);
        assert!(
            matches!(result, Err(ThresholdError::NotImplemented(_))),
            "threshold ECDSA presign must fail closed, got {result:?}"
        );
    }

    #[test]
    fn test_presign_fails_closed_secp256k1() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (_group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::Secp256k1).unwrap();

        let (nonce1, commitment1) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
        let (_nonce2, commitment2) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
        let commitments = vec![commitment1, commitment2];
        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        let result =
            ThresholdEcdsaEngine::presign(&shares[0], &nonce1, &commitments, &participants);
        assert!(matches!(result, Err(ThresholdError::NotImplemented(_))));
    }

    /// `sign_share` and `aggregate` must also refuse, even if a caller fabricates a
    /// pre-signature, so the broken math is unreachable from every public entrypoint.
    #[test]
    fn test_sign_share_and_aggregate_fail_closed() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();
        let participants = vec![shares[0].participant_id, shares[1].participant_id];
        let message_hash = hash_message(b"fabricated presig");

        // A fabricated (structurally valid) pre-signature.
        let presig = EcdsaPreSignature::new(
            shares[0].participant_id,
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            EcdsaCurve::P256,
        );

        let share_res = ThresholdEcdsaEngine::sign_share(&shares[0], &presig, &message_hash);
        assert!(matches!(share_res, Err(ThresholdError::NotImplemented(_))));

        let fake_shares = vec![
            EcdsaSignatureShare::new(shares[0].participant_id, vec![4u8; 32], EcdsaCurve::P256),
            EcdsaSignatureShare::new(shares[1].participant_id, vec![5u8; 32], EcdsaCurve::P256),
        ];
        let agg_res =
            ThresholdEcdsaEngine::aggregate(&group_key, &presig, &fake_shares, &participants);
        assert!(matches!(agg_res, Err(ThresholdError::NotImplemented(_))));
    }

    /// Target KAT for a correct threshold ECDSA implementation (GG20/MtA): the
    /// aggregated threshold signature MUST verify under standard ECDSA against the
    /// group public key. Ignored until `k^-1` is computed via a real MtA protocol.
    /// This documents the acceptance criterion and will FAIL (presign errors) today.
    #[test]
    #[ignore = "requires correct threshold ECDSA (GG20/MtA)"]
    fn test_threshold_ecdsa_signs_and_verifies_standard_p256() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();

        let message_hash = hash_message(b"threshold ECDSA KAT target");

        let (nonce1, commitment1) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
        let (nonce2, commitment2) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
        let commitments = vec![commitment1, commitment2];
        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        let presig1 =
            ThresholdEcdsaEngine::presign(&shares[0], &nonce1, &commitments, &participants)
                .unwrap();
        let presig2 =
            ThresholdEcdsaEngine::presign(&shares[1], &nonce2, &commitments, &participants)
                .unwrap();

        let s1 = ThresholdEcdsaEngine::sign_share(&shares[0], &presig1, &message_hash).unwrap();
        let s2 = ThresholdEcdsaEngine::sign_share(&shares[1], &presig2, &message_hash).unwrap();

        let signature =
            ThresholdEcdsaEngine::aggregate(&group_key, &presig1, &[s1, s2], &participants)
                .unwrap();

        // Acceptance criterion: a standard ECDSA verifier accepts the threshold sig.
        assert!(
            ThresholdEcdsaEngine::verify_standard(&group_key.bytes, &message_hash, &signature)
                .unwrap(),
            "threshold signature must verify under standard ECDSA"
        );
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

    /// Target full 3-of-5 flow for a correct threshold ECDSA implementation
    /// (GG20/MtA). Ignored until `k^-1` is computed; documents the non-consecutive
    /// participant subset case and the standard-ECDSA acceptance criterion.
    #[test]
    #[ignore = "requires correct threshold ECDSA (GG20/MtA)"]
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

        assert!(
            ThresholdEcdsaEngine::verify_standard(&group_key.bytes, &message_hash, &signature)
                .unwrap()
        );
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
