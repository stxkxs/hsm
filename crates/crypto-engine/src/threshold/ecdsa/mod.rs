//! Threshold ECDSA module
//!
//! This module provides threshold ECDSA signature capabilities, allowing
//! t-of-n parties to collaboratively sign messages without any single party
//! holding the complete private key.
//!
//! # Supported Curves
//!
//! - **P-256 (secp256r1)**: FIPS 140-3 approved, used in TLS, PIV, WebAuthn, etc.
//! - **secp256k1**: Bitcoin and Ethereum compatible (not FIPS approved)
//!
//! # Protocol
//!
//! Threshold ECDSA signing follows a 3-round protocol:
//!
//! 1. **Nonce Generation**: Each participant generates random nonces and broadcasts
//!    commitments to prevent replay attacks.
//!
//! 2. **Pre-signing**: Participants compute the R point collaboratively and derive
//!    pre-signature shares. This can be done before the message is known.
//!
//! 3. **Signing**: Given a message hash, participants compute signature shares
//!    that are aggregated into the final ECDSA signature (r, s).
//!
//! # Security Properties
//!
//! - **Key Splitting**: The private key is split using Shamir's Secret Sharing
//! - **Threshold Security**: Fewer than t parties learn nothing about the key
//! - **Nonce Security**: Fresh nonces prevent key extraction attacks
//! - **Standard Signatures**: Output signatures are standard ECDSA compatible
//!
//! # Example
//!
//! ```ignore
//! use hsm_crypto_engine::threshold::ecdsa::*;
//! use hsm_crypto_engine::threshold::types::EcdsaCurve;
//!
//! // Generate 2-of-3 threshold keys for P-256
//! let config = ThresholdConfig::new(2, 3).unwrap();
//! let (group_key, shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
//!     config,
//!     EcdsaCurve::P256
//! ).unwrap();
//!
//! // Sign a message with participants 1 and 2
//! let message_hash = ThresholdEcdsaEngine::hash_message(b"Hello, threshold ECDSA!");
//!
//! // Round 1: Generate nonces
//! let (nonce1, commit1) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
//! let (nonce2, commit2) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
//! let commitments = vec![commit1, commit2];
//! let participants = vec![shares[0].participant_id, shares[1].participant_id];
//!
//! // Round 2: Pre-sign
//! let presig1 = ThresholdEcdsaEngine::presign(&shares[0], &nonce1, &commitments, &participants).unwrap();
//! let presig2 = ThresholdEcdsaEngine::presign(&shares[1], &nonce2, &commitments, &participants).unwrap();
//!
//! // Round 3: Sign
//! let share1 = ThresholdEcdsaEngine::sign_share(&shares[0], &presig1, &message_hash).unwrap();
//! let share2 = ThresholdEcdsaEngine::sign_share(&shares[1], &presig2, &message_hash).unwrap();
//!
//! // Aggregate
//! let signature = ThresholdEcdsaEngine::aggregate(
//!     &group_key,
//!     &presig1,
//!     &[share1, share2],
//!     &participants
//! ).unwrap();
//!
//! // Signature is standard ECDSA format
//! println!("Signature: {} bytes", signature.to_bytes().len());
//! ```
//!
//! # FIPS Compliance
//!
//! For FIPS 140-3 compliance, use the P-256 curve:
//!
//! ```ignore
//! // FIPS-approved configuration
//! let (group_key, shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
//!     config,
//!     EcdsaCurve::P256  // FIPS approved
//! ).unwrap();
//!
//! assert!(group_key.is_fips_approved());
//! ```
//!
//! For Bitcoin/Ethereum compatibility, use secp256k1 (not FIPS approved):
//!
//! ```ignore
//! // Bitcoin/Ethereum configuration
//! let (group_key, shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
//!     config,
//!     EcdsaCurve::Secp256k1  // Not FIPS approved
//! ).unwrap();
//!
//! assert!(!group_key.is_fips_approved());
//! ```

pub mod dkg;
mod engine;
pub mod feldman;
mod p256;
mod secp256k1;
mod types;

// Re-export the main engine
pub use engine::ThresholdEcdsaEngine;

// Re-export types
pub use types::{
    EcdsaGroupPublicKey, EcdsaKeyShare, EcdsaPreSignature, EcdsaSignatureShare,
    EcdsaSigningCommitment, EcdsaSigningNonce, EcdsaThresholdSignature,
};

// Re-export curve operations for advanced usage
pub use p256::P256ThresholdOps;
pub use secp256k1::Secp256k1ThresholdOps;

// Re-export DKG types
pub use dkg::{EcdsaDkg, EcdsaDkgRound1Package, EcdsaDkgRound2Package, EcdsaDkgState};

// Re-export Feldman VSS
pub use feldman::FeldmanVss;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::types::{EcdsaCurve, ThresholdConfig};

    /// Integration test: Full 2-of-3 P-256 signing and verification.
    ///
    /// Ignored: the threshold-ECDSA signing path now fails closed because it never
    /// computes `k^-1` (see `ThresholdEcdsaEngine::presign`). This test drove the
    /// full presign->sign_share->aggregate flow and only checked the signature's
    /// shape (`r.len()/s.len()`), never that it verifies — exactly the kind of
    /// shape-only assertion that masked the broken math. Re-enable once a correct
    /// GG20/MtA protocol is implemented.
    #[test]
    #[ignore = "requires correct threshold ECDSA (GG20/MtA)"]
    fn test_integration_p256_2_of_3() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();

        let message = b"Integration test message for P-256 threshold ECDSA";
        let message_hash = ThresholdEcdsaEngine::hash_message(message);

        // Use participants 1 and 3 (indices 0 and 2)
        let selected_indices = [0, 2];

        // Round 1: Nonces
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for &idx in &selected_indices {
            let (nonce, commitment) = ThresholdEcdsaEngine::generate_nonces(&shares[idx]).unwrap();
            nonces.push(nonce);
            commitments.push(commitment);
        }

        let participants: Vec<_> = selected_indices
            .iter()
            .map(|&i| shares[i].participant_id)
            .collect();

        // Round 2: Pre-sign
        let presigs: Vec<_> = selected_indices
            .iter()
            .enumerate()
            .map(|(i, &idx)| {
                ThresholdEcdsaEngine::presign(&shares[idx], &nonces[i], &commitments, &participants)
                    .unwrap()
            })
            .collect();

        // Round 3: Sign
        let sig_shares: Vec<_> = selected_indices
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

        // Verify signature format
        assert_eq!(signature.r.len(), 32);
        assert_eq!(signature.s.len(), 32);
        assert_eq!(signature.curve, EcdsaCurve::P256);
    }

    /// Integration test: Full 3-of-5 secp256k1 signing.
    ///
    /// Ignored: the threshold-ECDSA signing path now fails closed (no `k^-1`); this
    /// test only checked `signature.to_bytes().len() == 64`, never that the signature
    /// verifies. Re-enable once a correct GG20/MtA protocol is implemented.
    #[test]
    #[ignore = "requires correct threshold ECDSA (GG20/MtA)"]
    fn test_integration_secp256k1_3_of_5() {
        let config = ThresholdConfig::new(3, 5).unwrap();
        let (group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::Secp256k1).unwrap();

        let message = b"Bitcoin/Ethereum compatible threshold signature";
        let message_hash = ThresholdEcdsaEngine::hash_message(message);

        // Use participants 1, 2, 5 (indices 0, 1, 4)
        let selected_indices = [0, 1, 4];

        // Round 1
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for &idx in &selected_indices {
            let (nonce, commitment) = ThresholdEcdsaEngine::generate_nonces(&shares[idx]).unwrap();
            nonces.push(nonce);
            commitments.push(commitment);
        }

        let participants: Vec<_> = selected_indices
            .iter()
            .map(|&i| shares[i].participant_id)
            .collect();

        // Round 2
        let presigs: Vec<_> = selected_indices
            .iter()
            .enumerate()
            .map(|(i, &idx)| {
                ThresholdEcdsaEngine::presign(&shares[idx], &nonces[i], &commitments, &participants)
                    .unwrap()
            })
            .collect();

        // Round 3
        let sig_shares: Vec<_> = selected_indices
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

        // Verify format
        assert_eq!(signature.curve, EcdsaCurve::Secp256k1);
        assert_eq!(signature.to_bytes().len(), 64);
    }

    /// Test that P-256 is marked as FIPS approved
    #[test]
    fn test_fips_approval_p256() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();

        assert!(group_key.is_fips_approved());
        for share in &shares {
            assert!(share.is_fips_approved());
        }
    }

    /// Test that secp256k1 is NOT FIPS approved
    #[test]
    fn test_fips_approval_secp256k1() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::Secp256k1).unwrap();

        assert!(!group_key.is_fips_approved());
        for share in &shares {
            assert!(!share.is_fips_approved());
        }
    }

    /// Test threshold enforcement
    #[test]
    fn test_threshold_enforcement() {
        let config = ThresholdConfig::new(3, 5).unwrap();
        let (_group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();

        let _message_hash = ThresholdEcdsaEngine::hash_message(b"threshold test");

        // Try with only 2 participants (need 3)
        let (nonce1, commit1) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
        let (_nonce2, commit2) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
        let commitments = vec![commit1, commit2];
        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        // Pre-sign should fail due to insufficient participants
        let result =
            ThresholdEcdsaEngine::presign(&shares[0], &nonce1, &commitments, &participants);

        assert!(matches!(
            result,
            Err(
                crate::threshold::types::ThresholdError::InsufficientParticipants {
                    required: 3,
                    provided: 2
                }
            )
        ));
    }

    /// Test that curve operations are consistent
    #[test]
    fn test_p256_ops_consistency() {
        // Test split and reconstruct
        let secret = P256ThresholdOps::random_scalar();
        let shares = P256ThresholdOps::split_secret(&secret, 2, 3).unwrap();

        let subset: Vec<_> = shares[0..2]
            .iter()
            .map(|(id, s)| (crate::threshold::types::ParticipantId(*id), *s))
            .collect();

        let reconstructed = P256ThresholdOps::reconstruct_secret(&subset);
        assert_eq!(secret, reconstructed);
    }

    /// Test that curve operations are consistent for secp256k1
    #[test]
    fn test_secp256k1_ops_consistency() {
        let secret = Secp256k1ThresholdOps::random_scalar();
        let shares = Secp256k1ThresholdOps::split_secret(&secret, 2, 3).unwrap();

        let subset: Vec<_> = shares[0..2]
            .iter()
            .map(|(id, s)| (crate::threshold::types::ParticipantId(*id), *s))
            .collect();

        let reconstructed = Secp256k1ThresholdOps::reconstruct_secret(&subset);
        assert_eq!(secret, reconstructed);
    }
}
