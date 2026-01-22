//! FROST (Flexible Round-Optimized Schnorr Threshold) implementation
//!
//! This module provides the core FROST operations for threshold Ed25519 signatures:
//! - Key generation (trusted dealer and DKG)
//! - Commitment generation (Round 1)
//! - Signature share generation (Round 2)
//! - Signature aggregation
//! - Signature verification
//!
//! # Security
//!
//! - Nonces must be fresh for each signing session; reusing nonces allows key extraction
//! - The trusted dealer method requires a secure channel for distributing shares
//! - For production use, prefer DKG (distributed key generation) over trusted dealer

use frost_ed25519 as frost;
use rand_core::OsRng;
use std::collections::BTreeMap;

use super::types::*;

/// FROST threshold signing engine for Ed25519.
///
/// Provides static methods for all FROST operations. This engine does not
/// hold any state; all state is managed through the types returned by
/// each operation.
pub struct FrostEngine;

impl FrostEngine {
    /// Generate key shares using a trusted dealer.
    ///
    /// This is the simpler key generation method but requires trusting a single
    /// party (the dealer) to generate and distribute keys honestly. The dealer
    /// has access to the full secret key during generation.
    ///
    /// # Arguments
    ///
    /// * `config` - Threshold configuration (t-of-n)
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
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = ThresholdConfig::new(2, 3).unwrap();
    /// let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();
    /// assert_eq!(shares.len(), 3);
    /// ```
    pub fn trusted_dealer_keygen(
        config: ThresholdConfig,
    ) -> Result<(GroupPublicKey, Vec<KeyShare>), ThresholdError> {
        let (shares, pubkey_package) = frost::keys::generate_with_dealer(
            config.total_participants,
            config.threshold,
            frost::keys::IdentifierList::Default,
            OsRng,
        )
        .map_err(|e| ThresholdError::DkgFailed {
            round: 0,
            reason: e.to_string(),
        })?;

        // Serialize the public key package for later use in aggregation
        let pubkey_package_bytes = pubkey_package
            .serialize()
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Get verifying key bytes - serialize returns Result<Vec<u8>, Error>
        let verifying_key_bytes: Vec<u8> = pubkey_package
            .verifying_key()
            .serialize()
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        let group_public_key =
            GroupPublicKey::new(verifying_key_bytes, config, pubkey_package_bytes);

        // Process shares - enumerate to get participant number (1-indexed)
        let key_shares: Result<Vec<KeyShare>, ThresholdError> = shares
            .into_iter()
            .enumerate()
            .map(|(index, (_id, secret_share))| {
                // Participant IDs in FROST are 1-indexed
                let participant_num = (index + 1) as u16;

                // Serialize the signing share - returns fixed-size array
                let secret_share_bytes: Vec<u8> = secret_share.signing_share().serialize().to_vec();

                // Verify the share and get the verifying share
                // The verify method returns (VerifyingShare, VerifyingKey)
                let (verifying_share, _) =
                    secret_share
                        .verify()
                        .map_err(|e| ThresholdError::DkgFailed {
                            round: 0,
                            reason: format!("Share verification failed: {}", e),
                        })?;

                // Serialize the verifying share
                let public_share_bytes: Vec<u8> = verifying_share
                    .serialize()
                    .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

                Ok(KeyShare::new(
                    ParticipantId(participant_num),
                    config,
                    secret_share_bytes,
                    public_share_bytes,
                ))
            })
            .collect();

        Ok((group_public_key, key_shares?))
    }

    /// Generate signing nonces and commitment for Round 1.
    ///
    /// Each participant must call this at the start of a signing session.
    /// The nonce must be kept secret; the commitment is shared with others.
    ///
    /// # Arguments
    ///
    /// * `key_share` - The participant's key share
    ///
    /// # Returns
    ///
    /// Tuple of (signing_nonce, signing_commitment) where the nonce is secret
    /// and the commitment is public.
    ///
    /// # Security
    ///
    /// - NEVER reuse nonces across signing sessions
    /// - Nonces are automatically zeroized when dropped
    /// - Generate fresh nonces for each message
    pub fn generate_nonces(
        key_share: &KeyShare,
    ) -> Result<(SigningNonce, SigningCommitment), ThresholdError> {
        // Reconstruct the signing share from serialized bytes
        let signing_share = frost::keys::SigningShare::deserialize(key_share.secret_share_bytes())
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Generate nonces and commitments
        let (nonces, commitments) = frost::round1::commit(&signing_share, &mut OsRng);

        // Serialize for storage/transmission
        let nonce_bytes = nonces
            .serialize()
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        let commitment_bytes = commitments
            .serialize()
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        Ok((
            SigningNonce::new(nonce_bytes),
            SigningCommitment::new(key_share.participant_id, commitment_bytes),
        ))
    }

    /// Generate a signature share (Round 2).
    ///
    /// After receiving all commitments from participating signers, each
    /// participant generates their signature share.
    ///
    /// # Arguments
    ///
    /// * `key_share` - The participant's key share
    /// * `nonce` - The nonce generated in Round 1 (consumed)
    /// * `message` - The message to sign
    /// * `commitments` - All signing commitments from Round 1
    /// * `group_public_key` - The group's public key
    ///
    /// # Returns
    ///
    /// A signature share that will be combined with other shares.
    ///
    /// # Security
    ///
    /// - The nonce is consumed and should not be reused
    /// - Verify the message matches what you expect before signing
    pub fn sign_share(
        key_share: &KeyShare,
        nonce: &SigningNonce,
        message: &[u8],
        commitments: &[SigningCommitment],
        group_public_key: &GroupPublicKey,
    ) -> Result<SignatureShare, ThresholdError> {
        // Check we have enough commitments
        if commitments.len() < key_share.config.threshold as usize {
            return Err(ThresholdError::InsufficientParticipants {
                required: key_share.config.threshold,
                provided: commitments.len() as u16,
            });
        }

        // Reconstruct the signing share
        let signing_share = frost::keys::SigningShare::deserialize(key_share.secret_share_bytes())
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Reconstruct the verifying share
        let verifying_share = frost::keys::VerifyingShare::deserialize(&key_share.public_key_share)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Reconstruct the verifying key
        let verifying_key = frost::VerifyingKey::deserialize(&group_public_key.bytes)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Build the identifier
        let identifier = frost::Identifier::try_from(key_share.participant_id.0)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Build the key package
        let key_package = frost::keys::KeyPackage::new(
            identifier,
            signing_share,
            verifying_share,
            verifying_key,
            key_share.config.threshold,
        );

        // Deserialize the signing nonces
        let signing_nonces = frost::round1::SigningNonces::deserialize(&nonce.nonce_bytes)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Build the commitment map
        let commitment_map: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> =
            commitments
                .iter()
                .map(|c| {
                    let id = frost::Identifier::try_from(c.participant_id.0)
                        .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

                    let commitment =
                        frost::round1::SigningCommitments::deserialize(&c.commitment_bytes)
                            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

                    Ok((id, commitment))
                })
                .collect::<Result<_, ThresholdError>>()?;

        // Create the signing package
        let signing_package = frost::SigningPackage::new(commitment_map, message);

        // Generate the signature share
        let sig_share = frost::round2::sign(&signing_package, &signing_nonces, &key_package)
            .map_err(|e| ThresholdError::SigningFailed(e.to_string()))?;

        Ok(SignatureShare::new(
            key_share.participant_id,
            sig_share.serialize().to_vec(),
        ))
    }

    /// Aggregate signature shares into a final threshold signature.
    ///
    /// The coordinator collects signature shares from at least t participants
    /// and combines them into a single signature that verifies against the
    /// group public key.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `commitments` - All signing commitments from Round 1
    /// * `signature_shares` - Signature shares from Round 2
    /// * `group_public_key` - The group's public key
    ///
    /// # Returns
    ///
    /// A complete threshold signature that verifies as a standard Ed25519 signature.
    ///
    /// # Security
    ///
    /// - Verifies each signature share before aggregation
    /// - Invalid shares will cause aggregation to fail
    pub fn aggregate_signatures(
        message: &[u8],
        commitments: &[SigningCommitment],
        signature_shares: &[SignatureShare],
        group_public_key: &GroupPublicKey,
    ) -> Result<ThresholdSignature, ThresholdError> {
        // Check we have enough shares
        if signature_shares.len() < group_public_key.config.threshold as usize {
            return Err(ThresholdError::InsufficientParticipants {
                required: group_public_key.config.threshold,
                provided: signature_shares.len() as u16,
            });
        }

        // Build the commitment map
        let commitment_map: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> =
            commitments
                .iter()
                .map(|c| {
                    let id = frost::Identifier::try_from(c.participant_id.0)
                        .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

                    let commitment =
                        frost::round1::SigningCommitments::deserialize(&c.commitment_bytes)
                            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

                    Ok((id, commitment))
                })
                .collect::<Result<_, ThresholdError>>()?;

        // Create the signing package
        let signing_package = frost::SigningPackage::new(commitment_map, message);

        // Build the signature share map
        let share_map: BTreeMap<frost::Identifier, frost::round2::SignatureShare> =
            signature_shares
                .iter()
                .map(|s| {
                    let id = frost::Identifier::try_from(s.participant_id.0)
                        .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

                    let share = frost::round2::SignatureShare::deserialize(&s.share)
                        .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

                    Ok((id, share))
                })
                .collect::<Result<_, ThresholdError>>()?;

        // Deserialize the public key package
        let pubkey_package =
            frost::keys::PublicKeyPackage::deserialize(&group_public_key.pubkey_package)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Aggregate the signature shares
        let signature = frost::aggregate(&signing_package, &share_map, &pubkey_package)
            .map_err(|e| ThresholdError::SigningFailed(e.to_string()))?;

        let sig_bytes = signature
            .serialize()
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;
        Ok(ThresholdSignature::new(sig_bytes))
    }

    /// Verify a threshold signature.
    ///
    /// The resulting signature is a standard Ed25519 signature and can be
    /// verified using standard Ed25519 verification. This method provides
    /// a convenient wrapper.
    ///
    /// # Arguments
    ///
    /// * `group_public_key` - The group's public key
    /// * `message` - The message that was signed
    /// * `signature` - The threshold signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, error otherwise.
    pub fn verify(
        group_public_key: &GroupPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        // Reconstruct the verifying key
        let verifying_key = frost::VerifyingKey::deserialize(&group_public_key.bytes)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Reconstruct the signature
        let sig = frost::Signature::deserialize(&signature.bytes)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Verify
        verifying_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(|_| ThresholdError::VerificationFailed)
    }

    /// Verify a threshold signature using standard Ed25519 verification.
    ///
    /// This demonstrates that threshold signatures are compatible with
    /// standard Ed25519 verification (using ed25519-dalek or similar).
    ///
    /// # Arguments
    ///
    /// * `public_key_bytes` - 32-byte Ed25519 public key
    /// * `message` - The message that was signed
    /// * `signature_bytes` - 64-byte Ed25519 signature
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid.
    pub fn verify_with_ed25519(
        public_key_bytes: &[u8],
        message: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, ThresholdError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let public_key_array: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| ThresholdError::SerializationError("Invalid public key length".into()))?;

        let verifying_key = VerifyingKey::from_bytes(&public_key_array)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        let sig_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| ThresholdError::SerializationError("Invalid signature length".into()))?;

        let signature = Signature::from_bytes(&sig_array);

        verifying_key
            .verify(message, &signature)
            .map(|_| true)
            .map_err(|_| ThresholdError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_dealer_keygen_2_of_3() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        assert_eq!(shares.len(), 3);
        assert_eq!(group_key.bytes.len(), 32); // Ed25519 public key
        assert_eq!(group_key.config.threshold, 2);
        assert_eq!(group_key.config.total_participants, 3);

        // Each share should have valid structure
        for share in &shares {
            assert_eq!(share.config.threshold, 2);
            assert_eq!(share.config.total_participants, 3);
            assert!(!share.secret_share.is_empty());
            assert!(!share.public_key_share.is_empty());
        }
    }

    #[test]
    fn test_trusted_dealer_keygen_3_of_5() {
        let config = ThresholdConfig::new(3, 5).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        assert_eq!(shares.len(), 5);
        assert_eq!(group_key.config.threshold, 3);
        assert_eq!(group_key.config.total_participants, 5);
    }

    #[test]
    fn test_generate_nonces() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (_, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        let (nonce, commitment) = FrostEngine::generate_nonces(&shares[0]).unwrap();

        // Nonce should be non-empty
        assert!(!nonce.nonce_bytes.is_empty());
        // Commitment should reference the correct participant
        assert_eq!(commitment.participant_id, shares[0].participant_id);
        assert!(!commitment.commitment_bytes.is_empty());
    }

    #[test]
    fn test_full_signing_flow_2_of_3() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Test message for threshold signing";

        // Round 1: Generate nonces and commitments for first 2 participants
        let (nonce1, commitment1) = FrostEngine::generate_nonces(&shares[0]).unwrap();
        let (nonce2, commitment2) = FrostEngine::generate_nonces(&shares[1]).unwrap();

        let commitments = vec![commitment1.clone(), commitment2.clone()];

        // Round 2: Generate signature shares
        let sig_share1 =
            FrostEngine::sign_share(&shares[0], &nonce1, message, &commitments, &group_key)
                .unwrap();

        let sig_share2 =
            FrostEngine::sign_share(&shares[1], &nonce2, message, &commitments, &group_key)
                .unwrap();

        let signature_shares = vec![sig_share1, sig_share2];

        // Aggregate signature
        let signature =
            FrostEngine::aggregate_signatures(message, &commitments, &signature_shares, &group_key)
                .unwrap();

        // Verify the signature
        let valid = FrostEngine::verify(&group_key, message, &signature).unwrap();
        assert!(valid);

        // Also verify using standard Ed25519
        let valid_ed25519 =
            FrostEngine::verify_with_ed25519(&group_key.bytes, message, &signature.bytes).unwrap();
        assert!(valid_ed25519);
    }

    #[test]
    fn test_full_signing_flow_3_of_5() {
        let config = ThresholdConfig::new(3, 5).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Another test message";

        // Use participants 0, 2, and 4 (demonstrating non-consecutive selection)
        let selected_indices = [0, 2, 4];

        // Round 1: Generate nonces and commitments
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();

        for &idx in &selected_indices {
            let (nonce, commitment) = FrostEngine::generate_nonces(&shares[idx]).unwrap();
            nonces.push(nonce);
            commitments.push(commitment);
        }

        // Round 2: Generate signature shares
        let mut signature_shares = Vec::new();

        for (i, &idx) in selected_indices.iter().enumerate() {
            let sig_share = FrostEngine::sign_share(
                &shares[idx],
                &nonces[i],
                message,
                &commitments,
                &group_key,
            )
            .unwrap();
            signature_shares.push(sig_share);
        }

        // Aggregate and verify
        let signature =
            FrostEngine::aggregate_signatures(message, &commitments, &signature_shares, &group_key)
                .unwrap();

        let valid = FrostEngine::verify(&group_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_insufficient_participants_fails() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Test message";

        // Only get commitment from 1 participant (need 2)
        let (nonce1, commitment1) = FrostEngine::generate_nonces(&shares[0]).unwrap();
        let commitments = vec![commitment1];

        // Try to sign with only 1 commitment - should fail
        let result =
            FrostEngine::sign_share(&shares[0], &nonce1, message, &commitments, &group_key);

        assert!(matches!(
            result,
            Err(ThresholdError::InsufficientParticipants { .. })
        ));
    }

    #[test]
    fn test_verification_fails_for_wrong_message() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Original message";
        let wrong_message = b"Different message";

        // Generate valid signature for original message
        let (nonce1, commitment1) = FrostEngine::generate_nonces(&shares[0]).unwrap();
        let (nonce2, commitment2) = FrostEngine::generate_nonces(&shares[1]).unwrap();
        let commitments = vec![commitment1, commitment2];

        let sig_share1 =
            FrostEngine::sign_share(&shares[0], &nonce1, message, &commitments, &group_key)
                .unwrap();
        let sig_share2 =
            FrostEngine::sign_share(&shares[1], &nonce2, message, &commitments, &group_key)
                .unwrap();

        let signature = FrostEngine::aggregate_signatures(
            message,
            &commitments,
            &[sig_share1, sig_share2],
            &group_key,
        )
        .unwrap();

        // Verify with wrong message should fail
        let result = FrostEngine::verify(&group_key, wrong_message, &signature);
        assert!(matches!(result, Err(ThresholdError::VerificationFailed)));
    }

    #[test]
    fn test_different_participant_subsets_produce_valid_signatures() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Test message";

        // Sign with participants 0 and 1
        let (nonce0, commitment0) = FrostEngine::generate_nonces(&shares[0]).unwrap();
        let (nonce1, commitment1) = FrostEngine::generate_nonces(&shares[1]).unwrap();
        let commitments_01 = vec![commitment0, commitment1];

        let sig_share0 =
            FrostEngine::sign_share(&shares[0], &nonce0, message, &commitments_01, &group_key)
                .unwrap();
        let sig_share1 =
            FrostEngine::sign_share(&shares[1], &nonce1, message, &commitments_01, &group_key)
                .unwrap();

        let signature_01 = FrostEngine::aggregate_signatures(
            message,
            &commitments_01,
            &[sig_share0, sig_share1],
            &group_key,
        )
        .unwrap();

        // Sign with participants 1 and 2
        let (nonce1_b, commitment1_b) = FrostEngine::generate_nonces(&shares[1]).unwrap();
        let (nonce2, commitment2) = FrostEngine::generate_nonces(&shares[2]).unwrap();
        let commitments_12 = vec![commitment1_b, commitment2];

        let sig_share1_b =
            FrostEngine::sign_share(&shares[1], &nonce1_b, message, &commitments_12, &group_key)
                .unwrap();
        let sig_share2 =
            FrostEngine::sign_share(&shares[2], &nonce2, message, &commitments_12, &group_key)
                .unwrap();

        let signature_12 = FrostEngine::aggregate_signatures(
            message,
            &commitments_12,
            &[sig_share1_b, sig_share2],
            &group_key,
        )
        .unwrap();

        // Both signatures should verify
        assert!(FrostEngine::verify(&group_key, message, &signature_01).unwrap());
        assert!(FrostEngine::verify(&group_key, message, &signature_12).unwrap());

        // Both should also verify with standard Ed25519
        assert!(
            FrostEngine::verify_with_ed25519(&group_key.bytes, message, &signature_01.bytes)
                .unwrap()
        );
        assert!(
            FrostEngine::verify_with_ed25519(&group_key.bytes, message, &signature_12.bytes)
                .unwrap()
        );
    }
}
