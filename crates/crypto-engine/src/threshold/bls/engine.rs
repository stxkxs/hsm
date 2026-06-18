//! Threshold BLS12-381 signing engine
//!
//! This module implements threshold BLS signatures using the BLS12-381 curve.
//! BLS signatures have native aggregation support and require only a single
//! round for signing (no commitment phase needed).
//!
//! # Protocol Overview
//!
//! BLS threshold signing is simpler than FROST or threshold ECDSA:
//!
//! 1. **Key Generation**: Split secret key using Shamir's Secret Sharing
//! 2. **Signing**: Each participant signs the message with their share
//! 3. **Aggregation**: Combine signature shares using Lagrange interpolation
//!
//! # Security Properties
//!
//! - Single-round protocol (no nonce commitments needed)
//! - Signatures are deterministic given key and message
//! - Native signature aggregation for multi-party verification
//! - Threshold signatures are indistinguishable from regular BLS signatures
//!
//! # FIPS Status
//!
//! BLS12-381 is currently under NIST evaluation and is NOT yet FIPS approved.
//! Use FROST-Ed25519 or Threshold-ECDSA-P256 for FIPS-compliant applications.

use super::types::{BlsKeyShare, BlsSignatureShare, BlsThresholdSignature, BLS_DST};
use crate::threshold::types::{GroupPublicKey, ParticipantId, ThresholdConfig, ThresholdError};
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

/// Threshold BLS signing engine for BLS12-381.
///
/// Provides static methods for all threshold BLS operations. This engine
/// does not hold any state; all state is managed through the types returned
/// by each operation.
///
/// # Example
///
/// ```ignore
/// use hsm_crypto_engine::threshold::bls::{ThresholdBlsEngine, BlsKeyShare};
/// use hsm_crypto_engine::threshold::ThresholdConfig;
///
/// // Generate 2-of-3 threshold keys
/// let config = ThresholdConfig::new(2, 3).unwrap();
/// let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();
///
/// // Sign with participants 1 and 2
/// let message = b"Hello, threshold BLS!";
/// let share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
/// let share2 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
///
/// // Aggregate signature shares
/// let participants = vec![shares[0].participant_id, shares[1].participant_id];
/// let signature =
///     ThresholdBlsEngine::aggregate(&[share1, share2], &participants, config.threshold).unwrap();
///
/// // Verify
/// assert!(ThresholdBlsEngine::verify(&group_key, message, &signature).unwrap());
/// ```
pub struct ThresholdBlsEngine;

impl ThresholdBlsEngine {
    /// Generate key shares using a trusted dealer.
    ///
    /// This method generates a master BLS keypair and splits the secret key
    /// into shares using Shamir's Secret Sharing. The dealer has access to
    /// the complete secret key during generation.
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
    pub fn trusted_dealer_keygen(
        config: ThresholdConfig,
    ) -> Result<(GroupPublicKey, Vec<BlsKeyShare>), ThresholdError> {
        // Generate random master secret key (32 bytes)
        let mut master_sk_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut master_sk_bytes);

        // Create BLS secret key from random bytes using key_gen
        // The key_gen function properly hashes the input to derive a valid scalar
        let master_sk = SecretKey::key_gen(&master_sk_bytes, &[]).map_err(|_| {
            ThresholdError::CryptoError("Failed to generate master secret key".into())
        })?;

        // Zeroize the raw bytes
        master_sk_bytes.zeroize();

        // Compute group public key
        let master_pk = master_sk.sk_to_pk();

        // Split secret into shares using Shamir's Secret Sharing
        let secret_shares =
            Self::split_secret_shamir(&master_sk, config.threshold, config.total_participants)?;

        // Create key share objects
        let mut key_shares = Vec::with_capacity(config.total_participants as usize);

        for (i, share_bytes) in secret_shares.into_iter().enumerate() {
            let participant_id = ParticipantId::new((i + 1) as u16)?;

            // Derive public key share from secret share
            let share_sk =
                SecretKey::from_bytes(&share_bytes).map_err(|_| ThresholdError::InvalidKeyShare)?;
            let share_pk = share_sk.sk_to_pk();

            key_shares.push(BlsKeyShare::new(
                participant_id,
                config,
                share_bytes,
                share_pk.to_bytes().to_vec(),
                master_pk.to_bytes().to_vec(),
            ));
        }

        // Create GroupPublicKey for compatibility with the threshold module types
        let group_public_key = GroupPublicKey::new(
            master_pk.to_bytes().to_vec(),
            config,
            master_pk.to_bytes().to_vec(), // pubkey_package is just the raw bytes for BLS
        );

        Ok((group_public_key, key_shares))
    }

    /// Generate a signature share.
    ///
    /// BLS signing is single-round: each participant simply signs the message
    /// with their secret key share. No commitment phase is required.
    ///
    /// # Arguments
    ///
    /// * `key_share` - The participant's key share
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// A signature share that will be combined with other shares.
    pub fn sign_share(
        key_share: &BlsKeyShare,
        message: &[u8],
    ) -> Result<BlsSignatureShare, ThresholdError> {
        let sk = key_share.secret_key()?;

        // BLS sign: sigma_i = sk_i * H(m)
        let sig = sk.sign(message, BLS_DST, &[]);

        Ok(BlsSignatureShare::new(
            key_share.participant_id,
            sig.to_bytes().to_vec(),
        ))
    }

    /// Aggregate signature shares into a final threshold signature.
    ///
    /// This combines the signature shares from at least t participants
    /// using Lagrange interpolation to reconstruct the full signature.
    ///
    /// # Arguments
    ///
    /// * `signature_shares` - Signature shares from participants
    /// * `participants` - The participant IDs in the same order as shares
    /// * `threshold` - The scheme threshold `t`; aggregation is rejected when
    ///   fewer than `t` shares are provided. Pass `config.threshold` from the
    ///   `ThresholdConfig`/`GroupPublicKey` used at key generation.
    ///
    /// # Returns
    ///
    /// A complete threshold signature that verifies against the group public key.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Fewer than `threshold` shares provided
    /// - Share deserialization fails
    /// - Lagrange coefficient computation fails
    pub fn aggregate(
        signature_shares: &[BlsSignatureShare],
        participants: &[ParticipantId],
        threshold: u16,
    ) -> Result<BlsThresholdSignature, ThresholdError> {
        // A threshold of at least 2 is required for a meaningful threshold
        // signature; reject degenerate configurations as well as any attempt
        // to aggregate fewer than `t` shares.
        let required = threshold.max(2);
        if (signature_shares.len() as u64) < required as u64 {
            return Err(ThresholdError::InsufficientParticipants {
                required,
                provided: signature_shares.len() as u16,
            });
        }

        if signature_shares.len() != participants.len() {
            return Err(ThresholdError::InvalidParticipant(
                "Number of shares must match number of participants".into(),
            ));
        }

        // Deserialize all signature shares
        let mut sigs: Vec<Signature> = Vec::with_capacity(signature_shares.len());
        for share in signature_shares {
            let sig = share.signature()?;
            sigs.push(sig);
        }

        // Compute Lagrange coefficients and aggregate
        // sigma = sum(lambda_i * sigma_i) for all participants
        let aggregated = Self::lagrange_interpolate_signatures(&sigs, participants)?;

        Ok(BlsThresholdSignature::new(aggregated.to_bytes().to_vec()))
    }

    /// Verify a threshold BLS signature.
    ///
    /// The resulting signature is a standard BLS signature and can be
    /// verified using standard BLS verification.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The group's public key
    /// * `message` - The message that was signed
    /// * `signature` - The threshold signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, error otherwise.
    pub fn verify(
        public_key: &GroupPublicKey,
        message: &[u8],
        signature: &BlsThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        let pk = PublicKey::from_bytes(&public_key.bytes)
            .map_err(|_| ThresholdError::InvalidPublicKey)?;

        let sig = signature.signature()?;

        // BLS verify: e(pk, H(m)) == e(G1, sig)
        let result = sig.verify(true, message, BLS_DST, &[], &pk, true);

        Ok(result == BLST_ERROR::BLST_SUCCESS)
    }

    /// Aggregate multiple BLS signatures into one.
    ///
    /// This is BLS's native signature aggregation feature - multiple signatures
    /// on different messages can be combined into a single signature that
    /// verifies against the aggregated public keys.
    ///
    /// # Arguments
    ///
    /// * `signatures` - The signatures to aggregate
    ///
    /// # Returns
    ///
    /// A single aggregated signature.
    pub fn aggregate_signatures(
        signatures: &[BlsThresholdSignature],
    ) -> Result<BlsThresholdSignature, ThresholdError> {
        if signatures.is_empty() {
            return Err(ThresholdError::AggregationFailed(
                "No signatures to aggregate".into(),
            ));
        }

        if signatures.len() == 1 {
            return Ok(signatures[0].clone());
        }

        let mut agg_sig = AggregateSignature::from_signature(&signatures[0].signature()?);

        for sig in signatures.iter().skip(1) {
            agg_sig
                .add_signature(&sig.signature()?, true)
                .map_err(|e| {
                    ThresholdError::AggregationFailed(format!("Failed to add signature: {:?}", e))
                })?;
        }

        Ok(BlsThresholdSignature::new(
            agg_sig.to_signature().to_bytes().to_vec(),
        ))
    }

    /// Aggregate multiple public keys into one.
    ///
    /// This is useful for multi-party verification where you want to verify
    /// an aggregated signature against the combined public key.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - The public keys to aggregate
    ///
    /// # Returns
    ///
    /// A single aggregated public key.
    pub fn aggregate_public_keys(
        public_keys: &[GroupPublicKey],
    ) -> Result<GroupPublicKey, ThresholdError> {
        if public_keys.is_empty() {
            return Err(ThresholdError::AggregationFailed(
                "No public keys to aggregate".into(),
            ));
        }

        if public_keys.len() == 1 {
            return Ok(public_keys[0].clone());
        }

        // Parse first public key
        let first_pk = PublicKey::from_bytes(&public_keys[0].bytes)
            .map_err(|_| ThresholdError::InvalidPublicKey)?;

        let mut agg_pk = AggregatePublicKey::from_public_key(&first_pk);

        for pk in public_keys.iter().skip(1) {
            let parsed_pk =
                PublicKey::from_bytes(&pk.bytes).map_err(|_| ThresholdError::InvalidPublicKey)?;
            agg_pk.add_public_key(&parsed_pk, true).map_err(|e| {
                ThresholdError::AggregationFailed(format!("Failed to add public key: {:?}", e))
            })?;
        }

        Ok(GroupPublicKey::new(
            agg_pk.to_public_key().to_bytes().to_vec(),
            public_keys[0].config,
            agg_pk.to_public_key().to_bytes().to_vec(),
        ))
    }

    // ========== Internal Implementation ==========

    /// Split a BLS secret key using Shamir's Secret Sharing.
    ///
    /// Creates a polynomial f(x) = s + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
    /// where s is the secret and t is the threshold. Each share is f(i) for
    /// participant i.
    fn split_secret_shamir(
        master_sk: &SecretKey,
        threshold: u16,
        total: u16,
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
        // Get the master secret as bytes
        let master_bytes = master_sk.to_bytes();

        // Generate random polynomial coefficients (a_1, a_2, ..., a_{t-1})
        // The constant term a_0 is the master secret
        let mut coefficients: Vec<[u8; 32]> = Vec::with_capacity(threshold as usize);
        coefficients.push(master_bytes);

        for _ in 1..threshold {
            let mut coef = [0u8; 32];
            OsRng.fill_bytes(&mut coef);
            coefficients.push(coef);
        }

        // Evaluate polynomial at each participant's x-coordinate (1, 2, ..., n)
        let mut shares = Vec::with_capacity(total as usize);

        for i in 1..=total {
            let share = Self::evaluate_polynomial(&coefficients, i)?;
            shares.push(share);
        }

        // Zeroize coefficients
        for coef in &mut coefficients {
            coef.zeroize();
        }

        Ok(shares)
    }

    /// Evaluate a polynomial at a given x-coordinate using blst_fr operations.
    ///
    /// Uses Horner's method for efficient evaluation:
    /// f(x) = a_0 + x*(a_1 + x*(a_2 + ... + x*a_{t-1}))
    fn evaluate_polynomial(coefficients: &[[u8; 32]], x: u16) -> Result<Vec<u8>, ThresholdError> {
        use blst::{
            blst_bendian_from_scalar, blst_fr, blst_fr_add, blst_fr_from_scalar, blst_fr_mul,
            blst_scalar, blst_scalar_from_bendian, blst_scalar_from_fr,
        };

        if coefficients.is_empty() {
            return Err(ThresholdError::CryptoError(
                "Empty polynomial coefficients".into(),
            ));
        }

        // Convert x to scalar/fr
        let mut x_bytes = [0u8; 32];
        x_bytes[30] = (x >> 8) as u8;
        x_bytes[31] = x as u8;

        let mut x_scalar = blst_scalar::default();
        let mut x_fr = blst_fr::default();
        // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from x_bytes (a [u8; 32]);
        // blst_fr_from_scalar operates on caller-owned struct references.
        unsafe {
            blst_scalar_from_bendian(&mut x_scalar, x_bytes.as_ptr());
            blst_fr_from_scalar(&mut x_fr, &x_scalar);
        }

        // Initialize result with highest coefficient (Horner's method)
        let mut result_fr = blst_fr::default();
        let mut coef_scalar = blst_scalar::default();
        // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from the last coefficient (a [u8; 32]);
        // blst_fr_from_scalar operates on caller-owned struct references.
        unsafe {
            blst_scalar_from_bendian(&mut coef_scalar, coefficients.last().unwrap().as_ptr());
            blst_fr_from_scalar(&mut result_fr, &coef_scalar);
        }

        // Horner's method: work from highest to lowest coefficient
        for coef in coefficients.iter().rev().skip(1) {
            // result = result * x + coef
            let mut temp = blst_fr::default();
            // SAFETY: blst_fr_mul reads caller-owned result_fr and x_fr and writes to caller-owned temp.
            unsafe {
                blst_fr_mul(&mut temp, &result_fr, &x_fr);
            }

            let mut coef_scalar_inner = blst_scalar::default();
            let mut coef_fr = blst_fr::default();
            // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from coef (a [u8; 32]);
            // blst_fr_from_scalar and blst_fr_add operate on caller-owned struct references.
            unsafe {
                blst_scalar_from_bendian(&mut coef_scalar_inner, coef.as_ptr());
                blst_fr_from_scalar(&mut coef_fr, &coef_scalar_inner);
                blst_fr_add(&mut result_fr, &temp, &coef_fr);
            }
        }

        // Convert result back to bytes
        let mut result_scalar = blst_scalar::default();
        // SAFETY: blst_scalar_from_fr reads caller-owned result_fr and writes to caller-owned result_scalar.
        unsafe {
            blst_scalar_from_fr(&mut result_scalar, &result_fr);
        }

        let mut result_bytes = [0u8; 32];
        // SAFETY: blst_bendian_from_scalar writes exactly 32 bytes to result_bytes (a [u8; 32]).
        unsafe {
            blst_bendian_from_scalar(result_bytes.as_mut_ptr(), &result_scalar);
        }

        Ok(result_bytes.to_vec())
    }

    /// Compute Lagrange coefficient for a participant.
    ///
    /// lambda_i = product_{j != i} (x_j / (x_j - x_i))
    fn lagrange_coefficient(
        participant: ParticipantId,
        participants: &[ParticipantId],
    ) -> Result<[u8; 32], ThresholdError> {
        use blst::{
            blst_bendian_from_scalar, blst_fr, blst_fr_from_scalar, blst_fr_inverse, blst_fr_mul,
            blst_fr_sub, blst_scalar, blst_scalar_from_bendian, blst_scalar_from_fr,
        };

        let x_i = participant.0 as u64;

        // Start with multiplicative identity (1)
        let mut numerator = blst_fr::default();
        let mut denominator = blst_fr::default();

        // Initialize to 1
        let one_bytes = {
            let mut bytes = [0u8; 32];
            bytes[31] = 1;
            bytes
        };
        let mut one_scalar = blst_scalar::default();
        // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from one_bytes (a [u8; 32]);
        // blst_fr_from_scalar operates on caller-owned struct references.
        unsafe {
            blst_scalar_from_bendian(&mut one_scalar, one_bytes.as_ptr());
            blst_fr_from_scalar(&mut numerator, &one_scalar);
            blst_fr_from_scalar(&mut denominator, &one_scalar);
        }

        for &p in participants {
            if p == participant {
                continue;
            }

            let x_j = p.0 as u64;

            // numerator *= x_j
            let mut xj_bytes = [0u8; 32];
            xj_bytes[24..32].copy_from_slice(&x_j.to_be_bytes());
            let mut xj_scalar = blst_scalar::default();
            let mut xj_fr = blst_fr::default();
            // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from xj_bytes (a [u8; 32]);
            // blst_fr_from_scalar and blst_fr_mul operate on caller-owned struct references.
            unsafe {
                blst_scalar_from_bendian(&mut xj_scalar, xj_bytes.as_ptr());
                blst_fr_from_scalar(&mut xj_fr, &xj_scalar);
                blst_fr_mul(&mut numerator, &numerator, &xj_fr);
            }

            // denominator *= (x_j - x_i)
            let mut xi_bytes = [0u8; 32];
            xi_bytes[24..32].copy_from_slice(&x_i.to_be_bytes());
            let mut xi_scalar = blst_scalar::default();
            let mut xi_fr = blst_fr::default();
            // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from xi_bytes (a [u8; 32]);
            // blst_fr_from_scalar operates on caller-owned struct references.
            unsafe {
                blst_scalar_from_bendian(&mut xi_scalar, xi_bytes.as_ptr());
                blst_fr_from_scalar(&mut xi_fr, &xi_scalar);
            }

            let mut diff = blst_fr::default();
            // SAFETY: blst_fr_sub and blst_fr_mul operate on caller-owned blst_fr struct references.
            unsafe {
                blst_fr_sub(&mut diff, &xj_fr, &xi_fr);
                blst_fr_mul(&mut denominator, &denominator, &diff);
            }
        }

        // result = numerator / denominator = numerator * inverse(denominator)
        let mut denom_inv = blst_fr::default();
        // SAFETY: blst_fr_inverse reads caller-owned denominator and writes to caller-owned denom_inv.
        unsafe {
            blst_fr_inverse(&mut denom_inv, &denominator);
        }

        let mut result_fr = blst_fr::default();
        // SAFETY: blst_fr_mul reads caller-owned numerator and denom_inv and writes to caller-owned result_fr.
        unsafe {
            blst_fr_mul(&mut result_fr, &numerator, &denom_inv);
        }

        // Convert back to scalar bytes
        let mut result_scalar = blst_scalar::default();
        // SAFETY: blst_scalar_from_fr reads caller-owned result_fr and writes to caller-owned result_scalar.
        unsafe {
            blst_scalar_from_fr(&mut result_scalar, &result_fr);
        }

        let mut result_bytes = [0u8; 32];
        // SAFETY: blst_bendian_from_scalar writes exactly 32 bytes to result_bytes (a [u8; 32]).
        unsafe {
            blst_bendian_from_scalar(result_bytes.as_mut_ptr(), &result_scalar);
        }

        Ok(result_bytes)
    }

    /// Aggregate signature shares using Lagrange interpolation.
    ///
    /// sigma = sum(lambda_i * sigma_i) for all participants
    fn lagrange_interpolate_signatures(
        signatures: &[Signature],
        participants: &[ParticipantId],
    ) -> Result<Signature, ThresholdError> {
        use blst::{
            blst_p2, blst_p2_add_or_double, blst_p2_affine, blst_p2_affine_compress,
            blst_p2_from_affine, blst_p2_mult, blst_p2_to_affine, blst_p2_uncompress, blst_scalar,
            blst_scalar_from_bendian,
        };

        if signatures.is_empty() {
            return Err(ThresholdError::AggregationFailed(
                "No signatures to aggregate".into(),
            ));
        }

        // Initialize result as the identity point (all zeros in projective)
        let mut result = blst_p2::default();

        for (i, sig) in signatures.iter().enumerate() {
            // Compute Lagrange coefficient for this participant
            let lambda_bytes = Self::lagrange_coefficient(participants[i], participants)?;

            // Get signature point (G2)
            let sig_bytes = sig.to_bytes();
            let mut sig_affine = blst_p2_affine::default();
            let mut sig_point = blst_p2::default();

            // Decompress signature to get G2 point
            // SAFETY: blst_p2_uncompress reads exactly 96 bytes from sig_bytes (sig.to_bytes() returns
            // a fixed-size compressed G2 array) and writes to caller-owned sig_affine; blst_p2_from_affine
            // converts caller-owned sig_affine into caller-owned sig_point.
            unsafe {
                let sig_affine_result = blst_p2_uncompress(&mut sig_affine, sig_bytes.as_ptr());
                if sig_affine_result != BLST_ERROR::BLST_SUCCESS {
                    return Err(ThresholdError::InvalidSignature);
                }
                blst_p2_from_affine(&mut sig_point, &sig_affine);
            }

            // Multiply signature by Lagrange coefficient: lambda_i * sigma_i
            let mut lambda_scalar = blst_scalar::default();
            // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from lambda_bytes (a [u8; 32]).
            unsafe {
                blst_scalar_from_bendian(&mut lambda_scalar, lambda_bytes.as_ptr());
            }

            let mut scaled_sig = blst_p2::default();
            // SAFETY: blst_p2_mult reads caller-owned sig_point and lambda_scalar.b (a [u8; 32] inside
            // blst_scalar, with bit-length 256 passed explicitly) and writes to caller-owned scaled_sig.
            unsafe {
                blst_p2_mult(&mut scaled_sig, &sig_point, lambda_scalar.b.as_ptr(), 256);
            }

            // Add to result
            let mut new_result = blst_p2::default();
            // SAFETY: blst_p2_add_or_double reads caller-owned result and scaled_sig and writes to
            // caller-owned new_result.
            unsafe {
                blst_p2_add_or_double(&mut new_result, &result, &scaled_sig);
            }
            result = new_result;
        }

        // Convert result back to affine and serialize
        let mut result_affine = blst_p2_affine::default();
        // SAFETY: blst_p2_to_affine reads caller-owned result and writes to caller-owned result_affine.
        unsafe {
            blst_p2_to_affine(&mut result_affine, &result);
        }

        let mut result_bytes = [0u8; 96];
        // SAFETY: blst_p2_affine_compress writes exactly 96 bytes to result_bytes (a [u8; 96]) from
        // caller-owned result_affine.
        unsafe {
            blst_p2_affine_compress(result_bytes.as_mut_ptr(), &result_affine);
        }

        Signature::from_bytes(&result_bytes).map_err(|_| {
            ThresholdError::AggregationFailed(
                "Failed to create signature from aggregated point".into(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_dealer_keygen_2_of_3() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        assert_eq!(shares.len(), 3);
        assert_eq!(group_key.bytes.len(), 48); // BLS public key is 48 bytes compressed G1
        assert_eq!(group_key.config.threshold, 2);
        assert_eq!(group_key.config.total_participants, 3);

        // Each share should have valid structure
        for share in &shares {
            assert_eq!(share.config.threshold, 2);
            assert_eq!(share.config.total_participants, 3);
            assert_eq!(share.secret_share_bytes().len(), 32);
            assert_eq!(share.public_share.len(), 48);
            assert_eq!(share.group_public_key.len(), 48);
        }
    }

    #[test]
    fn test_trusted_dealer_keygen_3_of_5() {
        let config = ThresholdConfig::new(3, 5).unwrap();
        let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        assert_eq!(shares.len(), 5);
        assert_eq!(group_key.config.threshold, 3);
        assert_eq!(group_key.config.total_participants, 5);
    }

    #[test]
    fn test_bls_sign_share() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (_, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Test message for BLS signing";
        let sig_share = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();

        assert_eq!(sig_share.participant_id, shares[0].participant_id);
        assert_eq!(sig_share.share.len(), 96); // BLS signature is 96 bytes compressed G2
    }

    #[test]
    fn test_full_signing_flow_2_of_3() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Test message for threshold BLS signing";

        // Sign with participants 1 and 2 (indices 0 and 1)
        let sig_share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let sig_share2 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();

        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        // Aggregate signature shares
        let signature = ThresholdBlsEngine::aggregate(
            &[sig_share1, sig_share2],
            &participants,
            config.threshold,
        )
        .unwrap();

        // Verify the signature
        let valid = ThresholdBlsEngine::verify(&group_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_full_signing_flow_3_of_5() {
        let config = ThresholdConfig::new(3, 5).unwrap();
        let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Another test message";

        // Use participants 1, 3, and 5 (indices 0, 2, 4)
        let selected_indices = [0, 2, 4];

        let mut sig_shares = Vec::new();
        let mut participants = Vec::new();

        for &idx in &selected_indices {
            let sig_share = ThresholdBlsEngine::sign_share(&shares[idx], message).unwrap();
            sig_shares.push(sig_share);
            participants.push(shares[idx].participant_id);
        }

        // Aggregate and verify
        let signature =
            ThresholdBlsEngine::aggregate(&sig_shares, &participants, config.threshold).unwrap();
        let valid = ThresholdBlsEngine::verify(&group_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_different_participant_subsets_produce_valid_signatures() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Test message";

        // Sign with participants 1 and 2
        let sig_share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let sig_share2 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
        let participants_12 = vec![shares[0].participant_id, shares[1].participant_id];
        let signature_12 = ThresholdBlsEngine::aggregate(
            &[sig_share1, sig_share2],
            &participants_12,
            config.threshold,
        )
        .unwrap();

        // Sign with participants 2 and 3
        let sig_share2b = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
        let sig_share3 = ThresholdBlsEngine::sign_share(&shares[2], message).unwrap();
        let participants_23 = vec![shares[1].participant_id, shares[2].participant_id];
        let signature_23 = ThresholdBlsEngine::aggregate(
            &[sig_share2b, sig_share3],
            &participants_23,
            config.threshold,
        )
        .unwrap();

        // Both signatures should verify
        assert!(ThresholdBlsEngine::verify(&group_key, message, &signature_12).unwrap());
        assert!(ThresholdBlsEngine::verify(&group_key, message, &signature_23).unwrap());

        // Both signatures should be the same (deterministic)
        assert_eq!(signature_12.bytes, signature_23.bytes);
    }

    #[test]
    fn test_insufficient_participants_fails() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (_, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Test message";

        // Only get one signature share (need 2)
        let sig_share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let participants = vec![shares[0].participant_id];

        // Try to aggregate with only 1 share - should fail
        let result = ThresholdBlsEngine::aggregate(&[sig_share1], &participants, config.threshold);
        assert!(matches!(
            result,
            Err(ThresholdError::InsufficientParticipants { .. })
        ));
    }

    #[test]
    fn test_verification_fails_for_wrong_message() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Original message";
        let wrong_message = b"Different message";

        // Generate valid signature for original message
        let sig_share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let sig_share2 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        let signature = ThresholdBlsEngine::aggregate(
            &[sig_share1, sig_share2],
            &participants,
            config.threshold,
        )
        .unwrap();

        // Verify with wrong message should fail
        let result = ThresholdBlsEngine::verify(&group_key, wrong_message, &signature).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_aggregate_signatures() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (_, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message1 = b"Message 1";
        let message2 = b"Message 2";

        // Create two complete threshold signatures
        let sig_share1_1 = ThresholdBlsEngine::sign_share(&shares[0], message1).unwrap();
        let sig_share1_2 = ThresholdBlsEngine::sign_share(&shares[1], message1).unwrap();
        let participants = vec![shares[0].participant_id, shares[1].participant_id];
        let signature1 = ThresholdBlsEngine::aggregate(
            &[sig_share1_1, sig_share1_2],
            &participants,
            config.threshold,
        )
        .unwrap();

        let sig_share2_1 = ThresholdBlsEngine::sign_share(&shares[0], message2).unwrap();
        let sig_share2_2 = ThresholdBlsEngine::sign_share(&shares[1], message2).unwrap();
        let signature2 = ThresholdBlsEngine::aggregate(
            &[sig_share2_1, sig_share2_2],
            &participants,
            config.threshold,
        )
        .unwrap();

        // Aggregate the two signatures
        let aggregated =
            ThresholdBlsEngine::aggregate_signatures(&[signature1.clone(), signature2.clone()])
                .unwrap();

        // The aggregated signature should be valid (though verifying aggregated BLS signatures
        // requires multi-verify which we don't implement here, so we just check it doesn't error)
        assert_eq!(aggregated.bytes.len(), 96);
    }

    #[test]
    fn test_aggregate_public_keys() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key1, _) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();
        let (group_key2, _) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        // Aggregate the two public keys
        let aggregated =
            ThresholdBlsEngine::aggregate_public_keys(&[group_key1.clone(), group_key2.clone()])
                .unwrap();

        // Should produce a valid 48-byte public key
        assert_eq!(aggregated.bytes.len(), 48);
    }

    #[test]
    fn test_lagrange_coefficient_computation() {
        // Test that Lagrange interpolation is correct by verifying
        // that the polynomial evaluates to 1 at the identity
        let participants = vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)];

        // Just verify that the coefficients don't error
        for p in &participants {
            let coef = ThresholdBlsEngine::lagrange_coefficient(*p, &participants);
            assert!(coef.is_ok());
        }
    }

    #[test]
    fn test_polynomial_evaluation() {
        // Simple test: polynomial with just constant term should return that constant
        let mut coef_with_value = [[0u8; 32]; 1];
        coef_with_value[0][31] = 42;

        let result = ThresholdBlsEngine::evaluate_polynomial(&coef_with_value, 5).unwrap();
        assert_eq!(result[31], 42);
    }

    #[test]
    fn test_sign_share_deterministic() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (_, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Test message";

        // Sign the same message twice with the same share
        let sig1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let sig2 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();

        // BLS signatures are deterministic
        assert_eq!(sig1.share, sig2.share);
    }

    #[test]
    fn test_key_share_zeroize_on_drop() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (_, mut shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        // Get a reference to the secret bytes before zeroizing
        let secret_len = shares[0].secret_share_bytes().len();
        assert!(secret_len > 0);

        // Manually zeroize
        shares[0].zeroize();

        // Verify the secret is zeroized
        assert!(shares[0].secret_share_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_all_participants_sign() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Test with all participants";

        // All 3 participants sign
        let sig_shares: Vec<_> = shares
            .iter()
            .map(|s| ThresholdBlsEngine::sign_share(s, message).unwrap())
            .collect();

        let participants: Vec<_> = shares.iter().map(|s| s.participant_id).collect();

        // Aggregate all 3 shares
        let signature =
            ThresholdBlsEngine::aggregate(&sig_shares, &participants, config.threshold).unwrap();

        // Should still verify
        assert!(ThresholdBlsEngine::verify(&group_key, message, &signature).unwrap());
    }

    #[test]
    fn test_sign_with_participants_1_and_3() {
        // Test with non-consecutive participants to ensure Lagrange interpolation works correctly
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"Test with participants 1 and 3";

        // Sign with participants 1 and 3 (indices 0 and 2)
        let sig_share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let sig_share3 = ThresholdBlsEngine::sign_share(&shares[2], message).unwrap();

        let participants = vec![shares[0].participant_id, shares[2].participant_id];
        let signature = ThresholdBlsEngine::aggregate(
            &[sig_share1, sig_share3],
            &participants,
            config.threshold,
        )
        .unwrap();

        // Should verify
        assert!(ThresholdBlsEngine::verify(&group_key, message, &signature).unwrap());
    }

    #[test]
    fn test_empty_message() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"";

        let sig_share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let sig_share2 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();

        let participants = vec![shares[0].participant_id, shares[1].participant_id];
        let signature = ThresholdBlsEngine::aggregate(
            &[sig_share1, sig_share2],
            &participants,
            config.threshold,
        )
        .unwrap();

        assert!(ThresholdBlsEngine::verify(&group_key, message, &signature).unwrap());
    }

    #[test]
    fn test_large_message() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        // 10KB message
        let message = vec![0xABu8; 10_000];

        let sig_share1 = ThresholdBlsEngine::sign_share(&shares[0], &message).unwrap();
        let sig_share2 = ThresholdBlsEngine::sign_share(&shares[1], &message).unwrap();

        let participants = vec![shares[0].participant_id, shares[1].participant_id];
        let signature = ThresholdBlsEngine::aggregate(
            &[sig_share1, sig_share2],
            &participants,
            config.threshold,
        )
        .unwrap();

        assert!(ThresholdBlsEngine::verify(&group_key, &message, &signature).unwrap());
    }

    /// Aggregation with fewer than `t` shares must be rejected for a t > 2 scheme.
    ///
    /// This is a NEGATIVE test for finding #24: the previous implementation
    /// hardcoded the minimum at 2, so a 3-of-5 scheme would happily aggregate
    /// only 2 shares (producing a signature that does not verify against the
    /// group key, since Lagrange interpolation over an insufficient subset is
    /// wrong). It now must fail closed.
    #[test]
    fn test_aggregate_below_threshold_rejected_for_t_greater_than_2() {
        let config = ThresholdConfig::new(3, 5).unwrap();
        let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"below threshold must be rejected";

        // Only 2 signature shares for a 3-of-5 scheme.
        let sig_share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let sig_share2 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        let result = ThresholdBlsEngine::aggregate(
            &[sig_share1, sig_share2],
            &participants,
            config.threshold,
        );

        match result {
            Err(ThresholdError::InsufficientParticipants { required, provided }) => {
                assert_eq!(required, 3, "must require the scheme threshold t=3, not 2");
                assert_eq!(provided, 2);
            }
            other => panic!("expected InsufficientParticipants {{ required: 3 }}, got {other:?}"),
        }

        // Exactly t=3 shares must succeed and verify.
        let s1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let s2 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
        let s3 = ThresholdBlsEngine::sign_share(&shares[2], message).unwrap();
        let parts = vec![
            shares[0].participant_id,
            shares[1].participant_id,
            shares[2].participant_id,
        ];
        let sig = ThresholdBlsEngine::aggregate(&[s1, s2, s3], &parts, config.threshold).unwrap();
        assert!(ThresholdBlsEngine::verify(&group_key, message, &sig).unwrap());
    }
}
