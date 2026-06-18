//! secp256k1 curve operations for threshold ECDSA
//!
//! This module implements the cryptographic primitives needed for threshold
//! ECDSA on the secp256k1 curve, which is used by Bitcoin and Ethereum.
//!
//! # Note on FIPS Compliance
//!
//! secp256k1 is NOT a FIPS 140-3 approved curve. Use P-256 for FIPS compliance.
//!
//! # Operations
//!
//! - Shamir secret sharing over the secp256k1 scalar field
//! - Lagrange coefficient computation
//! - Point and scalar arithmetic
//!
//! # Security
//!
//! All scalar operations use constant-time implementations from the `k256` crate.
//! Secrets are zeroized after use.

use crate::threshold::types::{ParticipantId, ThresholdError};
use k256::{
    elliptic_curve::{
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field,
    },
    AffinePoint, ProjectivePoint, Scalar, U256,
};
use rand_core::OsRng;
use zeroize::Zeroize;

/// secp256k1 threshold operations.
pub struct Secp256k1ThresholdOps;

impl Secp256k1ThresholdOps {
    /// Generate a random scalar.
    pub fn random_scalar() -> Scalar {
        Scalar::random(&mut OsRng)
    }

    /// Split a secret using Shamir's Secret Sharing over the secp256k1 scalar field.
    ///
    /// Generates a random polynomial of degree (threshold - 1) with the secret
    /// as the constant term, then evaluates it at points 1, 2, ..., total.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret scalar to split
    /// * `threshold` - Minimum shares needed to reconstruct (t)
    /// * `total` - Total number of shares to generate (n)
    ///
    /// # Returns
    ///
    /// A vector of (participant_id, share) pairs.
    pub fn split_secret(
        secret: &Scalar,
        threshold: u16,
        total: u16,
    ) -> Result<Vec<(u16, Scalar)>, ThresholdError> {
        if threshold == 0 || threshold > total {
            return Err(ThresholdError::InvalidThreshold(format!(
                "Invalid threshold: {} of {}",
                threshold, total
            )));
        }

        // Generate random polynomial coefficients: f(x) = secret + a_1*x + a_2*x^2 + ...
        let mut coefficients = vec![*secret];
        for _ in 1..threshold {
            coefficients.push(Self::random_scalar());
        }

        // Evaluate polynomial at each participant's x-coordinate (1, 2, ..., n)
        let shares: Vec<(u16, Scalar)> = (1..=total)
            .map(|i| {
                let x = Scalar::from(i as u64);
                let y = Self::evaluate_polynomial(&coefficients, &x);
                (i, y)
            })
            .collect();

        // Zeroize coefficients
        for mut coeff in coefficients {
            coeff.zeroize();
        }

        Ok(shares)
    }

    /// Evaluate a polynomial at a given point.
    ///
    /// Uses Horner's method: f(x) = a_0 + x(a_1 + x(a_2 + ...))
    fn evaluate_polynomial(coefficients: &[Scalar], x: &Scalar) -> Scalar {
        let mut result = Scalar::ZERO;
        for coeff in coefficients.iter().rev() {
            result = result * x + coeff;
        }
        result
    }

    /// Compute the Lagrange coefficient for a participant.
    ///
    /// lambda_i = product_{j != i} (x_j / (x_j - x_i))
    ///
    /// where x_i is the participant's ID treated as a scalar.
    pub fn lagrange_coefficient(
        participant: ParticipantId,
        participants: &[ParticipantId],
    ) -> Scalar {
        let x_i = Scalar::from(participant.0 as u64);
        let mut result = Scalar::ONE;

        for &p in participants {
            if p != participant {
                let x_j = Scalar::from(p.0 as u64);
                // lambda_i *= x_j / (x_j - x_i)
                let num = x_j;
                let denom = x_j - x_i;
                // Note: denom should never be zero if participants are unique
                let denom_inv = denom.invert().unwrap_or(Scalar::ONE);
                result *= num * denom_inv;
            }
        }

        result
    }

    /// Compute the public key point from a scalar.
    pub fn scalar_to_point(scalar: &Scalar) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * scalar
    }

    /// Compress a projective point to bytes.
    pub fn point_to_bytes(point: &ProjectivePoint) -> Vec<u8> {
        point.to_affine().to_encoded_point(true).as_bytes().to_vec()
    }

    /// Decompress a point from bytes.
    pub fn point_from_bytes(bytes: &[u8]) -> Result<ProjectivePoint, ThresholdError> {
        let encoded = k256::EncodedPoint::from_bytes(bytes)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        let affine = AffinePoint::from_encoded_point(&encoded);
        if affine.is_some().into() {
            Ok(ProjectivePoint::from(affine.unwrap()))
        } else {
            Err(ThresholdError::InvalidPublicKey)
        }
    }

    /// Serialize a scalar to bytes.
    pub fn scalar_to_bytes(scalar: &Scalar) -> Vec<u8> {
        scalar.to_bytes().to_vec()
    }

    /// Deserialize a scalar from bytes.
    pub fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar, ThresholdError> {
        if bytes.len() != 32 {
            return Err(ThresholdError::SerializationError(format!(
                "Invalid scalar length: expected 32, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);

        // Use reduce to handle potential out-of-range values
        let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&arr.into());
        Ok(scalar)
    }

    /// Reconstruct a secret from shares using Lagrange interpolation.
    ///
    /// Computes f(0) = sum_i (y_i * lambda_i)
    pub fn reconstruct_secret(shares: &[(ParticipantId, Scalar)]) -> Scalar {
        let participants: Vec<ParticipantId> = shares.iter().map(|(id, _)| *id).collect();

        let mut result = Scalar::ZERO;
        for (id, share) in shares {
            let lambda = Self::lagrange_coefficient(*id, &participants);
            result += *share * lambda;
        }

        result
    }

    /// Verify that a share is consistent with a public commitment.
    ///
    /// Checks that share * G equals the expected point derived from commitments.
    pub fn verify_share(
        participant_id: ParticipantId,
        share: &Scalar,
        commitments: &[ProjectivePoint],
    ) -> bool {
        // Compute expected: sum_j (C_j * i^j) where i is participant ID
        let x = Scalar::from(participant_id.0 as u64);
        let mut expected = ProjectivePoint::IDENTITY;
        let mut x_pow = Scalar::ONE;

        for commitment in commitments {
            expected += *commitment * x_pow;
            x_pow *= x;
        }

        // Verify: share * G == expected
        let actual = ProjectivePoint::GENERATOR * share;
        actual == expected
    }

    /// Get the x-coordinate of a point as a scalar (for ECDSA r value).
    pub fn point_x_coordinate(point: &ProjectivePoint) -> Scalar {
        let affine = point.to_affine();
        // Use the EncodedPoint to get coordinates
        let encoded = affine.to_encoded_point(false);
        let x_bytes = encoded.x().expect("point is not identity");
        <Scalar as Reduce<U256>>::reduce_bytes(x_bytes)
    }

    /// Compute the additive inverse (negation) of a scalar.
    pub fn negate_scalar(scalar: &Scalar) -> Scalar {
        -scalar
    }

    /// Compute the multiplicative inverse of a scalar.
    pub fn invert_scalar(scalar: &Scalar) -> Option<Scalar> {
        let inv = scalar.invert();
        if inv.is_some().into() {
            Some(inv.unwrap())
        } else {
            None
        }
    }

    /// Normalize s value for Bitcoin/Ethereum (low-S signature malleability fix).
    ///
    /// If s > n/2, return n - s instead. This ensures signatures are canonical.
    pub fn normalize_s(s: &Scalar) -> Scalar {
        // secp256k1 order / 2
        // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        // n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        let half_n_bytes: [u8; 32] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46,
            0x68, 0x1B, 0x20, 0xA0,
        ];

        let s_bytes = s.to_bytes();
        let s_high = s_bytes.as_slice() > &half_n_bytes;

        if s_high {
            -s
        } else {
            *s
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reconstruct_2_of_3() {
        let secret = Secp256k1ThresholdOps::random_scalar();

        // Split into 3 shares with threshold 2
        let shares = Secp256k1ThresholdOps::split_secret(&secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // Reconstruct using first 2 shares
        let subset: Vec<(ParticipantId, Scalar)> = shares[0..2]
            .iter()
            .map(|(id, s)| (ParticipantId(*id), *s))
            .collect();

        let reconstructed = Secp256k1ThresholdOps::reconstruct_secret(&subset);
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_split_and_reconstruct_3_of_5() {
        let secret = Secp256k1ThresholdOps::random_scalar();

        let shares = Secp256k1ThresholdOps::split_secret(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Reconstruct using shares 1, 3, 5 (non-consecutive)
        let subset: Vec<(ParticipantId, Scalar)> = vec![
            (ParticipantId(shares[0].0), shares[0].1),
            (ParticipantId(shares[2].0), shares[2].1),
            (ParticipantId(shares[4].0), shares[4].1),
        ];

        let reconstructed = Secp256k1ThresholdOps::reconstruct_secret(&subset);
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_lagrange_coefficients_sum_to_one() {
        let participants = vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)];

        let mut sum = Scalar::ZERO;
        for &p in &participants {
            sum += Secp256k1ThresholdOps::lagrange_coefficient(p, &participants);
        }

        // At x=0, sum of Lagrange coefficients should equal 1
        assert_eq!(sum, Scalar::ONE);
    }

    #[test]
    fn test_scalar_point_roundtrip() {
        let scalar = Secp256k1ThresholdOps::random_scalar();
        let point = Secp256k1ThresholdOps::scalar_to_point(&scalar);
        let bytes = Secp256k1ThresholdOps::point_to_bytes(&point);
        let recovered = Secp256k1ThresholdOps::point_from_bytes(&bytes).unwrap();

        assert_eq!(point, recovered);
    }

    #[test]
    fn test_scalar_serialization_roundtrip() {
        let scalar = Secp256k1ThresholdOps::random_scalar();
        let bytes = Secp256k1ThresholdOps::scalar_to_bytes(&scalar);
        assert_eq!(bytes.len(), 32);

        let recovered = Secp256k1ThresholdOps::scalar_from_bytes(&bytes).unwrap();
        assert_eq!(scalar, recovered);
    }

    #[test]
    fn test_invalid_threshold_config() {
        let secret = Secp256k1ThresholdOps::random_scalar();

        // Threshold > total should fail
        let result = Secp256k1ThresholdOps::split_secret(&secret, 4, 3);
        assert!(result.is_err());

        // Threshold 0 should fail
        let result = Secp256k1ThresholdOps::split_secret(&secret, 0, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_scalar_inversion() {
        let scalar = Secp256k1ThresholdOps::random_scalar();
        let inv = Secp256k1ThresholdOps::invert_scalar(&scalar).unwrap();

        // scalar * inv should equal 1
        assert_eq!(scalar * inv, Scalar::ONE);
    }

    #[test]
    fn test_point_x_coordinate() {
        let scalar = Secp256k1ThresholdOps::random_scalar();
        let point = Secp256k1ThresholdOps::scalar_to_point(&scalar);
        let x = Secp256k1ThresholdOps::point_x_coordinate(&point);

        // x should be non-zero for random points
        assert_ne!(x, Scalar::ZERO);
    }

    #[test]
    fn test_normalize_s_is_idempotent() {
        let s = Secp256k1ThresholdOps::random_scalar();
        let normalized = Secp256k1ThresholdOps::normalize_s(&s);
        let normalized_again = Secp256k1ThresholdOps::normalize_s(&normalized);

        // Normalizing twice should give the same result
        assert_eq!(normalized, normalized_again);
    }

    #[test]
    fn test_share_verification() {
        let secret = Secp256k1ThresholdOps::random_scalar();

        // Create polynomial with random coefficients
        let a1 = Secp256k1ThresholdOps::random_scalar();
        let coefficients = [secret, a1];

        // Compute commitments (C_j = a_j * G)
        let commitments: Vec<ProjectivePoint> = coefficients
            .iter()
            .map(|c| ProjectivePoint::GENERATOR * c)
            .collect();

        // Evaluate polynomial at x=1 to get share
        let share = secret + a1;

        // Verify the share
        assert!(Secp256k1ThresholdOps::verify_share(
            ParticipantId(1),
            &share,
            &commitments
        ));

        // Wrong share should fail
        let wrong_share = share + Scalar::ONE;
        assert!(!Secp256k1ThresholdOps::verify_share(
            ParticipantId(1),
            &wrong_share,
            &commitments
        ));
    }

    #[test]
    fn test_different_participant_subsets_reconstruct_same_secret() {
        let secret = Secp256k1ThresholdOps::random_scalar();
        let shares = Secp256k1ThresholdOps::split_secret(&secret, 2, 4).unwrap();

        // Try all 2-combinations
        let pairs = vec![
            vec![(0, 1), (0, 2), (0, 3)],
            vec![(1, 2), (1, 3)],
            vec![(2, 3)],
        ];

        for pair_group in pairs {
            for (i, j) in pair_group {
                let subset: Vec<(ParticipantId, Scalar)> = vec![
                    (ParticipantId(shares[i].0), shares[i].1),
                    (ParticipantId(shares[j].0), shares[j].1),
                ];
                let reconstructed = Secp256k1ThresholdOps::reconstruct_secret(&subset);
                assert_eq!(reconstructed, secret);
            }
        }
    }
}
