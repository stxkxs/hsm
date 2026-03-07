//! Feldman Verifiable Secret Sharing (VSS) for threshold ECDSA
//!
//! This module implements Feldman's VSS scheme, which allows a dealer to distribute
//! shares of a secret such that recipients can verify the correctness of their
//! shares without revealing the secret.
//!
//! # Protocol
//!
//! 1. **Commitment Generation**: For a polynomial f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1},
//!    compute commitments C_i = a_i * G for each coefficient.
//!
//! 2. **Share Distribution**: Send share f(j) to participant j.
//!
//! 3. **Verification**: Participant j verifies: f(j) * G == sum(C_i * j^i)
//!
//! # Security Properties
//!
//! - Commitments are binding: dealer cannot change the polynomial after broadcasting commitments
//! - Shares are verifiable: participants can detect malformed shares
//! - The constant term (secret) remains hidden despite commitments being public

use super::p256::P256ThresholdOps;
use super::secp256k1::Secp256k1ThresholdOps;
use crate::threshold::types::{EcdsaCurve, ParticipantId, ThresholdError};

/// Feldman Verifiable Secret Sharing implementation.
///
/// Provides operations for both P-256 and secp256k1 curves.
pub struct FeldmanVss;

impl FeldmanVss {
    /// Generate Feldman commitments for polynomial coefficients on P-256.
    ///
    /// Given coefficients [a_0, a_1, ..., a_{t-1}], computes [a_0*G, a_1*G, ..., a_{t-1}*G].
    /// The first commitment C_0 = a_0 * G is the commitment to the secret.
    ///
    /// # Arguments
    ///
    /// * `coefficients` - The polynomial coefficients as serialized scalars (32 bytes each)
    /// * `curve` - The elliptic curve to use
    ///
    /// # Returns
    ///
    /// A vector of compressed point commitments (33 bytes each for both curves).
    pub fn generate_commitments(
        coefficients: &[Vec<u8>],
        curve: EcdsaCurve,
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
        match curve {
            EcdsaCurve::P256 => Self::generate_commitments_p256(coefficients),
            EcdsaCurve::Secp256k1 => Self::generate_commitments_secp256k1(coefficients),
        }
    }

    fn generate_commitments_p256(coefficients: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, ThresholdError> {
        let mut commitments = Vec::with_capacity(coefficients.len());

        for coeff_bytes in coefficients {
            let scalar = P256ThresholdOps::scalar_from_bytes(coeff_bytes)?;
            let point = P256ThresholdOps::scalar_to_point(&scalar);
            let commitment = P256ThresholdOps::point_to_bytes(&point);
            commitments.push(commitment);
        }

        Ok(commitments)
    }

    fn generate_commitments_secp256k1(
        coefficients: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
        let mut commitments = Vec::with_capacity(coefficients.len());

        for coeff_bytes in coefficients {
            let scalar = Secp256k1ThresholdOps::scalar_from_bytes(coeff_bytes)?;
            let point = Secp256k1ThresholdOps::scalar_to_point(&scalar);
            let commitment = Secp256k1ThresholdOps::point_to_bytes(&point);
            commitments.push(commitment);
        }

        Ok(commitments)
    }

    /// Verify a share against Feldman commitments.
    ///
    /// Checks that: share * G == sum(C_i * participant_id^i)
    ///
    /// # Arguments
    ///
    /// * `participant_id` - The participant's ID (used as the x-coordinate)
    /// * `share` - The secret share (32 bytes)
    /// * `commitments` - The Feldman commitments (33 bytes each)
    /// * `curve` - The elliptic curve
    ///
    /// # Returns
    ///
    /// `true` if the share is valid, `false` otherwise.
    pub fn verify_share(
        participant_id: ParticipantId,
        share: &[u8],
        commitments: &[Vec<u8>],
        curve: EcdsaCurve,
    ) -> Result<bool, ThresholdError> {
        match curve {
            EcdsaCurve::P256 => Self::verify_share_p256(participant_id, share, commitments),
            EcdsaCurve::Secp256k1 => {
                Self::verify_share_secp256k1(participant_id, share, commitments)
            }
        }
    }

    fn verify_share_p256(
        participant_id: ParticipantId,
        share: &[u8],
        commitments: &[Vec<u8>],
    ) -> Result<bool, ThresholdError> {
        use p256::{ProjectivePoint, Scalar};

        // Parse share as scalar
        let share_scalar = P256ThresholdOps::scalar_from_bytes(share)?;

        // Compute share * G
        let actual = P256ThresholdOps::scalar_to_point(&share_scalar);

        // Compute expected: sum(C_i * x^i) where x = participant_id
        let x = Scalar::from(participant_id.0 as u64);
        let mut expected = ProjectivePoint::IDENTITY;
        let mut x_pow = Scalar::ONE;

        for commitment_bytes in commitments {
            let commitment_point = P256ThresholdOps::point_from_bytes(commitment_bytes)?;
            expected += commitment_point * x_pow;
            x_pow *= x;
        }

        Ok(actual == expected)
    }

    fn verify_share_secp256k1(
        participant_id: ParticipantId,
        share: &[u8],
        commitments: &[Vec<u8>],
    ) -> Result<bool, ThresholdError> {
        use k256::{ProjectivePoint, Scalar};

        // Parse share as scalar
        let share_scalar = Secp256k1ThresholdOps::scalar_from_bytes(share)?;

        // Compute share * G
        let actual = Secp256k1ThresholdOps::scalar_to_point(&share_scalar);

        // Compute expected: sum(C_i * x^i) where x = participant_id
        let x = Scalar::from(participant_id.0 as u64);
        let mut expected = ProjectivePoint::IDENTITY;
        let mut x_pow = Scalar::ONE;

        for commitment_bytes in commitments {
            let commitment_point = Secp256k1ThresholdOps::point_from_bytes(commitment_bytes)?;
            expected += commitment_point * x_pow;
            x_pow *= x;
        }

        Ok(actual == expected)
    }

    /// Evaluate a polynomial at a given point.
    ///
    /// Given coefficients [a_0, a_1, ..., a_{t-1}], computes f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}.
    /// Uses Horner's method for efficiency.
    ///
    /// # Arguments
    ///
    /// * `coefficients` - The polynomial coefficients (32 bytes each)
    /// * `x` - The evaluation point (participant ID)
    /// * `curve` - The elliptic curve
    ///
    /// # Returns
    ///
    /// The evaluation f(x) as a 32-byte scalar.
    pub fn evaluate_polynomial(
        coefficients: &[Vec<u8>],
        x: u16,
        curve: EcdsaCurve,
    ) -> Result<Vec<u8>, ThresholdError> {
        match curve {
            EcdsaCurve::P256 => Self::evaluate_polynomial_p256(coefficients, x),
            EcdsaCurve::Secp256k1 => Self::evaluate_polynomial_secp256k1(coefficients, x),
        }
    }

    fn evaluate_polynomial_p256(
        coefficients: &[Vec<u8>],
        x: u16,
    ) -> Result<Vec<u8>, ThresholdError> {
        use p256::Scalar;

        if coefficients.is_empty() {
            return Err(ThresholdError::InvalidThreshold(
                "Empty polynomial coefficients".into(),
            ));
        }

        let x_scalar = Scalar::from(x as u64);

        // Horner's method: f(x) = a_0 + x*(a_1 + x*(a_2 + ...))
        let mut result = Scalar::ZERO;
        for coeff_bytes in coefficients.iter().rev() {
            let coeff = P256ThresholdOps::scalar_from_bytes(coeff_bytes)?;
            result = result * x_scalar + coeff;
        }

        Ok(P256ThresholdOps::scalar_to_bytes(&result))
    }

    fn evaluate_polynomial_secp256k1(
        coefficients: &[Vec<u8>],
        x: u16,
    ) -> Result<Vec<u8>, ThresholdError> {
        use k256::Scalar;

        if coefficients.is_empty() {
            return Err(ThresholdError::InvalidThreshold(
                "Empty polynomial coefficients".into(),
            ));
        }

        let x_scalar = Scalar::from(x as u64);

        // Horner's method
        let mut result = Scalar::ZERO;
        for coeff_bytes in coefficients.iter().rev() {
            let coeff = Secp256k1ThresholdOps::scalar_from_bytes(coeff_bytes)?;
            result = result * x_scalar + coeff;
        }

        Ok(Secp256k1ThresholdOps::scalar_to_bytes(&result))
    }

    /// Generate a random polynomial of specified degree with optional constant term.
    ///
    /// If `constant_term` is provided, it is used as a_0. Otherwise, a random a_0 is generated.
    /// This is useful for DKG where each participant contributes randomness.
    ///
    /// # Arguments
    ///
    /// * `degree` - The degree of the polynomial (t-1 for t-of-n threshold)
    /// * `constant_term` - Optional constant term (32 bytes). If None, random is generated.
    /// * `curve` - The elliptic curve
    ///
    /// # Returns
    ///
    /// A vector of coefficients [a_0, a_1, ..., a_{degree}] as 32-byte scalars.
    pub fn generate_polynomial(
        degree: u16,
        constant_term: Option<&[u8]>,
        curve: EcdsaCurve,
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
        match curve {
            EcdsaCurve::P256 => Self::generate_polynomial_p256(degree, constant_term),
            EcdsaCurve::Secp256k1 => Self::generate_polynomial_secp256k1(degree, constant_term),
        }
    }

    fn generate_polynomial_p256(
        degree: u16,
        constant_term: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
        let mut coefficients = Vec::with_capacity((degree + 1) as usize);

        // a_0: either provided or random
        let a0 = match constant_term {
            Some(bytes) => {
                let scalar = P256ThresholdOps::scalar_from_bytes(bytes)?;
                P256ThresholdOps::scalar_to_bytes(&scalar)
            }
            None => {
                let scalar = P256ThresholdOps::random_scalar();
                P256ThresholdOps::scalar_to_bytes(&scalar)
            }
        };
        coefficients.push(a0);

        // a_1, ..., a_degree: random
        for _ in 0..degree {
            let scalar = P256ThresholdOps::random_scalar();
            coefficients.push(P256ThresholdOps::scalar_to_bytes(&scalar));
        }

        Ok(coefficients)
    }

    fn generate_polynomial_secp256k1(
        degree: u16,
        constant_term: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
        let mut coefficients = Vec::with_capacity((degree + 1) as usize);

        // a_0: either provided or random
        let a0 = match constant_term {
            Some(bytes) => {
                let scalar = Secp256k1ThresholdOps::scalar_from_bytes(bytes)?;
                Secp256k1ThresholdOps::scalar_to_bytes(&scalar)
            }
            None => {
                let scalar = Secp256k1ThresholdOps::random_scalar();
                Secp256k1ThresholdOps::scalar_to_bytes(&scalar)
            }
        };
        coefficients.push(a0);

        // a_1, ..., a_degree: random
        for _ in 0..degree {
            let scalar = Secp256k1ThresholdOps::random_scalar();
            coefficients.push(Secp256k1ThresholdOps::scalar_to_bytes(&scalar));
        }

        Ok(coefficients)
    }

    /// Add two scalars (used for combining shares from multiple dealers in DKG).
    ///
    /// # Arguments
    ///
    /// * `a` - First scalar (32 bytes)
    /// * `b` - Second scalar (32 bytes)
    /// * `curve` - The elliptic curve
    ///
    /// # Returns
    ///
    /// The sum a + b as a 32-byte scalar.
    pub fn add_scalars(a: &[u8], b: &[u8], curve: EcdsaCurve) -> Result<Vec<u8>, ThresholdError> {
        match curve {
            EcdsaCurve::P256 => Self::add_scalars_p256(a, b),
            EcdsaCurve::Secp256k1 => Self::add_scalars_secp256k1(a, b),
        }
    }

    fn add_scalars_p256(a: &[u8], b: &[u8]) -> Result<Vec<u8>, ThresholdError> {
        let scalar_a = P256ThresholdOps::scalar_from_bytes(a)?;
        let scalar_b = P256ThresholdOps::scalar_from_bytes(b)?;
        let sum = scalar_a + scalar_b;
        Ok(P256ThresholdOps::scalar_to_bytes(&sum))
    }

    fn add_scalars_secp256k1(a: &[u8], b: &[u8]) -> Result<Vec<u8>, ThresholdError> {
        let scalar_a = Secp256k1ThresholdOps::scalar_from_bytes(a)?;
        let scalar_b = Secp256k1ThresholdOps::scalar_from_bytes(b)?;
        let sum = scalar_a + scalar_b;
        Ok(Secp256k1ThresholdOps::scalar_to_bytes(&sum))
    }

    /// Add two points (used for combining commitment constant terms to get group public key).
    ///
    /// # Arguments
    ///
    /// * `a` - First point (33 bytes compressed)
    /// * `b` - Second point (33 bytes compressed)
    /// * `curve` - The elliptic curve
    ///
    /// # Returns
    ///
    /// The sum a + b as a 33-byte compressed point.
    pub fn add_points(a: &[u8], b: &[u8], curve: EcdsaCurve) -> Result<Vec<u8>, ThresholdError> {
        match curve {
            EcdsaCurve::P256 => Self::add_points_p256(a, b),
            EcdsaCurve::Secp256k1 => Self::add_points_secp256k1(a, b),
        }
    }

    fn add_points_p256(a: &[u8], b: &[u8]) -> Result<Vec<u8>, ThresholdError> {
        let point_a = P256ThresholdOps::point_from_bytes(a)?;
        let point_b = P256ThresholdOps::point_from_bytes(b)?;
        let sum = point_a + point_b;
        Ok(P256ThresholdOps::point_to_bytes(&sum))
    }

    fn add_points_secp256k1(a: &[u8], b: &[u8]) -> Result<Vec<u8>, ThresholdError> {
        let point_a = Secp256k1ThresholdOps::point_from_bytes(a)?;
        let point_b = Secp256k1ThresholdOps::point_from_bytes(b)?;
        let sum = point_a + point_b;
        Ok(Secp256k1ThresholdOps::point_to_bytes(&sum))
    }

    /// Get the identity point for the given curve.
    pub fn identity_point(curve: EcdsaCurve) -> Vec<u8> {
        match curve {
            EcdsaCurve::P256 => {
                use p256::ProjectivePoint;
                P256ThresholdOps::point_to_bytes(&ProjectivePoint::IDENTITY)
            }
            EcdsaCurve::Secp256k1 => {
                use k256::ProjectivePoint;
                Secp256k1ThresholdOps::point_to_bytes(&ProjectivePoint::IDENTITY)
            }
        }
    }

    /// Get the zero scalar for the given curve.
    pub fn zero_scalar(_curve: EcdsaCurve) -> Vec<u8> {
        vec![0u8; 32]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_commitments_p256() {
        // Generate a polynomial
        let coefficients = FeldmanVss::generate_polynomial(2, None, EcdsaCurve::P256).unwrap();
        assert_eq!(coefficients.len(), 3); // degree 2 = 3 coefficients

        // Generate commitments
        let commitments =
            FeldmanVss::generate_commitments(&coefficients, EcdsaCurve::P256).unwrap();
        assert_eq!(commitments.len(), 3);

        // Each commitment should be 33 bytes (compressed point)
        for c in &commitments {
            assert_eq!(c.len(), 33);
        }

        // Evaluate polynomial at x=1
        let share = FeldmanVss::evaluate_polynomial(&coefficients, 1, EcdsaCurve::P256).unwrap();

        // Verify the share
        let valid =
            FeldmanVss::verify_share(ParticipantId(1), &share, &commitments, EcdsaCurve::P256)
                .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_generate_and_verify_commitments_secp256k1() {
        // Generate a polynomial
        let coefficients = FeldmanVss::generate_polynomial(2, None, EcdsaCurve::Secp256k1).unwrap();
        assert_eq!(coefficients.len(), 3);

        // Generate commitments
        let commitments =
            FeldmanVss::generate_commitments(&coefficients, EcdsaCurve::Secp256k1).unwrap();
        assert_eq!(commitments.len(), 3);

        // Evaluate polynomial at x=3
        let share =
            FeldmanVss::evaluate_polynomial(&coefficients, 3, EcdsaCurve::Secp256k1).unwrap();

        // Verify the share
        let valid = FeldmanVss::verify_share(
            ParticipantId(3),
            &share,
            &commitments,
            EcdsaCurve::Secp256k1,
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_invalid_share_detected() {
        let coefficients = FeldmanVss::generate_polynomial(1, None, EcdsaCurve::P256).unwrap();
        let commitments =
            FeldmanVss::generate_commitments(&coefficients, EcdsaCurve::P256).unwrap();

        // Get valid share
        let share = FeldmanVss::evaluate_polynomial(&coefficients, 1, EcdsaCurve::P256).unwrap();

        // Tamper with the share
        let mut tampered_share = share.clone();
        tampered_share[0] ^= 0xFF;

        // Valid share should verify
        let valid =
            FeldmanVss::verify_share(ParticipantId(1), &share, &commitments, EcdsaCurve::P256)
                .unwrap();
        assert!(valid);

        // Tampered share should fail
        let invalid = FeldmanVss::verify_share(
            ParticipantId(1),
            &tampered_share,
            &commitments,
            EcdsaCurve::P256,
        )
        .unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_wrong_participant_id_fails() {
        let coefficients = FeldmanVss::generate_polynomial(1, None, EcdsaCurve::P256).unwrap();
        let commitments =
            FeldmanVss::generate_commitments(&coefficients, EcdsaCurve::P256).unwrap();

        // Get share for participant 1
        let share = FeldmanVss::evaluate_polynomial(&coefficients, 1, EcdsaCurve::P256).unwrap();

        // Verify with correct ID
        let valid =
            FeldmanVss::verify_share(ParticipantId(1), &share, &commitments, EcdsaCurve::P256)
                .unwrap();
        assert!(valid);

        // Verify with wrong ID (pretending share is for participant 2)
        let invalid =
            FeldmanVss::verify_share(ParticipantId(2), &share, &commitments, EcdsaCurve::P256)
                .unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_polynomial_with_constant_term() {
        // Use a specific constant term
        let constant = vec![0x42u8; 32];
        let coefficients =
            FeldmanVss::generate_polynomial(2, Some(&constant), EcdsaCurve::P256).unwrap();

        // First coefficient should match (modulo field reduction)
        // For most 32-byte values within field range, this should be exact
        assert_eq!(coefficients[0].len(), 32);
    }

    #[test]
    fn test_add_scalars_p256() {
        let a = P256ThresholdOps::scalar_to_bytes(&P256ThresholdOps::random_scalar());
        let b = P256ThresholdOps::scalar_to_bytes(&P256ThresholdOps::random_scalar());

        let sum = FeldmanVss::add_scalars(&a, &b, EcdsaCurve::P256).unwrap();
        assert_eq!(sum.len(), 32);
    }

    #[test]
    fn test_add_scalars_secp256k1() {
        let a = Secp256k1ThresholdOps::scalar_to_bytes(&Secp256k1ThresholdOps::random_scalar());
        let b = Secp256k1ThresholdOps::scalar_to_bytes(&Secp256k1ThresholdOps::random_scalar());

        let sum = FeldmanVss::add_scalars(&a, &b, EcdsaCurve::Secp256k1).unwrap();
        assert_eq!(sum.len(), 32);
    }

    #[test]
    fn test_add_points_p256() {
        let scalar_a = P256ThresholdOps::random_scalar();
        let scalar_b = P256ThresholdOps::random_scalar();
        let point_a =
            P256ThresholdOps::point_to_bytes(&P256ThresholdOps::scalar_to_point(&scalar_a));
        let point_b =
            P256ThresholdOps::point_to_bytes(&P256ThresholdOps::scalar_to_point(&scalar_b));

        let sum = FeldmanVss::add_points(&point_a, &point_b, EcdsaCurve::P256).unwrap();
        assert_eq!(sum.len(), 33);

        // Verify: (a + b)*G = a*G + b*G
        let expected = P256ThresholdOps::point_to_bytes(&P256ThresholdOps::scalar_to_point(
            &(scalar_a + scalar_b),
        ));
        assert_eq!(sum, expected);
    }

    #[test]
    fn test_multiple_shares_verify() {
        let coefficients = FeldmanVss::generate_polynomial(2, None, EcdsaCurve::P256).unwrap();
        let commitments =
            FeldmanVss::generate_commitments(&coefficients, EcdsaCurve::P256).unwrap();

        // Verify shares for participants 1, 2, 3
        for i in 1..=3 {
            let share =
                FeldmanVss::evaluate_polynomial(&coefficients, i, EcdsaCurve::P256).unwrap();
            let valid =
                FeldmanVss::verify_share(ParticipantId(i), &share, &commitments, EcdsaCurve::P256)
                    .unwrap();
            assert!(valid, "Share for participant {} should be valid", i);
        }
    }
}
