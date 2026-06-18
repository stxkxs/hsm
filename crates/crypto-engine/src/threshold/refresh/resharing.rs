//! Resharing Protocol Implementation
//!
//! Implements resharing to change the threshold or participant set while
//! preserving the group public key.

use crate::threshold::config::ResharingConfig;
use crate::threshold::ecdsa::{FeldmanVss, P256ThresholdOps, Secp256k1ThresholdOps};
use crate::threshold::types::{
    EcdsaCurve, GroupPublicKey, KeyShare, ParticipantId, ThresholdError, ThresholdScheme,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Package sent from an old participant to a new participant during resharing.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ResharingPackage {
    /// The old participant who generated this share.
    #[zeroize(skip)]
    pub old_participant: ParticipantId,
    /// The new participant receiving this share.
    #[zeroize(skip)]
    pub new_participant: ParticipantId,
    /// The resharing share value.
    pub share: Vec<u8>,
    /// Feldman commitments for verification.
    #[zeroize(skip)]
    pub commitments: Vec<Vec<u8>>,
    /// The threshold scheme.
    #[zeroize(skip)]
    pub scheme: ThresholdScheme,
}

impl ResharingPackage {
    /// Create a new resharing package.
    pub fn new(
        old_participant: ParticipantId,
        new_participant: ParticipantId,
        share: Vec<u8>,
        commitments: Vec<Vec<u8>>,
        scheme: ThresholdScheme,
    ) -> Self {
        Self {
            old_participant,
            new_participant,
            share,
            commitments,
            scheme,
        }
    }

    /// Verify the share against the commitments.
    pub fn verify(&self) -> Result<bool, ThresholdError> {
        match self.scheme {
            ThresholdScheme::ThresholdEcdsaP256 => FeldmanVss::verify_share(
                self.new_participant,
                &self.share,
                &self.commitments,
                EcdsaCurve::P256,
            ),
            ThresholdScheme::ThresholdEcdsaSecp256k1 => FeldmanVss::verify_share(
                self.new_participant,
                &self.share,
                &self.commitments,
                EcdsaCurve::Secp256k1,
            ),
            ThresholdScheme::FrostEd25519 => {
                verify_ed25519_share(self.new_participant, &self.share, &self.commitments)
            }
            ThresholdScheme::ThresholdBls12381 => {
                verify_bls_share(self.new_participant, &self.share, &self.commitments)
            }
        }
    }
}

impl std::fmt::Debug for ResharingPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResharingPackage")
            .field("old_participant", &self.old_participant)
            .field("new_participant", &self.new_participant)
            .field("share", &"<redacted>")
            .field("commitments_len", &self.commitments.len())
            .field("scheme", &self.scheme)
            .finish()
    }
}

/// Resharing protocol for changing threshold or participants.
///
/// This protocol allows changing the participant set and/or the threshold
/// while preserving the group public key. Old participants (at least t of them)
/// generate new shares for the new participants.
///
/// # Protocol
///
/// 1. Old participants with their shares generate a polynomial where their
///    share is the constant term
/// 2. Each old participant evaluates their polynomial at each new participant's ID
/// 3. New participants receive shares from at least t old participants
/// 4. New participants use Lagrange interpolation to compute their new share
pub struct Resharing {
    /// Configuration for the resharing.
    config: ResharingConfig,
}

impl Resharing {
    /// Create a new resharing protocol instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration specifying old and new participants
    ///
    /// # Returns
    ///
    /// A new Resharing instance.
    pub fn new(config: ResharingConfig) -> Result<Self, ThresholdError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Get the resharing configuration.
    pub fn config(&self) -> &ResharingConfig {
        &self.config
    }

    /// Generate resharing packages for all new participants.
    ///
    /// An old participant calls this with their share to generate packages
    /// for all new participants.
    ///
    /// # Arguments
    ///
    /// * `old_share` - The old participant's key share
    ///
    /// # Returns
    ///
    /// A vector of ResharingPackage, one for each new participant.
    pub fn generate_new_shares(
        &self,
        old_share: &KeyShare,
    ) -> Result<Vec<ResharingPackage>, ThresholdError> {
        // Verify the old share belongs to one of the old participants
        if !self
            .config
            .old_participants
            .contains(&old_share.participant_id)
        {
            return Err(ThresholdError::InvalidParticipant(
                "Share does not belong to an old participant".into(),
            ));
        }

        // Generate a polynomial with the old share as constant term
        // Degree is new_threshold - 1
        let degree = self.config.new_config.threshold - 1;
        let coefficients =
            self.generate_polynomial_with_constant(&old_share.secret_share, degree)?;

        // Generate Feldman commitments
        let commitments = self.generate_commitments(&coefficients)?;

        // Generate a package for each new participant
        let mut packages = Vec::with_capacity(self.config.new_participants.len());

        for &new_participant in &self.config.new_participants {
            let share = self.evaluate_polynomial(&coefficients, new_participant.0)?;

            packages.push(ResharingPackage::new(
                old_share.participant_id,
                new_participant,
                share,
                commitments.clone(),
                self.config.scheme,
            ));
        }

        Ok(packages)
    }

    /// Receive and combine resharing packages to create a new share.
    ///
    /// A new participant calls this with packages received from old participants
    /// to compute their new share.
    ///
    /// # Arguments
    ///
    /// * `new_participant_id` - The new participant's ID
    /// * `packages` - Packages received from old participants
    /// * `group_public_key` - The group's public key (for verification)
    ///
    /// # Returns
    ///
    /// The new KeyShare for this participant.
    pub fn receive_shares(
        &self,
        new_participant_id: ParticipantId,
        packages: Vec<ResharingPackage>,
        _group_public_key: &GroupPublicKey,
    ) -> Result<KeyShare, ThresholdError> {
        // Verify we have enough packages
        if packages.len() < self.config.old_config.threshold as usize {
            return Err(ThresholdError::ResharingInsufficientShares {
                required: self.config.old_config.threshold as usize,
                provided: packages.len(),
            });
        }

        // Validate every package and collect DISTINCT old-participant shares.
        //
        // Lagrange interpolation assumes the supplied sample points are distinct,
        // valid members of the old committee. Without this check a caller could
        // pass duplicate or non-member `old_participant` IDs, producing a silently
        // corrupted reconstructed share (the Lagrange basis would be wrong). We
        // therefore reject duplicates and non-members up front.
        let mut seen: std::collections::HashSet<ParticipantId> = std::collections::HashSet::new();
        let mut shares_with_ids: Vec<(ParticipantId, Vec<u8>)> = Vec::with_capacity(packages.len());

        for pkg in &packages {
            if pkg.new_participant != new_participant_id {
                return Err(ThresholdError::InvalidParticipant(
                    "Package not intended for this participant".into(),
                ));
            }

            // The sender must be a member of the old committee.
            if !self.config.old_participants.contains(&pkg.old_participant) {
                return Err(ThresholdError::ResharingInvalidShare(pkg.old_participant));
            }

            // Reject duplicate senders: a single old participant must not be
            // counted twice toward the interpolation.
            if !seen.insert(pkg.old_participant) {
                return Err(ThresholdError::ResharingInvalidShare(pkg.old_participant));
            }

            // Verify the share against commitments.
            if !pkg.verify()? {
                return Err(ThresholdError::ResharingInvalidShare(pkg.old_participant));
            }

            shares_with_ids.push((pkg.old_participant, pkg.share.clone()));
        }

        // After de-duplication we must still have at least `threshold` distinct
        // valid members (the earlier length check could have been satisfied by
        // duplicates).
        if shares_with_ids.len() < self.config.old_config.threshold as usize {
            return Err(ThresholdError::ResharingInsufficientShares {
                required: self.config.old_config.threshold as usize,
                provided: shares_with_ids.len(),
            });
        }

        // Use exactly `threshold` distinct shares for interpolation.
        shares_with_ids.truncate(self.config.old_config.threshold as usize);

        // Compute the new share using Lagrange interpolation
        // The new share is: sum_i (lambda_i * s_i) where lambda_i is the
        // Lagrange coefficient for old participant i
        let new_secret_share = self.lagrange_interpolate(&shares_with_ids)?;

        // Compute the new public key share
        let new_public_share = self.compute_public_share(&new_secret_share)?;

        // Create the new KeyShare
        Ok(KeyShare::new(
            new_participant_id,
            self.config.new_config,
            new_secret_share,
            new_public_share,
        ))
    }

    // ========== Internal Helper Methods ==========

    /// Generate a polynomial with a specific constant term.
    fn generate_polynomial_with_constant(
        &self,
        constant: &[u8],
        degree: u16,
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
        match self.config.scheme {
            ThresholdScheme::ThresholdEcdsaP256 => {
                FeldmanVss::generate_polynomial(degree, Some(constant), EcdsaCurve::P256)
            }
            ThresholdScheme::ThresholdEcdsaSecp256k1 => {
                FeldmanVss::generate_polynomial(degree, Some(constant), EcdsaCurve::Secp256k1)
            }
            ThresholdScheme::FrostEd25519 => {
                self.generate_ed25519_polynomial_with_constant(constant, degree)
            }
            ThresholdScheme::ThresholdBls12381 => {
                self.generate_bls_polynomial_with_constant(constant, degree)
            }
        }
    }

    /// Generate an Ed25519 polynomial with a specific constant term.
    fn generate_ed25519_polynomial_with_constant(
        &self,
        constant: &[u8],
        degree: u16,
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
        use rand_core::{OsRng, RngCore};

        let mut coefficients = vec![constant.to_vec()];

        for _ in 0..degree {
            let mut coeff = vec![0u8; 32];
            OsRng.fill_bytes(&mut coeff);
            coefficients.push(coeff);
        }

        Ok(coefficients)
    }

    /// Generate a BLS polynomial with a specific constant term.
    fn generate_bls_polynomial_with_constant(
        &self,
        constant: &[u8],
        degree: u16,
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
        use rand_core::{OsRng, RngCore};

        let mut coefficients = vec![constant.to_vec()];

        for _ in 0..degree {
            let mut coeff = vec![0u8; 32];
            OsRng.fill_bytes(&mut coeff);
            coefficients.push(coeff);
        }

        Ok(coefficients)
    }

    /// Generate Feldman commitments for polynomial coefficients.
    fn generate_commitments(
        &self,
        coefficients: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
        match self.config.scheme {
            ThresholdScheme::ThresholdEcdsaP256 => {
                FeldmanVss::generate_commitments(coefficients, EcdsaCurve::P256)
            }
            ThresholdScheme::ThresholdEcdsaSecp256k1 => {
                FeldmanVss::generate_commitments(coefficients, EcdsaCurve::Secp256k1)
            }
            ThresholdScheme::FrostEd25519 => generate_ed25519_commitments(coefficients),
            ThresholdScheme::ThresholdBls12381 => generate_bls_commitments(coefficients),
        }
    }

    /// Evaluate polynomial at a given x-coordinate.
    fn evaluate_polynomial(
        &self,
        coefficients: &[Vec<u8>],
        x: u16,
    ) -> Result<Vec<u8>, ThresholdError> {
        match self.config.scheme {
            ThresholdScheme::ThresholdEcdsaP256 => {
                FeldmanVss::evaluate_polynomial(coefficients, x, EcdsaCurve::P256)
            }
            ThresholdScheme::ThresholdEcdsaSecp256k1 => {
                FeldmanVss::evaluate_polynomial(coefficients, x, EcdsaCurve::Secp256k1)
            }
            ThresholdScheme::FrostEd25519 => evaluate_ed25519_polynomial(coefficients, x),
            ThresholdScheme::ThresholdBls12381 => evaluate_bls_polynomial(coefficients, x),
        }
    }

    /// Perform Lagrange interpolation on shares to compute the new share.
    fn lagrange_interpolate(
        &self,
        shares: &[(ParticipantId, Vec<u8>)],
    ) -> Result<Vec<u8>, ThresholdError> {
        match self.config.scheme {
            ThresholdScheme::ThresholdEcdsaP256 => lagrange_interpolate_p256(shares),
            ThresholdScheme::ThresholdEcdsaSecp256k1 => lagrange_interpolate_secp256k1(shares),
            ThresholdScheme::FrostEd25519 => lagrange_interpolate_ed25519(shares),
            ThresholdScheme::ThresholdBls12381 => lagrange_interpolate_bls(shares),
        }
    }

    /// Compute the public share from a secret share.
    fn compute_public_share(&self, secret: &[u8]) -> Result<Vec<u8>, ThresholdError> {
        match self.config.scheme {
            ThresholdScheme::ThresholdEcdsaP256 => {
                let scalar = P256ThresholdOps::scalar_from_bytes(secret)?;
                let point = P256ThresholdOps::scalar_to_point(&scalar);
                Ok(P256ThresholdOps::point_to_bytes(&point))
            }
            ThresholdScheme::ThresholdEcdsaSecp256k1 => {
                let scalar = Secp256k1ThresholdOps::scalar_from_bytes(secret)?;
                let point = Secp256k1ThresholdOps::scalar_to_point(&scalar);
                Ok(Secp256k1ThresholdOps::point_to_bytes(&point))
            }
            ThresholdScheme::FrostEd25519 => {
                use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(secret);
                let scalar = Scalar::from_bytes_mod_order(bytes);
                let point = ED25519_BASEPOINT_TABLE * &scalar;
                Ok(point.compress().to_bytes().to_vec())
            }
            ThresholdScheme::ThresholdBls12381 => {
                use blst::min_pk::SecretKey;

                let sk =
                    SecretKey::from_bytes(secret).map_err(|_| ThresholdError::InvalidKeyShare)?;
                let pk = sk.sk_to_pk();
                Ok(pk.to_bytes().to_vec())
            }
        }
    }
}

// ========== Helper Functions ==========

/// Generate Ed25519 Feldman commitments.
fn generate_ed25519_commitments(coefficients: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, ThresholdError> {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

    let mut commitments = Vec::with_capacity(coefficients.len());

    for coeff_bytes in coefficients {
        if coeff_bytes.len() != 32 {
            return Err(ThresholdError::SerializationError(
                "Invalid coefficient length".into(),
            ));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(coeff_bytes);
        let scalar = Scalar::from_bytes_mod_order(bytes);
        let point = ED25519_BASEPOINT_TABLE * &scalar;
        commitments.push(point.compress().to_bytes().to_vec());
    }

    Ok(commitments)
}

/// Generate BLS Feldman commitments.
fn generate_bls_commitments(coefficients: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, ThresholdError> {
    use blst::{blst_p1, blst_p1_compress, blst_p1_mult, blst_scalar, blst_scalar_from_bendian};

    let mut commitments = Vec::with_capacity(coefficients.len());

    for coeff_bytes in coefficients {
        if coeff_bytes.len() != 32 {
            return Err(ThresholdError::SerializationError(
                "BLS coefficient must be 32 bytes".into(),
            ));
        }

        if coeff_bytes.iter().all(|&b| b == 0) {
            // Identity point: first byte 0xc0, rest zeros
            let mut identity_bytes = vec![0xc0u8];
            identity_bytes.extend(vec![0u8; 47]);
            commitments.push(identity_bytes);
        } else {
            // Compute commitment = coeff * G1. `blst_p1_mult` reads the scalar as a
            // *little-endian* byte array, so the big-endian `coeff_bytes` must be converted
            // via `blst_scalar_from_bendian` first (filling the little-endian `.b` limbs).
            // Passing the raw big-endian bytes would commit to `reverse(coeff)` and never
            // match the field-reduced share in `verify_bls_share`.
            let mut coeff_arr = [0u8; 32];
            coeff_arr.copy_from_slice(coeff_bytes);
            // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from coeff_arr (a [u8; 32]);
            // blst_p1_generator returns a valid static G1 generator pointer; blst_p1_mult reads
            // scalar.b (a [u8; 32] inside blst_scalar, bit-length 256 passed explicitly) and writes
            // to caller-owned result; blst_p1_compress writes exactly 48 bytes to compressed.
            unsafe {
                let mut scalar = blst_scalar::default();
                blst_scalar_from_bendian(&mut scalar, coeff_arr.as_ptr());

                let generator = blst::blst_p1_generator();
                let mut result = blst_p1::default();
                blst_p1_mult(&mut result, generator, scalar.b.as_ptr(), 256);

                let mut compressed = [0u8; 48];
                blst_p1_compress(compressed.as_mut_ptr(), &result);
                commitments.push(compressed.to_vec());
            }
        }
    }

    Ok(commitments)
}

/// Verify a BLS12-381 Feldman-VSS share against G1 commitments.
///
/// Checks `G1 * share == sum_i(C_i * x^i)` where `x = participant_id` and each
/// `C_i` is a compressed G1 commitment to a polynomial coefficient. This mirrors
/// the reference implementation in `bls/dkg.rs::verify_share` and replaces the
/// previous `Ok(true)` stub that accepted any (including malicious) share.
///
/// Returns `Err(InvalidCommitment)` if a commitment fails to decompress and
/// `Err(InvalidKeyShare)` if the share is not 32 bytes.
pub(crate) fn verify_bls_share(
    participant_id: ParticipantId,
    share: &[u8],
    commitments: &[Vec<u8>],
) -> Result<bool, ThresholdError> {
    use blst::{
        blst_fr, blst_fr_from_scalar, blst_fr_mul, blst_p1, blst_p1_add_or_double, blst_p1_affine,
        blst_p1_compress, blst_p1_from_affine, blst_p1_generator, blst_p1_mult, blst_p1_uncompress,
        blst_scalar, blst_scalar_from_bendian, blst_scalar_from_fr, BLST_ERROR,
    };

    if commitments.is_empty() {
        return Err(ThresholdError::ResharingFailed(
            "no BLS commitments to verify share against".into(),
        ));
    }

    // Share must be a 32-byte scalar in big-endian.
    let share_arr: [u8; 32] = share
        .try_into()
        .map_err(|_| ThresholdError::InvalidKeyShare)?;

    // LHS = G1 * share
    let lhs: [u8; 48] = unsafe {
        let mut scalar_repr = blst_scalar::default();
        blst_scalar_from_bendian(&mut scalar_repr, share_arr.as_ptr());
        let generator = *blst_p1_generator();
        let mut point = blst_p1::default();
        blst_p1_mult(&mut point, &generator, scalar_repr.b.as_ptr(), 256);
        let mut out = [0u8; 48];
        blst_p1_compress(out.as_mut_ptr(), &point);
        out
    };

    // x = participant_id as a field element; start x^0 = 1.
    let x = participant_id.0;
    let mut x_pow = blst_fr::default();
    unsafe {
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let mut one_scalar = blst_scalar::default();
        blst_scalar_from_bendian(&mut one_scalar, one_bytes.as_ptr());
        blst_fr_from_scalar(&mut x_pow, &one_scalar);
    }
    let x_fr = unsafe {
        let mut x_bytes = [0u8; 32];
        x_bytes[30] = (x >> 8) as u8;
        x_bytes[31] = x as u8;
        let mut x_scalar = blst_scalar::default();
        blst_scalar_from_bendian(&mut x_scalar, x_bytes.as_ptr());
        let mut fr = blst_fr::default();
        blst_fr_from_scalar(&mut fr, &x_scalar);
        fr
    };

    // RHS = sum_i(C_i * x^i)
    let mut sum = blst_p1::default();
    let mut is_first = true;
    for commitment in commitments {
        let commitment_arr: [u8; 48] = commitment
            .as_slice()
            .try_into()
            .map_err(|_| ThresholdError::InvalidCommitment(participant_id))?;

        // Scalar bytes for x^i.
        let mut xi_scalar = blst_scalar::default();
        unsafe {
            blst_scalar_from_fr(&mut xi_scalar, &x_pow);
        }

        let scaled = unsafe {
            let mut c_affine = blst_p1_affine::default();
            if blst_p1_uncompress(&mut c_affine, commitment_arr.as_ptr())
                != BLST_ERROR::BLST_SUCCESS
            {
                return Err(ThresholdError::InvalidCommitment(participant_id));
            }
            let mut c_point = blst_p1::default();
            blst_p1_from_affine(&mut c_point, &c_affine);
            let mut scaled = blst_p1::default();
            blst_p1_mult(&mut scaled, &c_point, xi_scalar.b.as_ptr(), 256);
            scaled
        };

        if is_first {
            sum = scaled;
            is_first = false;
        } else {
            let mut new_sum = blst_p1::default();
            unsafe {
                blst_p1_add_or_double(&mut new_sum, &sum, &scaled);
            }
            sum = new_sum;
        }

        // x_pow *= x
        let mut next = blst_fr::default();
        unsafe {
            blst_fr_mul(&mut next, &x_pow, &x_fr);
        }
        x_pow = next;
    }

    let rhs: [u8; 48] = unsafe {
        let mut out = [0u8; 48];
        blst_p1_compress(out.as_mut_ptr(), &sum);
        out
    };

    Ok(subtle::ConstantTimeEq::ct_eq(&lhs[..], &rhs[..]).into())
}

/// Verify an Ed25519 share against commitments.
fn verify_ed25519_share(
    participant_id: ParticipantId,
    share: &[u8],
    commitments: &[Vec<u8>],
) -> Result<bool, ThresholdError> {
    use curve25519_dalek::{
        constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, scalar::Scalar,
    };

    let mut share_bytes = [0u8; 32];
    share_bytes.copy_from_slice(share);
    let share_scalar = Scalar::from_bytes_mod_order(share_bytes);
    let actual = ED25519_BASEPOINT_TABLE * &share_scalar;

    let x = Scalar::from(participant_id.0 as u64);
    let mut expected = curve25519_dalek::edwards::EdwardsPoint::default();
    let mut x_pow = Scalar::ONE;

    for commitment_bytes in commitments {
        let commitment_point = CompressedEdwardsY::from_slice(commitment_bytes)
            .map_err(|_| ThresholdError::SerializationError("Invalid Ed25519 point".into()))?
            .decompress()
            .ok_or_else(|| ThresholdError::SerializationError("Invalid Ed25519 point".into()))?;

        expected += commitment_point * x_pow;
        x_pow *= x;
    }

    Ok(actual == expected)
}

/// Evaluate an Ed25519 polynomial at x.
fn evaluate_ed25519_polynomial(
    coefficients: &[Vec<u8>],
    x: u16,
) -> Result<Vec<u8>, ThresholdError> {
    use curve25519_dalek::scalar::Scalar;

    if coefficients.is_empty() {
        return Err(ThresholdError::KeyRefreshFailed("Empty polynomial".into()));
    }

    let x_scalar = Scalar::from(x as u64);
    let mut result = Scalar::ZERO;

    for coeff_bytes in coefficients.iter().rev() {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(coeff_bytes);
        let coeff = Scalar::from_bytes_mod_order(bytes);
        result = result * x_scalar + coeff;
    }

    Ok(result.to_bytes().to_vec())
}

/// Evaluate a BLS polynomial at x.
fn evaluate_bls_polynomial(coefficients: &[Vec<u8>], x: u16) -> Result<Vec<u8>, ThresholdError> {
    use blst::{
        blst_bendian_from_scalar, blst_fr, blst_fr_add, blst_fr_from_scalar, blst_fr_mul,
        blst_scalar, blst_scalar_from_bendian, blst_scalar_from_fr,
    };

    if coefficients.is_empty() {
        return Err(ThresholdError::KeyRefreshFailed("Empty polynomial".into()));
    }

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

    let mut result_fr = blst_fr::default();
    let mut coef_scalar = blst_scalar::default();

    let last_coef = coefficients.last().unwrap();
    let mut last_bytes = [0u8; 32];
    last_bytes.copy_from_slice(last_coef);
    // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from last_bytes (a [u8; 32]);
    // blst_fr_from_scalar operates on caller-owned struct references.
    unsafe {
        blst_scalar_from_bendian(&mut coef_scalar, last_bytes.as_ptr());
        blst_fr_from_scalar(&mut result_fr, &coef_scalar);
    }

    for coeff_bytes in coefficients.iter().rev().skip(1) {
        let mut temp = blst_fr::default();
        // SAFETY: blst_fr_mul reads caller-owned result_fr and x_fr and writes to caller-owned temp.
        unsafe {
            blst_fr_mul(&mut temp, &result_fr, &x_fr);
        }

        let mut coef_bytes_arr = [0u8; 32];
        coef_bytes_arr.copy_from_slice(coeff_bytes);
        let mut coef_scalar_inner = blst_scalar::default();
        let mut coef_fr = blst_fr::default();
        // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from coef_bytes_arr (a [u8; 32]);
        // blst_fr_from_scalar and blst_fr_add operate on caller-owned struct references.
        unsafe {
            blst_scalar_from_bendian(&mut coef_scalar_inner, coef_bytes_arr.as_ptr());
            blst_fr_from_scalar(&mut coef_fr, &coef_scalar_inner);
            blst_fr_add(&mut result_fr, &temp, &coef_fr);
        }
    }

    let mut result_scalar = blst_scalar::default();
    let mut result_bytes = [0u8; 32];
    // SAFETY: blst_scalar_from_fr reads caller-owned result_fr; blst_bendian_from_scalar writes
    // exactly 32 bytes to result_bytes (a [u8; 32]).
    unsafe {
        blst_scalar_from_fr(&mut result_scalar, &result_fr);
        blst_bendian_from_scalar(result_bytes.as_mut_ptr(), &result_scalar);
    }

    Ok(result_bytes.to_vec())
}

/// Lagrange interpolation for P-256 shares.
fn lagrange_interpolate_p256(
    shares: &[(ParticipantId, Vec<u8>)],
) -> Result<Vec<u8>, ThresholdError> {
    use p256::Scalar;

    let participants: Vec<ParticipantId> = shares.iter().map(|(id, _)| *id).collect();
    let mut result = Scalar::ZERO;

    for (id, share_bytes) in shares {
        let scalar = P256ThresholdOps::scalar_from_bytes(share_bytes)?;
        let lambda = P256ThresholdOps::lagrange_coefficient(*id, &participants);
        result += scalar * lambda;
    }

    Ok(P256ThresholdOps::scalar_to_bytes(&result))
}

/// Lagrange interpolation for secp256k1 shares.
fn lagrange_interpolate_secp256k1(
    shares: &[(ParticipantId, Vec<u8>)],
) -> Result<Vec<u8>, ThresholdError> {
    use k256::Scalar;

    let participants: Vec<ParticipantId> = shares.iter().map(|(id, _)| *id).collect();
    let mut result = Scalar::ZERO;

    for (id, share_bytes) in shares {
        let scalar = Secp256k1ThresholdOps::scalar_from_bytes(share_bytes)?;
        let lambda = Secp256k1ThresholdOps::lagrange_coefficient(*id, &participants);
        result += scalar * lambda;
    }

    Ok(Secp256k1ThresholdOps::scalar_to_bytes(&result))
}

/// Lagrange interpolation for Ed25519 shares.
fn lagrange_interpolate_ed25519(
    shares: &[(ParticipantId, Vec<u8>)],
) -> Result<Vec<u8>, ThresholdError> {
    use curve25519_dalek::scalar::Scalar;

    let participants: Vec<ParticipantId> = shares.iter().map(|(id, _)| *id).collect();
    let mut result = Scalar::ZERO;

    for (id, share_bytes) in shares {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(share_bytes);
        let scalar = Scalar::from_bytes_mod_order(bytes);

        // Compute Lagrange coefficient
        let x_i = Scalar::from(id.0 as u64);
        let mut lambda = Scalar::ONE;

        for &p in &participants {
            if p != *id {
                let x_j = Scalar::from(p.0 as u64);
                let num = x_j;
                let denom = x_j - x_i;
                let denom_inv = denom.invert();
                lambda *= num * denom_inv;
            }
        }

        result += scalar * lambda;
    }

    Ok(result.to_bytes().to_vec())
}

/// Lagrange interpolation for BLS shares.
fn lagrange_interpolate_bls(
    shares: &[(ParticipantId, Vec<u8>)],
) -> Result<Vec<u8>, ThresholdError> {
    use blst::{
        blst_bendian_from_scalar, blst_fr, blst_fr_add, blst_fr_from_scalar, blst_fr_inverse,
        blst_fr_mul, blst_fr_sub, blst_scalar, blst_scalar_from_bendian, blst_scalar_from_fr,
    };

    let participants: Vec<ParticipantId> = shares.iter().map(|(id, _)| *id).collect();
    let mut result_fr = blst_fr::default();

    for (id, share_bytes) in shares {
        // Parse share
        let mut share_bytes_arr = [0u8; 32];
        share_bytes_arr.copy_from_slice(share_bytes);
        let mut share_scalar = blst_scalar::default();
        let mut share_fr = blst_fr::default();
        // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from share_bytes_arr (a [u8; 32]);
        // blst_fr_from_scalar operates on caller-owned struct references.
        unsafe {
            blst_scalar_from_bendian(&mut share_scalar, share_bytes_arr.as_ptr());
            blst_fr_from_scalar(&mut share_fr, &share_scalar);
        }

        // Compute Lagrange coefficient
        let x_i = id.0 as u64;

        let one_bytes = {
            let mut bytes = [0u8; 32];
            bytes[31] = 1;
            bytes
        };

        let mut numerator = blst_fr::default();
        let mut denominator = blst_fr::default();
        let mut one_scalar = blst_scalar::default();
        // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from one_bytes (a [u8; 32]);
        // blst_fr_from_scalar operates on caller-owned struct references.
        unsafe {
            blst_scalar_from_bendian(&mut one_scalar, one_bytes.as_ptr());
            blst_fr_from_scalar(&mut numerator, &one_scalar);
            blst_fr_from_scalar(&mut denominator, &one_scalar);
        }

        for &p in &participants {
            if p != *id {
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
        }

        // lambda = numerator / denominator
        let mut denom_inv = blst_fr::default();
        let mut lambda = blst_fr::default();
        // SAFETY: blst_fr_inverse and blst_fr_mul operate on caller-owned blst_fr struct references.
        unsafe {
            blst_fr_inverse(&mut denom_inv, &denominator);
            blst_fr_mul(&mut lambda, &numerator, &denom_inv);
        }

        // result += share * lambda
        let mut term = blst_fr::default();
        // SAFETY: blst_fr_mul and blst_fr_add operate on caller-owned blst_fr struct references.
        unsafe {
            blst_fr_mul(&mut term, &share_fr, &lambda);
            blst_fr_add(&mut result_fr, &result_fr, &term);
        }
    }

    // Convert result to bytes
    let mut result_scalar = blst_scalar::default();
    let mut result_bytes = [0u8; 32];
    // SAFETY: blst_scalar_from_fr reads caller-owned result_fr; blst_bendian_from_scalar writes
    // exactly 32 bytes to result_bytes (a [u8; 32]).
    unsafe {
        blst_scalar_from_fr(&mut result_scalar, &result_fr);
        blst_bendian_from_scalar(result_bytes.as_mut_ptr(), &result_scalar);
    }

    Ok(result_bytes.to_vec())
}
