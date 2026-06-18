//! Key Refresh Protocol Implementation
//!
//! Implements proactive key refresh where participants update their shares
//! without changing the group public key.

use crate::threshold::config::KeyRefreshConfig;
use crate::threshold::ecdsa::{FeldmanVss, P256ThresholdOps, Secp256k1ThresholdOps};
use crate::threshold::types::{
    EcdsaCurve, KeyShare, ParticipantId, ThresholdError, ThresholdScheme,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// State of the key refresh protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshState {
    /// Protocol not yet started.
    NotStarted,
    /// Round 1 complete: commitments have been generated and shared.
    Round1Complete,
    /// Round 2 complete: refresh shares have been exchanged.
    Round2Complete,
    /// Refresh completed successfully.
    Complete,
    /// Protocol failed with the given reason.
    Failed(String),
}

/// Package sent during Round 1 of the refresh protocol.
///
/// Contains Feldman commitments to a zero-constant polynomial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshRound1Package {
    /// The participant who generated this package.
    pub sender: ParticipantId,
    /// Feldman commitments to the refresh polynomial.
    /// First commitment MUST be the identity point (commitment to zero).
    pub commitments: Vec<Vec<u8>>,
    /// The threshold scheme being used.
    pub scheme: ThresholdScheme,
}

impl RefreshRound1Package {
    /// Create a new Round 1 package.
    pub fn new(sender: ParticipantId, commitments: Vec<Vec<u8>>, scheme: ThresholdScheme) -> Self {
        Self {
            sender,
            commitments,
            scheme,
        }
    }

    /// Verify that the first commitment is the identity point.
    pub fn verify_zero_constant(&self) -> Result<bool, ThresholdError> {
        if self.commitments.is_empty() {
            return Err(ThresholdError::KeyRefreshFailed(
                "No commitments provided".into(),
            ));
        }

        let identity = match self.scheme {
            ThresholdScheme::ThresholdEcdsaP256 => FeldmanVss::identity_point(EcdsaCurve::P256),
            ThresholdScheme::ThresholdEcdsaSecp256k1 => {
                FeldmanVss::identity_point(EcdsaCurve::Secp256k1)
            }
            ThresholdScheme::FrostEd25519 => {
                // For Ed25519, the identity point is (0, 1) with compressed encoding
                // The compressed form is the y-coordinate with sign bit
                use curve25519_dalek::edwards::EdwardsPoint;
                let identity_point = EdwardsPoint::default();
                identity_point.compress().to_bytes().to_vec()
            }
            ThresholdScheme::ThresholdBls12381 => {
                // BLS G1 identity (point at infinity) - compressed form
                // The identity point in compressed G1 is a single byte 0xc0 followed by zeros
                let mut identity_bytes = vec![0xc0u8];
                identity_bytes.extend(vec![0u8; 47]);
                identity_bytes
            }
        };

        // Check if first commitment is identity
        Ok(self.commitments[0] == identity)
    }
}

/// Package sent during Round 2 of the refresh protocol.
///
/// Contains the refresh share for a specific receiver.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RefreshRound2Package {
    /// The participant who generated this share.
    #[zeroize(skip)]
    pub sender: ParticipantId,
    /// The intended receiver of this share.
    #[zeroize(skip)]
    pub receiver: ParticipantId,
    /// The refresh share (encrypted in production).
    pub refresh_share: Vec<u8>,
    /// The threshold scheme.
    #[zeroize(skip)]
    pub scheme: ThresholdScheme,
}

impl RefreshRound2Package {
    /// Create a new Round 2 package.
    pub fn new(
        sender: ParticipantId,
        receiver: ParticipantId,
        refresh_share: Vec<u8>,
        scheme: ThresholdScheme,
    ) -> Self {
        Self {
            sender,
            receiver,
            refresh_share,
            scheme,
        }
    }
}

impl std::fmt::Debug for RefreshRound2Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshRound2Package")
            .field("sender", &self.sender)
            .field("receiver", &self.receiver)
            .field("refresh_share", &"<redacted>")
            .field("scheme", &self.scheme)
            .finish()
    }
}

/// Key refresh protocol for proactive security.
///
/// This protocol allows participants to update their shares while preserving
/// the group public key. The key insight is that each participant generates
/// a polynomial with ZERO as the constant term, ensuring that the sum of all
/// refresh contributions is zero, leaving the group key unchanged.
pub struct KeyRefreshProtocol {
    /// Configuration for the refresh.
    config: KeyRefreshConfig,
    /// Current protocol state.
    state: RefreshState,
    /// Collected Round 1 packages from all participants.
    round1_packages: HashMap<ParticipantId, RefreshRound1Package>,
    /// Collected Round 2 packages for this participant.
    round2_packages: HashMap<ParticipantId, RefreshRound2Package>,
    /// This participant's ID.
    participant_id: ParticipantId,
    /// This participant's polynomial coefficients (generated in Round 1).
    my_coefficients: Vec<Vec<u8>>,
}

impl KeyRefreshProtocol {
    /// Create a new key refresh protocol instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the refresh operation
    /// * `participant_id` - This participant's ID
    ///
    /// # Returns
    ///
    /// A new KeyRefreshProtocol instance ready for Round 1.
    pub fn new(
        config: KeyRefreshConfig,
        participant_id: ParticipantId,
    ) -> Result<Self, ThresholdError> {
        config.validate()?;

        if !config.participants.contains(&participant_id) {
            return Err(ThresholdError::InvalidParticipant(
                "Participant not in refresh group".into(),
            ));
        }

        Ok(Self {
            config,
            state: RefreshState::NotStarted,
            round1_packages: HashMap::new(),
            round2_packages: HashMap::new(),
            participant_id,
            my_coefficients: Vec::new(),
        })
    }

    /// Get the current protocol state.
    pub fn state(&self) -> &RefreshState {
        &self.state
    }

    /// Execute Round 1: Generate refresh polynomial and commitments.
    ///
    /// Each participant generates a polynomial f(x) = a_1*x + a_2*x^2 + ...
    /// with ZERO constant term (a_0 = 0). This ensures that when all refresh
    /// shares are combined, the group secret remains unchanged.
    ///
    /// # Returns
    ///
    /// A RefreshRound1Package containing Feldman commitments.
    pub fn round1(&mut self) -> Result<RefreshRound1Package, ThresholdError> {
        if self.state != RefreshState::NotStarted {
            return Err(ThresholdError::KeyRefreshFailed(
                "Round 1 already completed or protocol failed".into(),
            ));
        }

        let degree = self.config.current_config.threshold - 1;

        // Generate polynomial with ZERO constant term
        let coefficients = self.generate_zero_constant_polynomial(degree)?;

        // Generate Feldman commitments
        let commitments = self.generate_commitments(&coefficients)?;

        // Store coefficients for Round 2
        self.my_coefficients = coefficients;

        let package =
            RefreshRound1Package::new(self.participant_id, commitments, self.config.scheme);

        self.state = RefreshState::Round1Complete;

        Ok(package)
    }

    /// Process a Round 1 package from another participant.
    ///
    /// # Arguments
    ///
    /// * `package` - The Round 1 package from another participant
    ///
    /// # Returns
    ///
    /// `Ok(())` if the package is valid and stored.
    pub fn process_round1_package(
        &mut self,
        package: RefreshRound1Package,
    ) -> Result<(), ThresholdError> {
        // Verify the zero constant
        if !package.verify_zero_constant()? {
            return Err(ThresholdError::KeyRefreshInvalidCommitment(package.sender));
        }

        // Store the package
        self.round1_packages.insert(package.sender, package);

        Ok(())
    }

    /// Execute Round 2: Generate refresh shares for all participants.
    ///
    /// After receiving and verifying all Round 1 packages, each participant
    /// evaluates their refresh polynomial at each participant's ID to generate
    /// the refresh shares.
    ///
    /// # Returns
    ///
    /// A vector of RefreshRound2Package, one for each participant.
    pub fn round2(&mut self) -> Result<Vec<RefreshRound2Package>, ThresholdError> {
        if self.state != RefreshState::Round1Complete {
            return Err(ThresholdError::KeyRefreshFailed(
                "Must complete Round 1 first".into(),
            ));
        }

        // Verify we have all Round 1 packages
        if self.round1_packages.len() < self.config.participants.len() - 1 {
            return Err(ThresholdError::KeyRefreshMissingCommitments);
        }

        let mut packages = Vec::new();

        for &receiver in &self.config.participants {
            let refresh_share = self.evaluate_polynomial_at(&self.my_coefficients, receiver.0)?;

            packages.push(RefreshRound2Package::new(
                self.participant_id,
                receiver,
                refresh_share,
                self.config.scheme,
            ));
        }

        self.state = RefreshState::Round2Complete;

        Ok(packages)
    }

    /// Process a Round 2 package from another participant.
    ///
    /// # Arguments
    ///
    /// * `package` - The Round 2 package intended for this participant
    ///
    /// # Returns
    ///
    /// `Ok(())` if the package is valid and stored.
    pub fn process_round2_package(
        &mut self,
        package: RefreshRound2Package,
    ) -> Result<(), ThresholdError> {
        if package.receiver != self.participant_id {
            return Err(ThresholdError::InvalidParticipant(
                "Package not intended for this participant".into(),
            ));
        }

        // Verify the share against the sender's commitments
        if let Some(round1_pkg) = self.round1_packages.get(&package.sender) {
            let valid =
                self.verify_refresh_share(&package.refresh_share, &round1_pkg.commitments)?;
            if !valid {
                return Err(ThresholdError::KeyRefreshInvalidShare(package.sender));
            }
        }

        self.round2_packages.insert(package.sender, package);

        Ok(())
    }

    /// Finalize the refresh protocol and compute the new key share.
    ///
    /// After receiving all Round 2 packages, combine the refresh shares with
    /// the old share to produce the new share.
    ///
    /// # Arguments
    ///
    /// * `old_share` - The participant's current key share
    ///
    /// # Returns
    ///
    /// The new KeyShare with updated secret but same public key.
    pub fn finalize(&mut self, old_share: &KeyShare) -> Result<KeyShare, ThresholdError> {
        if self.state != RefreshState::Round2Complete {
            return Err(ThresholdError::KeyRefreshFailed(
                "Must complete Round 2 first".into(),
            ));
        }

        // Verify we have all Round 2 packages
        // Note: We might not have packages from all participants if some are offline,
        // but we should have at least threshold packages
        let expected_packages = self.config.participants.len();
        if self.round2_packages.len() + 1 < expected_packages {
            // +1 for our own share
            return Err(ThresholdError::KeyRefreshFailed(
                "Missing refresh shares from some participants".into(),
            ));
        }

        // Combine all refresh shares
        let mut new_secret_share = old_share.secret_share.clone();

        // Add our own refresh share
        let my_refresh_share =
            self.evaluate_polynomial_at(&self.my_coefficients, self.participant_id.0)?;
        new_secret_share = self.add_shares(&new_secret_share, &my_refresh_share)?;

        // Add all received refresh shares
        for package in self.round2_packages.values() {
            new_secret_share = self.add_shares(&new_secret_share, &package.refresh_share)?;
        }

        // Create new KeyShare with same config but updated secret
        let new_share = KeyShare::new(
            self.participant_id,
            old_share.config,
            new_secret_share,
            old_share.public_key_share.clone(), // Public share doesn't change
        );

        self.state = RefreshState::Complete;

        Ok(new_share)
    }

    // ========== Internal Helper Methods ==========

    /// Generate a polynomial with zero constant term.
    fn generate_zero_constant_polynomial(
        &self,
        degree: u16,
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
        let curve = match self.config.scheme {
            ThresholdScheme::ThresholdEcdsaP256 => Some(EcdsaCurve::P256),
            ThresholdScheme::ThresholdEcdsaSecp256k1 => Some(EcdsaCurve::Secp256k1),
            ThresholdScheme::FrostEd25519 | ThresholdScheme::ThresholdBls12381 => None,
        };

        match curve {
            Some(c) => {
                // Generate polynomial with zero constant term
                let zero = FeldmanVss::zero_scalar(c);
                let mut coefficients = vec![zero];

                // Generate random coefficients for higher degrees
                for _ in 0..degree {
                    let coeff = match c {
                        EcdsaCurve::P256 => {
                            P256ThresholdOps::scalar_to_bytes(&P256ThresholdOps::random_scalar())
                        }
                        EcdsaCurve::Secp256k1 => Secp256k1ThresholdOps::scalar_to_bytes(
                            &Secp256k1ThresholdOps::random_scalar(),
                        ),
                    };
                    coefficients.push(coeff);
                }

                Ok(coefficients)
            }
            None => {
                // For FROST and BLS, generate 32-byte zero scalar and random coefficients
                let zero = vec![0u8; 32];
                let mut coefficients = vec![zero];

                for _ in 0..degree {
                    use rand_core::{OsRng, RngCore};
                    let mut coeff = vec![0u8; 32];
                    OsRng.fill_bytes(&mut coeff);
                    coefficients.push(coeff);
                }

                Ok(coefficients)
            }
        }
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
            ThresholdScheme::FrostEd25519 => {
                // Generate commitments for Ed25519
                self.generate_ed25519_commitments(coefficients)
            }
            ThresholdScheme::ThresholdBls12381 => {
                // Generate commitments for BLS
                self.generate_bls_commitments(coefficients)
            }
        }
    }

    /// Generate Ed25519 Feldman commitments.
    fn generate_ed25519_commitments(
        &self,
        coefficients: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
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
    fn generate_bls_commitments(
        &self,
        coefficients: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, ThresholdError> {
        use blst::{
            blst_p1, blst_p1_compress, blst_p1_mult, blst_scalar, blst_scalar_from_bendian,
        };

        let mut commitments = Vec::with_capacity(coefficients.len());

        for coeff_bytes in coefficients {
            if coeff_bytes.len() != 32 {
                return Err(ThresholdError::SerializationError(
                    "BLS coefficient must be 32 bytes".into(),
                ));
            }

            // For zero coefficient, the commitment is the identity
            if coeff_bytes.iter().all(|&b| b == 0) {
                // Identity point in compressed G1: first byte 0xc0, rest zeros
                let mut identity_bytes = vec![0xc0u8];
                identity_bytes.extend(vec![0u8; 47]);
                commitments.push(identity_bytes);
            } else {
                // For non-zero coefficients, compute commitment = coeff * G1.
                //
                // `blst_p1_mult` reads the scalar as a *little-endian* byte array, so the
                // big-endian `coeff_bytes` MUST first be converted via
                // `blst_scalar_from_bendian` (which fills the little-endian `.b` limbs).
                // Passing `coeff_bytes` directly would byte-reverse the scalar and produce a
                // commitment to `reverse(coeff)` instead of `coeff`, so verification against the
                // field-reduced share (computed with `blst_fr`) would always fail. This mirrors
                // the correct reference in `bls/dkg.rs::scalar_mult_g1` and `verify_bls_share`.
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

    /// Evaluate polynomial at a given x-coordinate.
    fn evaluate_polynomial_at(
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
            ThresholdScheme::FrostEd25519 => self.evaluate_ed25519_polynomial(coefficients, x),
            ThresholdScheme::ThresholdBls12381 => self.evaluate_bls_polynomial(coefficients, x),
        }
    }

    /// Evaluate Ed25519 polynomial using Horner's method.
    fn evaluate_ed25519_polynomial(
        &self,
        coefficients: &[Vec<u8>],
        x: u16,
    ) -> Result<Vec<u8>, ThresholdError> {
        use curve25519_dalek::scalar::Scalar;

        if coefficients.is_empty() {
            return Err(ThresholdError::KeyRefreshFailed("Empty polynomial".into()));
        }

        let x_scalar = Scalar::from(x as u64);
        let mut result = Scalar::ZERO;

        // Horner's method: work from highest to lowest coefficient
        for coeff_bytes in coefficients.iter().rev() {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(coeff_bytes);
            let coeff = Scalar::from_bytes_mod_order(bytes);
            result = result * x_scalar + coeff;
        }

        Ok(result.to_bytes().to_vec())
    }

    /// Evaluate BLS polynomial using Horner's method.
    fn evaluate_bls_polynomial(
        &self,
        coefficients: &[Vec<u8>],
        x: u16,
    ) -> Result<Vec<u8>, ThresholdError> {
        use blst::{
            blst_bendian_from_scalar, blst_fr, blst_fr_add, blst_fr_from_scalar, blst_fr_mul,
            blst_scalar, blst_scalar_from_bendian, blst_scalar_from_fr,
        };

        if coefficients.is_empty() {
            return Err(ThresholdError::KeyRefreshFailed("Empty polynomial".into()));
        }

        // Convert x to scalar/fr
        let mut x_bytes = [0u8; 32];
        x_bytes[30] = (x >> 8) as u8;
        x_bytes[31] = x as u8;

        let mut x_scalar = blst_scalar::default();
        let mut x_fr = blst_fr::default();
        // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from x_bytes (a [u8; 32]) and writes
        // to caller-owned x_scalar; blst_fr_from_scalar reads x_scalar and writes to caller-owned x_fr.
        unsafe {
            blst_scalar_from_bendian(&mut x_scalar, x_bytes.as_ptr());
            blst_fr_from_scalar(&mut x_fr, &x_scalar);
        }

        // Initialize result with highest coefficient (Horner's method)
        let mut result_fr = blst_fr::default();
        let mut coef_scalar = blst_scalar::default();

        let last_coef = coefficients.last().unwrap();
        let mut last_bytes = [0u8; 32];
        last_bytes.copy_from_slice(last_coef);
        // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from last_bytes (a [u8; 32]) and writes
        // to caller-owned coef_scalar; blst_fr_from_scalar reads coef_scalar and writes to caller-owned result_fr.
        unsafe {
            blst_scalar_from_bendian(&mut coef_scalar, last_bytes.as_ptr());
            blst_fr_from_scalar(&mut result_fr, &coef_scalar);
        }

        // Horner's method: work from highest to lowest coefficient
        for coeff_bytes in coefficients.iter().rev().skip(1) {
            let mut temp = blst_fr::default();
            // SAFETY: blst_fr_mul reads valid caller-owned result_fr and x_fr and writes the product
            // to caller-owned temp.
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

        // Convert result back to bytes
        let mut result_scalar = blst_scalar::default();
        // SAFETY: blst_scalar_from_fr reads caller-owned result_fr and writes to caller-owned result_scalar.
        unsafe {
            blst_scalar_from_fr(&mut result_scalar, &result_fr);
        }

        let mut result_bytes = [0u8; 32];
        // SAFETY: blst_bendian_from_scalar writes exactly 32 bytes to result_bytes (a [u8; 32]) from
        // caller-owned result_scalar.
        unsafe {
            blst_bendian_from_scalar(result_bytes.as_mut_ptr(), &result_scalar);
        }

        Ok(result_bytes.to_vec())
    }

    /// Verify a refresh share against commitments.
    fn verify_refresh_share(
        &self,
        share: &[u8],
        commitments: &[Vec<u8>],
    ) -> Result<bool, ThresholdError> {
        match self.config.scheme {
            ThresholdScheme::ThresholdEcdsaP256 => {
                FeldmanVss::verify_share(self.participant_id, share, commitments, EcdsaCurve::P256)
            }
            ThresholdScheme::ThresholdEcdsaSecp256k1 => FeldmanVss::verify_share(
                self.participant_id,
                share,
                commitments,
                EcdsaCurve::Secp256k1,
            ),
            ThresholdScheme::FrostEd25519 => self.verify_ed25519_share(share, commitments),
            ThresholdScheme::ThresholdBls12381 => {
                // Verify share against G1 commitments (Feldman VSS) instead of
                // unconditionally accepting it. See resharing::verify_bls_share.
                super::resharing::verify_bls_share(self.participant_id, share, commitments)
            }
        }
    }

    /// Verify an Ed25519 share against commitments.
    fn verify_ed25519_share(
        &self,
        share: &[u8],
        commitments: &[Vec<u8>],
    ) -> Result<bool, ThresholdError> {
        use curve25519_dalek::{
            constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, scalar::Scalar,
        };

        // Parse share as scalar
        let mut share_bytes = [0u8; 32];
        share_bytes.copy_from_slice(share);
        let share_scalar = Scalar::from_bytes_mod_order(share_bytes);

        // Compute share * G
        let actual = ED25519_BASEPOINT_TABLE * &share_scalar;

        // Compute expected: sum(C_i * x^i) where x = participant_id
        let x = Scalar::from(self.participant_id.0 as u64);
        let mut expected = curve25519_dalek::edwards::EdwardsPoint::default();
        let mut x_pow = Scalar::ONE;

        for commitment_bytes in commitments {
            let commitment_point = CompressedEdwardsY::from_slice(commitment_bytes)
                .map_err(|_| ThresholdError::SerializationError("Invalid Ed25519 point".into()))?
                .decompress()
                .ok_or_else(|| {
                    ThresholdError::SerializationError("Invalid Ed25519 point".into())
                })?;

            expected += commitment_point * x_pow;
            x_pow *= x;
        }

        Ok(actual == expected)
    }

    /// Add two shares (scalar addition in the appropriate field).
    fn add_shares(&self, a: &[u8], b: &[u8]) -> Result<Vec<u8>, ThresholdError> {
        match self.config.scheme {
            ThresholdScheme::ThresholdEcdsaP256 => FeldmanVss::add_scalars(a, b, EcdsaCurve::P256),
            ThresholdScheme::ThresholdEcdsaSecp256k1 => {
                FeldmanVss::add_scalars(a, b, EcdsaCurve::Secp256k1)
            }
            ThresholdScheme::FrostEd25519 => self.add_ed25519_scalars(a, b),
            ThresholdScheme::ThresholdBls12381 => self.add_bls_scalars(a, b),
        }
    }

    /// Add two Ed25519 scalars.
    fn add_ed25519_scalars(&self, a: &[u8], b: &[u8]) -> Result<Vec<u8>, ThresholdError> {
        use curve25519_dalek::scalar::Scalar;

        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        a_bytes.copy_from_slice(a);
        b_bytes.copy_from_slice(b);

        let scalar_a = Scalar::from_bytes_mod_order(a_bytes);
        let scalar_b = Scalar::from_bytes_mod_order(b_bytes);
        let sum = scalar_a + scalar_b;

        Ok(sum.to_bytes().to_vec())
    }

    /// Add two BLS scalars.
    fn add_bls_scalars(&self, a: &[u8], b: &[u8]) -> Result<Vec<u8>, ThresholdError> {
        use blst::{
            blst_bendian_from_scalar, blst_fr, blst_fr_add, blst_fr_from_scalar, blst_scalar,
            blst_scalar_from_bendian, blst_scalar_from_fr,
        };

        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        a_bytes.copy_from_slice(a);
        b_bytes.copy_from_slice(b);

        let mut a_scalar = blst_scalar::default();
        let mut b_scalar = blst_scalar::default();
        let mut a_fr = blst_fr::default();
        let mut b_fr = blst_fr::default();
        let mut sum_fr = blst_fr::default();

        // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from a_bytes/b_bytes (both [u8; 32]);
        // blst_fr_from_scalar and blst_fr_add operate on caller-owned struct references.
        unsafe {
            blst_scalar_from_bendian(&mut a_scalar, a_bytes.as_ptr());
            blst_scalar_from_bendian(&mut b_scalar, b_bytes.as_ptr());
            blst_fr_from_scalar(&mut a_fr, &a_scalar);
            blst_fr_from_scalar(&mut b_fr, &b_scalar);
            blst_fr_add(&mut sum_fr, &a_fr, &b_fr);
        }

        let mut sum_scalar = blst_scalar::default();
        let mut sum_bytes = [0u8; 32];
        // SAFETY: blst_scalar_from_fr reads caller-owned sum_fr; blst_bendian_from_scalar writes exactly
        // 32 bytes to sum_bytes (a [u8; 32]).
        unsafe {
            blst_scalar_from_fr(&mut sum_scalar, &sum_fr);
            blst_bendian_from_scalar(sum_bytes.as_mut_ptr(), &sum_scalar);
        }

        Ok(sum_bytes.to_vec())
    }
}

impl Drop for KeyRefreshProtocol {
    fn drop(&mut self) {
        // Zeroize sensitive data
        for coeff in &mut self.my_coefficients {
            coeff.zeroize();
        }
    }
}
