//! BLS Distributed Key Generation (DKG)
//!
//! This module implements a 3-round DKG protocol for threshold BLS signatures
//! using the BLS12-381 curve. DKG enables decentralized key generation where
//! no single party knows the master secret.
//!
//! # Protocol Overview
//!
//! The protocol follows Pedersen's DKG with Feldman's Verifiable Secret Sharing (VSS):
//!
//! ## Round 1: Commitment
//! Each participant:
//! 1. Generates a random polynomial f_i(x) of degree (t-1)
//! 2. Computes commitments C_i,j = g1 * a_i,j for each coefficient
//! 3. Broadcasts commitments to all participants
//!
//! ## Round 2: Share Distribution
//! Each participant:
//! 1. Evaluates their polynomial at each other participant's index
//! 2. Sends s_i,j = f_i(j) to participant j (privately)
//!
//! ## Round 3: Verification and Finalization
//! Each participant:
//! 1. Verifies received shares against commitments
//! 2. Combines all valid shares to compute their secret share
//! 3. Computes the group public key from constant term commitments
//!
//! # Security Properties
//!
//! - **Verifiable**: VSS ensures participants can detect invalid shares
//! - **Threshold**: Any t-of-n participants can reconstruct/sign
//! - **No trusted dealer**: No single party ever knows the master secret
//! - **Forward secrecy**: Compromising shares later doesn't reveal past secrets
//!
//! # Example
//!
//! ```ignore
//! use hsm_crypto_engine::threshold::bls::dkg::{BlsDkg, BlsDkgRound1Package, BlsDkgRound2Package};
//! use hsm_crypto_engine::threshold::config::DkgConfig;
//! use hsm_crypto_engine::threshold::types::{ParticipantId, ThresholdScheme};
//!
//! // Setup 2-of-3 DKG
//! let participants = vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)];
//! let config = DkgConfig::new(ThresholdScheme::ThresholdBls12381, 2, participants.clone()).unwrap();
//!
//! // Each participant creates their DKG instance
//! let mut dkg1 = BlsDkg::new(config.clone(), ParticipantId(1)).unwrap();
//! let mut dkg2 = BlsDkg::new(config.clone(), ParticipantId(2)).unwrap();
//! let mut dkg3 = BlsDkg::new(config.clone(), ParticipantId(3)).unwrap();
//!
//! // Round 1: Generate and exchange commitments
//! let r1_pkg1 = dkg1.round1().unwrap();
//! let r1_pkg2 = dkg2.round1().unwrap();
//! let r1_pkg3 = dkg3.round1().unwrap();
//!
//! // Round 2: Generate and distribute shares
//! let r2_pkgs1 = dkg1.round2(vec![r1_pkg1.clone(), r1_pkg2.clone(), r1_pkg3.clone()]).unwrap();
//! // ... similar for dkg2, dkg3
//!
//! // Finalize: Each participant combines shares
//! // Filter packages for each recipient...
//! let (share1, group_pk) = dkg1.finalize(/* packages for participant 1 */).unwrap();
//! ```

use super::types::BlsKeyShare;
use crate::threshold::config::DkgConfig;
use crate::threshold::types::{GroupPublicKey, ParticipantId, ThresholdError};
use blst::{
    blst_bendian_from_scalar, blst_fr, blst_fr_add, blst_fr_from_scalar, blst_fr_mul, blst_p1,
    blst_p1_add_or_double, blst_p1_affine, blst_p1_compress, blst_p1_from_affine,
    blst_p1_generator, blst_p1_mult, blst_p1_uncompress, blst_scalar, blst_scalar_from_bendian,
    blst_scalar_from_fr, BLST_ERROR,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use zeroize::Zeroize;

/// BLS Distributed Key Generation state machine.
///
/// This struct manages the state for a single participant in the DKG protocol.
/// Create one instance per participant and follow the 3-round protocol.
pub struct BlsDkg {
    /// DKG configuration
    config: DkgConfig,
    /// This participant's identifier
    participant_id: ParticipantId,
    /// Current state of the DKG protocol
    state: BlsDkgState,

    // Round 1 data - our polynomial and commitments
    /// Secret polynomial coefficients [a_0, a_1, ..., a_{t-1}]
    secret_polynomial: Option<Vec<[u8; 32]>>,
    /// Commitments to our polynomial coefficients (G1 points)
    commitments: Option<Vec<[u8; 48]>>,

    // Round 2 data - received from others
    /// Received shares from other participants: sender_id -> share
    received_shares: HashMap<ParticipantId, [u8; 32]>,
    /// Received commitments from other participants: sender_id -> [C_0, C_1, ...]
    received_commitments: HashMap<ParticipantId, Vec<[u8; 48]>>,

    // Result
    /// The final key share after DKG completion
    key_share: Option<BlsKeyShare>,
}

/// State of the BLS DKG protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlsDkgState {
    /// DKG not yet started
    NotStarted,
    /// Round 1 complete (commitments generated)
    Round1Complete,
    /// Round 2 complete (shares distributed)
    Round2Complete,
    /// DKG successfully completed
    Complete,
    /// DKG failed with an error
    Failed(String),
}

/// Round 1 package containing commitments to share with all participants.
///
/// This package is broadcast to all participants. It contains the sender's
/// polynomial commitments which will be used to verify shares in Round 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsDkgRound1Package {
    /// The participant who created this package
    pub sender: ParticipantId,
    /// Commitments to polynomial coefficients (compressed G1 points, 48 bytes each)
    pub commitments: Vec<Vec<u8>>,
}

/// Round 2 package containing a secret share for a specific recipient.
///
/// This package must be sent privately to the specified receiver.
/// It contains the sender's polynomial evaluated at the receiver's index.
#[derive(Clone, Serialize, Deserialize)]
pub struct BlsDkgRound2Package {
    /// The participant who created this package
    pub sender: ParticipantId,
    /// The intended recipient of this share
    pub receiver: ParticipantId,
    /// The secret share (32-byte scalar, encrypted/private channel assumed)
    share: Vec<u8>,
}

impl BlsDkgRound2Package {
    /// Create a new Round 2 package
    pub fn new(sender: ParticipantId, receiver: ParticipantId, share: Vec<u8>) -> Self {
        Self {
            sender,
            receiver,
            share,
        }
    }

    /// Get the share bytes (for the recipient to use)
    pub fn share(&self) -> &[u8] {
        &self.share
    }
}

impl fmt::Debug for BlsDkgRound2Package {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlsDkgRound2Package")
            .field("sender", &self.sender)
            .field("receiver", &self.receiver)
            .field("share", &"<redacted>")
            .finish()
    }
}

impl Drop for BlsDkgRound2Package {
    fn drop(&mut self) {
        self.share.zeroize();
    }
}

impl BlsDkg {
    /// Create a new BLS DKG instance for a participant.
    ///
    /// # Arguments
    ///
    /// * `config` - The DKG configuration
    /// * `participant_id` - This participant's identifier
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Configuration is invalid
    /// - Participant ID is not in the participant list
    pub fn new(config: DkgConfig, participant_id: ParticipantId) -> Result<Self, ThresholdError> {
        // Validate configuration
        config.validate()?;

        // Check that participant_id is in the participant list
        if !config.participants.contains(&participant_id) {
            return Err(ThresholdError::InvalidParticipant(format!(
                "Participant {} is not in the DKG participant list",
                participant_id
            )));
        }

        Ok(Self {
            config,
            participant_id,
            state: BlsDkgState::NotStarted,
            secret_polynomial: None,
            commitments: None,
            received_shares: HashMap::new(),
            received_commitments: HashMap::new(),
            key_share: None,
        })
    }

    /// Get the current state of the DKG.
    pub fn state(&self) -> &BlsDkgState {
        &self.state
    }

    /// Get the participant ID for this DKG instance.
    pub fn participant_id(&self) -> ParticipantId {
        self.participant_id
    }

    /// Execute Round 1 of the DKG protocol.
    ///
    /// This generates:
    /// 1. A random polynomial f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
    /// 2. Commitments C_i = g1 * a_i for each coefficient
    ///
    /// The returned package should be broadcast to all participants.
    ///
    /// # Returns
    ///
    /// A Round 1 package containing commitments to broadcast.
    ///
    /// # Errors
    ///
    /// Returns error if DKG is not in NotStarted state.
    pub fn round1(&mut self) -> Result<BlsDkgRound1Package, ThresholdError> {
        if self.state != BlsDkgState::NotStarted {
            return Err(ThresholdError::DkgInvalidState);
        }

        let threshold = self.config.threshold_config.threshold as usize;

        // Generate random polynomial coefficients [a_0, a_1, ..., a_{t-1}]
        let mut polynomial: Vec<[u8; 32]> = Vec::with_capacity(threshold);
        for _ in 0..threshold {
            let mut coef = [0u8; 32];
            OsRng.fill_bytes(&mut coef);
            polynomial.push(coef);
        }

        // Compute commitments C_i = g1 * a_i
        let mut commitments: Vec<[u8; 48]> = Vec::with_capacity(threshold);

        for coef in &polynomial {
            let commitment = self.scalar_mult_g1(coef)?;
            commitments.push(commitment);
        }

        // Store polynomial and commitments
        self.secret_polynomial = Some(polynomial);
        self.commitments = Some(commitments.clone());

        // Update state
        self.state = BlsDkgState::Round1Complete;

        // Create and return the round 1 package
        Ok(BlsDkgRound1Package {
            sender: self.participant_id,
            commitments: commitments.iter().map(|c| c.to_vec()).collect(),
        })
    }

    /// Execute Round 2 of the DKG protocol.
    ///
    /// This processes received Round 1 packages and generates shares for each
    /// participant. Each share is the sender's polynomial evaluated at the
    /// receiver's participant ID.
    ///
    /// # Arguments
    ///
    /// * `round1_packages` - Round 1 packages from all participants (including self)
    ///
    /// # Returns
    ///
    /// A vector of Round 2 packages. Each package should be sent privately
    /// to its designated receiver.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - DKG is not in Round1Complete state
    /// - Missing packages from participants
    /// - Invalid commitments received
    pub fn round2(
        &mut self,
        round1_packages: Vec<BlsDkgRound1Package>,
    ) -> Result<Vec<BlsDkgRound2Package>, ThresholdError> {
        if self.state != BlsDkgState::Round1Complete {
            return Err(ThresholdError::DkgInvalidState);
        }

        // Validate we have packages from all participants
        let expected_count = self.config.participants.len();
        if round1_packages.len() != expected_count {
            return Err(ThresholdError::DkgFailed {
                round: 2,
                reason: format!(
                    "Expected {} round1 packages, got {}",
                    expected_count,
                    round1_packages.len()
                ),
            });
        }

        // Store received commitments (including our own for consistency)
        for pkg in &round1_packages {
            // Validate commitment count matches threshold
            let threshold = self.config.threshold_config.threshold as usize;
            if pkg.commitments.len() != threshold {
                return Err(ThresholdError::InvalidCommitment(pkg.sender));
            }

            // Convert commitments to fixed-size arrays
            let mut fixed_commitments: Vec<[u8; 48]> = Vec::with_capacity(threshold);
            for commitment in &pkg.commitments {
                if commitment.len() != 48 {
                    return Err(ThresholdError::InvalidCommitment(pkg.sender));
                }
                let mut fixed = [0u8; 48];
                fixed.copy_from_slice(commitment);
                fixed_commitments.push(fixed);
            }

            self.received_commitments
                .insert(pkg.sender, fixed_commitments);
        }

        // Verify we have our own polynomial
        let polynomial = self
            .secret_polynomial
            .as_ref()
            .ok_or(ThresholdError::DkgInvalidState)?;

        // Generate shares for each participant
        let mut packages = Vec::new();

        for &receiver_id in &self.config.participants {
            if receiver_id == self.participant_id {
                // We also need to store our own share (f_i(i))
                let self_share = self.evaluate_polynomial(polynomial, receiver_id.0)?;
                self.received_shares.insert(self.participant_id, self_share);
                continue;
            }

            // Evaluate our polynomial at receiver's index: f_i(j)
            let share = self.evaluate_polynomial(polynomial, receiver_id.0)?;

            packages.push(BlsDkgRound2Package::new(
                self.participant_id,
                receiver_id,
                share.to_vec(),
            ));
        }

        // Update state
        self.state = BlsDkgState::Round2Complete;

        Ok(packages)
    }

    /// Finalize the DKG protocol.
    ///
    /// This processes received Round 2 packages, verifies each share against
    /// the sender's commitments, and combines all shares to produce the final
    /// key share and group public key.
    ///
    /// # Arguments
    ///
    /// * `round2_packages` - Round 2 packages intended for this participant
    ///
    /// # Returns
    ///
    /// A tuple of (BlsKeyShare, GroupPublicKey) representing this participant's
    /// share of the distributed key and the group's combined public key.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - DKG is not in Round2Complete state
    /// - Missing shares from participants
    /// - Invalid share detected (VSS verification fails)
    pub fn finalize(
        &mut self,
        round2_packages: Vec<BlsDkgRound2Package>,
    ) -> Result<(BlsKeyShare, GroupPublicKey), ThresholdError> {
        if self.state != BlsDkgState::Round2Complete {
            return Err(ThresholdError::DkgInvalidState);
        }

        // Process received packages - only accept packages meant for us
        for pkg in round2_packages {
            if pkg.receiver != self.participant_id {
                continue; // Skip packages not meant for us
            }

            if pkg.share.len() != 32 {
                return Err(ThresholdError::DkgInvalidShare(pkg.sender));
            }

            let mut share = [0u8; 32];
            share.copy_from_slice(&pkg.share);

            // Verify the share against sender's commitments
            let sender_commitments = self
                .received_commitments
                .get(&pkg.sender)
                .ok_or(ThresholdError::DkgMissingCommitments(pkg.sender))?;

            if !self.verify_share(&share, pkg.sender, sender_commitments)? {
                return Err(ThresholdError::DkgInvalidShare(pkg.sender));
            }

            self.received_shares.insert(pkg.sender, share);
        }

        // Verify we have shares from all participants
        let expected_count = self.config.participants.len();
        if self.received_shares.len() != expected_count {
            // Find who is missing
            for &p in &self.config.participants {
                if !self.received_shares.contains_key(&p) {
                    return Err(ThresholdError::DkgMissingCommitments(p));
                }
            }
        }

        // Combine all shares: s = sum(s_j,i) for all j
        let combined_share = self.combine_shares()?;

        // Compute group public key from constant term commitments: PK = sum(C_j,0) for all j
        let group_pk = self.compute_group_public_key()?;

        // Compute our public key share
        let public_share = self.scalar_mult_g1(&combined_share)?;

        // Create the key share
        let key_share = BlsKeyShare::new(
            self.participant_id,
            self.config.threshold_config,
            combined_share.to_vec(),
            public_share.to_vec(),
            group_pk.clone(),
        );

        // Create GroupPublicKey for compatibility
        let group_public_key =
            GroupPublicKey::new(group_pk.clone(), self.config.threshold_config, group_pk);

        // Store key share and update state
        self.key_share = Some(key_share.clone());
        self.state = BlsDkgState::Complete;

        // Zeroize sensitive data
        if let Some(ref mut poly) = self.secret_polynomial {
            for coef in poly.iter_mut() {
                coef.zeroize();
            }
        }

        Ok((key_share, group_public_key))
    }

    // ========== Internal Implementation ==========

    /// Multiply a scalar by the G1 generator point.
    fn scalar_mult_g1(&self, scalar: &[u8; 32]) -> Result<[u8; 48], ThresholdError> {
        let mut scalar_repr = blst_scalar::default();
        // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from scalar (a [u8; 32]) and writes
        // to caller-owned scalar_repr.
        unsafe {
            blst_scalar_from_bendian(&mut scalar_repr, scalar.as_ptr());
        }

        // Get the generator point
        // SAFETY: blst_p1_generator returns a valid static G1 generator pointer with 'static lifetime.
        let generator_ptr = unsafe { blst_p1_generator() };
        // SAFETY: generator_ptr points to a valid static blst_p1 owned by blst; the dereference copies
        // the struct by value into a local.
        let generator = unsafe { *generator_ptr };

        let mut result = blst_p1::default();
        // SAFETY: blst_p1_mult reads caller-owned generator and scalar_repr.b (a [u8; 32] inside
        // blst_scalar, bit-length 256 passed explicitly) and writes to caller-owned result.
        unsafe {
            blst_p1_mult(&mut result, &generator, scalar_repr.b.as_ptr(), 256);
        }

        // Compress the result
        let mut compressed = [0u8; 48];
        // SAFETY: blst_p1_compress writes exactly 48 bytes to compressed (a [u8; 48]) from caller-owned result.
        unsafe {
            blst_p1_compress(compressed.as_mut_ptr(), &result);
        }

        Ok(compressed)
    }

    /// Evaluate a polynomial at a given x-coordinate.
    ///
    /// Uses Horner's method: f(x) = a_0 + x*(a_1 + x*(a_2 + ... + x*a_{t-1}))
    fn evaluate_polynomial(
        &self,
        coefficients: &[[u8; 32]],
        x: u16,
    ) -> Result<[u8; 32], ThresholdError> {
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

        Ok(result_bytes)
    }

    /// Verify a share against the sender's commitments using VSS.
    ///
    /// Verifies: G1 * share == sum(C_i * x^i) where x = our participant_id
    fn verify_share(
        &self,
        share: &[u8; 32],
        sender_id: ParticipantId,
        commitments: &[[u8; 48]],
    ) -> Result<bool, ThresholdError> {
        // Compute G1 * share (left-hand side)
        let lhs = self.scalar_mult_g1(share)?;

        // Compute sum(C_i * x^i) where x = our participant_id (right-hand side)
        let x = self.participant_id.0;

        // Initialize sum to zero (identity point)
        let mut sum = blst_p1::default();
        let mut is_first = true;

        // Compute x^i for each coefficient
        let mut x_power = [0u8; 32];
        x_power[31] = 1; // x^0 = 1

        for commitment in commitments {
            // Decompress commitment
            let mut c_affine = blst_p1_affine::default();
            let mut c_point = blst_p1::default();
            // SAFETY: blst_p1_uncompress reads exactly 48 bytes from commitment (a [u8; 48]) and writes
            // to caller-owned c_affine; blst_p1_from_affine reads caller-owned c_affine and writes to
            // caller-owned c_point.
            unsafe {
                let result = blst_p1_uncompress(&mut c_affine, commitment.as_ptr());
                if result != BLST_ERROR::BLST_SUCCESS {
                    return Err(ThresholdError::InvalidCommitment(sender_id));
                }
                blst_p1_from_affine(&mut c_point, &c_affine);
            }

            // Multiply commitment by x^i: C_i * x^i
            let mut x_power_scalar = blst_scalar::default();
            // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from x_power (a [u8; 32]).
            unsafe {
                blst_scalar_from_bendian(&mut x_power_scalar, x_power.as_ptr());
            }

            let mut scaled_c = blst_p1::default();
            // SAFETY: blst_p1_mult reads caller-owned c_point and x_power_scalar.b (a [u8; 32] inside
            // blst_scalar, bit-length 256 passed explicitly) and writes to caller-owned scaled_c.
            unsafe {
                blst_p1_mult(&mut scaled_c, &c_point, x_power_scalar.b.as_ptr(), 256);
            }

            // Add to sum
            if is_first {
                sum = scaled_c;
                is_first = false;
            } else {
                let mut new_sum = blst_p1::default();
                // SAFETY: blst_p1_add_or_double reads caller-owned sum and scaled_c and writes to caller-owned new_sum.
                unsafe {
                    blst_p1_add_or_double(&mut new_sum, &sum, &scaled_c);
                }
                sum = new_sum;
            }

            // Update x^i for next iteration: x_power *= x
            x_power = self.scalar_multiply(&x_power, x)?;
        }

        // Compress the sum (right-hand side)
        let mut rhs = [0u8; 48];
        // SAFETY: blst_p1_compress writes exactly 48 bytes to rhs (a [u8; 48]) from caller-owned sum.
        unsafe {
            blst_p1_compress(rhs.as_mut_ptr(), &sum);
        }

        // Compare LHS == RHS (constant-time comparison for security)
        Ok(subtle::ConstantTimeEq::ct_eq(&lhs[..], &rhs[..]).into())
    }

    /// Multiply a scalar by a u16 value.
    fn scalar_multiply(
        &self,
        scalar: &[u8; 32],
        multiplier: u16,
    ) -> Result<[u8; 32], ThresholdError> {
        let mut scalar_fr = blst_fr::default();
        let mut scalar_repr = blst_scalar::default();
        // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from scalar (a [u8; 32]);
        // blst_fr_from_scalar operates on caller-owned struct references.
        unsafe {
            blst_scalar_from_bendian(&mut scalar_repr, scalar.as_ptr());
            blst_fr_from_scalar(&mut scalar_fr, &scalar_repr);
        }

        // Convert multiplier to fr
        let mut mult_bytes = [0u8; 32];
        mult_bytes[30] = (multiplier >> 8) as u8;
        mult_bytes[31] = multiplier as u8;

        let mut mult_scalar = blst_scalar::default();
        let mut mult_fr = blst_fr::default();
        // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from mult_bytes (a [u8; 32]);
        // blst_fr_from_scalar operates on caller-owned struct references.
        unsafe {
            blst_scalar_from_bendian(&mut mult_scalar, mult_bytes.as_ptr());
            blst_fr_from_scalar(&mut mult_fr, &mult_scalar);
        }

        // Multiply
        let mut result_fr = blst_fr::default();
        // SAFETY: blst_fr_mul reads caller-owned scalar_fr and mult_fr and writes to caller-owned result_fr.
        unsafe {
            blst_fr_mul(&mut result_fr, &scalar_fr, &mult_fr);
        }

        // Convert back to bytes
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

    /// Combine all received shares into the final secret share.
    fn combine_shares(&self) -> Result<[u8; 32], ThresholdError> {
        let mut sum_fr = blst_fr::default();
        let mut is_first = true;

        for share in self.received_shares.values() {
            let mut share_scalar = blst_scalar::default();
            let mut share_fr = blst_fr::default();
            // SAFETY: blst_scalar_from_bendian reads exactly 32 bytes from share (a [u8; 32]);
            // blst_fr_from_scalar operates on caller-owned struct references.
            unsafe {
                blst_scalar_from_bendian(&mut share_scalar, share.as_ptr());
                blst_fr_from_scalar(&mut share_fr, &share_scalar);
            }

            if is_first {
                sum_fr = share_fr;
                is_first = false;
            } else {
                let mut new_sum = blst_fr::default();
                // SAFETY: blst_fr_add reads caller-owned sum_fr and share_fr and writes to caller-owned new_sum.
                unsafe {
                    blst_fr_add(&mut new_sum, &sum_fr, &share_fr);
                }
                sum_fr = new_sum;
            }
        }

        // Convert back to bytes
        let mut result_scalar = blst_scalar::default();
        // SAFETY: blst_scalar_from_fr reads caller-owned sum_fr and writes to caller-owned result_scalar.
        unsafe {
            blst_scalar_from_fr(&mut result_scalar, &sum_fr);
        }

        let mut result_bytes = [0u8; 32];
        // SAFETY: blst_bendian_from_scalar writes exactly 32 bytes to result_bytes (a [u8; 32]).
        unsafe {
            blst_bendian_from_scalar(result_bytes.as_mut_ptr(), &result_scalar);
        }

        Ok(result_bytes)
    }

    /// Compute the group public key from all participants' constant term commitments.
    fn compute_group_public_key(&self) -> Result<Vec<u8>, ThresholdError> {
        let mut sum = blst_p1::default();
        let mut is_first = true;

        for commitments in self.received_commitments.values() {
            // Get the constant term commitment (C_0)
            let c0 = &commitments[0];

            // Decompress
            let mut c_affine = blst_p1_affine::default();
            let mut c_point = blst_p1::default();
            // SAFETY: blst_p1_uncompress reads exactly 48 bytes from c0 (a [u8; 48]) and writes to
            // caller-owned c_affine; blst_p1_from_affine reads caller-owned c_affine and writes to caller-owned c_point.
            unsafe {
                let result = blst_p1_uncompress(&mut c_affine, c0.as_ptr());
                if result != BLST_ERROR::BLST_SUCCESS {
                    return Err(ThresholdError::CryptoError(
                        "Invalid commitment during group key computation".into(),
                    ));
                }
                blst_p1_from_affine(&mut c_point, &c_affine);
            }

            // Add to sum
            if is_first {
                sum = c_point;
                is_first = false;
            } else {
                let mut new_sum = blst_p1::default();
                // SAFETY: blst_p1_add_or_double reads caller-owned sum and c_point and writes to caller-owned new_sum.
                unsafe {
                    blst_p1_add_or_double(&mut new_sum, &sum, &c_point);
                }
                sum = new_sum;
            }
        }

        // Compress the result
        let mut compressed = [0u8; 48];
        // SAFETY: blst_p1_compress writes exactly 48 bytes to compressed (a [u8; 48]) from caller-owned sum.
        unsafe {
            blst_p1_compress(compressed.as_mut_ptr(), &sum);
        }

        Ok(compressed.to_vec())
    }
}

impl Drop for BlsDkg {
    fn drop(&mut self) {
        // Zeroize sensitive data
        if let Some(ref mut poly) = self.secret_polynomial {
            for coef in poly.iter_mut() {
                coef.zeroize();
            }
        }
        for share in self.received_shares.values_mut() {
            share.zeroize();
        }
    }
}

impl fmt::Debug for BlsDkg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlsDkg")
            .field("config", &self.config)
            .field("participant_id", &self.participant_id)
            .field("state", &self.state)
            .field("secret_polynomial", &"<redacted>")
            .field("received_shares_count", &self.received_shares.len())
            .field(
                "received_commitments_count",
                &self.received_commitments.len(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::bls::ThresholdBlsEngine;
    use crate::threshold::types::ThresholdScheme;

    fn create_dkg_config(threshold: u16, n: u16) -> DkgConfig {
        let participants: Vec<ParticipantId> = (1..=n).map(ParticipantId).collect();
        DkgConfig::new(ThresholdScheme::ThresholdBls12381, threshold, participants).unwrap()
    }

    fn run_full_dkg(threshold: u16, n: u16) -> (Vec<BlsKeyShare>, GroupPublicKey) {
        let config = create_dkg_config(threshold, n);
        let participants: Vec<ParticipantId> = (1..=n).map(ParticipantId).collect();

        // Create DKG instances for each participant
        let mut dkgs: Vec<BlsDkg> = participants
            .iter()
            .map(|&p| BlsDkg::new(config.clone(), p).unwrap())
            .collect();

        // Round 1: Generate commitments
        let round1_packages: Vec<BlsDkgRound1Package> =
            dkgs.iter_mut().map(|dkg| dkg.round1().unwrap()).collect();

        // Round 2: Generate and exchange shares
        let mut all_round2_packages: Vec<Vec<BlsDkgRound2Package>> = Vec::new();
        for dkg in &mut dkgs {
            let packages = dkg.round2(round1_packages.clone()).unwrap();
            all_round2_packages.push(packages);
        }

        // Collect packages for each participant
        let mut packages_per_participant: Vec<Vec<BlsDkgRound2Package>> =
            vec![Vec::new(); n as usize];

        for sender_packages in all_round2_packages {
            for pkg in sender_packages {
                let receiver_idx = (pkg.receiver.0 - 1) as usize;
                packages_per_participant[receiver_idx].push(pkg);
            }
        }

        // Finalize: Each participant combines shares
        let mut shares = Vec::new();
        let mut group_pk = None;

        for (i, dkg) in dkgs.iter_mut().enumerate() {
            let (share, gpk) = dkg.finalize(packages_per_participant[i].clone()).unwrap();
            shares.push(share);
            group_pk = Some(gpk);
        }

        (shares, group_pk.unwrap())
    }

    #[test]
    fn test_bls_dkg_2_of_3() {
        let (shares, group_pk) = run_full_dkg(2, 3);

        assert_eq!(shares.len(), 3);
        assert_eq!(group_pk.bytes.len(), 48);

        // All participants should have the same group public key
        for share in &shares {
            assert_eq!(share.group_public_key, group_pk.bytes);
        }

        // Each share should have the correct configuration
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.participant_id, ParticipantId((i + 1) as u16));
            assert_eq!(share.config.threshold, 2);
            assert_eq!(share.config.total_participants, 3);
        }
    }

    #[test]
    fn test_bls_dkg_3_of_5() {
        let (shares, group_pk) = run_full_dkg(3, 5);

        assert_eq!(shares.len(), 5);
        assert_eq!(group_pk.bytes.len(), 48);

        // All participants should have the same group public key
        for share in &shares {
            assert_eq!(share.group_public_key, group_pk.bytes);
        }
    }

    #[test]
    fn test_bls_dkg_invalid_share_detected() {
        let config = create_dkg_config(2, 3);
        let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();

        // Create DKG instances
        let mut dkgs: Vec<BlsDkg> = participants
            .iter()
            .map(|&p| BlsDkg::new(config.clone(), p).unwrap())
            .collect();

        // Round 1
        let round1_packages: Vec<BlsDkgRound1Package> =
            dkgs.iter_mut().map(|dkg| dkg.round1().unwrap()).collect();

        // Round 2
        let mut all_round2_packages: Vec<Vec<BlsDkgRound2Package>> = Vec::new();
        for dkg in &mut dkgs {
            let packages = dkg.round2(round1_packages.clone()).unwrap();
            all_round2_packages.push(packages);
        }

        // Tamper with a share intended for participant 1 from participant 2
        // Find the package from participant 2 to participant 1
        for pkg in &mut all_round2_packages[1] {
            if pkg.receiver == ParticipantId(1) {
                // Corrupt the share
                pkg.share[0] ^= 0xFF;
                pkg.share[1] ^= 0xFF;
            }
        }

        // Collect packages for participant 1
        let mut packages_for_p1: Vec<BlsDkgRound2Package> = Vec::new();
        for sender_packages in &all_round2_packages {
            for pkg in sender_packages {
                if pkg.receiver == ParticipantId(1) {
                    packages_for_p1.push(pkg.clone());
                }
            }
        }

        // Finalize should detect the invalid share
        let result = dkgs[0].finalize(packages_for_p1);
        assert!(matches!(result, Err(ThresholdError::DkgInvalidShare(_))));
    }

    #[test]
    fn test_bls_dkg_consistent_group_key() {
        // Run DKG multiple times and verify all participants derive the same group key
        for _ in 0..3 {
            let (shares, group_pk) = run_full_dkg(2, 3);

            // All participants should have the exact same group public key
            let expected_group_pk = &group_pk.bytes;
            for share in &shares {
                assert_eq!(
                    &share.group_public_key, expected_group_pk,
                    "Participant {} has different group public key",
                    share.participant_id.0
                );
            }
        }
    }

    #[test]
    fn test_bls_dkg_shares_sign_valid() {
        let (shares, group_pk) = run_full_dkg(2, 3);

        let message = b"Test message signed with DKG-generated keys";

        // Sign with participants 1 and 2
        let sig_share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let sig_share2 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();

        let participants = vec![shares[0].participant_id, shares[1].participant_id];
        let signature =
            ThresholdBlsEngine::aggregate(&[sig_share1, sig_share2], &participants).unwrap();

        // Verify against the group public key
        let valid = ThresholdBlsEngine::verify(&group_pk, message, &signature).unwrap();
        assert!(valid, "Signature from DKG-generated shares should verify");
    }

    #[test]
    fn test_bls_dkg_all_participant_subsets_sign_valid() {
        let (shares, group_pk) = run_full_dkg(2, 3);

        let message = b"Test with all subsets";

        // Test all possible 2-of-3 combinations
        let subsets = [
            vec![0, 1], // participants 1 and 2
            vec![0, 2], // participants 1 and 3
            vec![1, 2], // participants 2 and 3
        ];

        for subset in &subsets {
            let sig_shares: Vec<_> = subset
                .iter()
                .map(|&i| ThresholdBlsEngine::sign_share(&shares[i], message).unwrap())
                .collect();

            let participants: Vec<_> = subset.iter().map(|&i| shares[i].participant_id).collect();

            let signature = ThresholdBlsEngine::aggregate(&sig_shares, &participants).unwrap();
            let valid = ThresholdBlsEngine::verify(&group_pk, message, &signature).unwrap();

            assert!(
                valid,
                "Signature from subset {:?} should verify",
                participants
            );
        }
    }

    #[test]
    fn test_bls_dkg_3_of_5_subset_signing() {
        let (shares, group_pk) = run_full_dkg(3, 5);

        let message = b"3-of-5 threshold test";

        // Use participants 1, 3, and 5
        let selected_indices = [0, 2, 4];

        let sig_shares: Vec<_> = selected_indices
            .iter()
            .map(|&i| ThresholdBlsEngine::sign_share(&shares[i], message).unwrap())
            .collect();

        let participants: Vec<_> = selected_indices
            .iter()
            .map(|&i| shares[i].participant_id)
            .collect();

        let signature = ThresholdBlsEngine::aggregate(&sig_shares, &participants).unwrap();
        let valid = ThresholdBlsEngine::verify(&group_pk, message, &signature).unwrap();

        assert!(valid, "3-of-5 signature should verify");
    }

    #[test]
    fn test_bls_dkg_state_transitions() {
        let config = create_dkg_config(2, 3);
        let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();

        // Create DKG instances for all participants
        let mut dkgs: Vec<BlsDkg> = participants
            .iter()
            .map(|&p| BlsDkg::new(config.clone(), p).unwrap())
            .collect();

        // Initial state
        assert_eq!(dkgs[0].state(), &BlsDkgState::NotStarted);

        // Round 1 for all participants
        let round1_packages: Vec<BlsDkgRound1Package> =
            dkgs.iter_mut().map(|dkg| dkg.round1().unwrap()).collect();

        assert_eq!(dkgs[0].state(), &BlsDkgState::Round1Complete);

        // Cannot run round1 again
        assert!(matches!(
            dkgs[0].round1(),
            Err(ThresholdError::DkgInvalidState)
        ));

        // Round 2 for participant 1
        let _ = dkgs[0].round2(round1_packages.clone()).unwrap();
        assert_eq!(dkgs[0].state(), &BlsDkgState::Round2Complete);

        // Cannot run round2 again
        assert!(matches!(
            dkgs[0].round2(vec![]),
            Err(ThresholdError::DkgInvalidState)
        ));

        // Cannot finalize without being in Round2Complete state
        let mut fresh_dkg = BlsDkg::new(config.clone(), ParticipantId(1)).unwrap();
        assert!(matches!(
            fresh_dkg.finalize(vec![]),
            Err(ThresholdError::DkgInvalidState)
        ));
    }

    #[test]
    fn test_bls_dkg_invalid_participant() {
        let config = create_dkg_config(2, 3);

        // Try to create DKG for a participant not in the list
        let result = BlsDkg::new(config, ParticipantId(10));
        assert!(matches!(result, Err(ThresholdError::InvalidParticipant(_))));
    }

    #[test]
    fn test_bls_dkg_polynomial_evaluation() {
        let config = create_dkg_config(2, 3);
        let dkg = BlsDkg::new(config, ParticipantId(1)).unwrap();

        // Create a simple polynomial: f(x) = 5 + 3x
        // f(1) = 8, f(2) = 11, f(3) = 14
        let mut coef0 = [0u8; 32];
        coef0[31] = 5;
        let mut coef1 = [0u8; 32];
        coef1[31] = 3;

        let polynomial = vec![coef0, coef1];

        let result_at_1 = dkg.evaluate_polynomial(&polynomial, 1).unwrap();
        assert_eq!(result_at_1[31], 8);

        let result_at_2 = dkg.evaluate_polynomial(&polynomial, 2).unwrap();
        assert_eq!(result_at_2[31], 11);

        let result_at_3 = dkg.evaluate_polynomial(&polynomial, 3).unwrap();
        assert_eq!(result_at_3[31], 14);
    }

    #[test]
    fn test_bls_dkg_deterministic_signatures() {
        // DKG-generated shares should produce deterministic signatures (BLS property)
        let (shares, group_pk) = run_full_dkg(2, 3);

        let message = b"Deterministic signature test";

        // Sign twice with the same shares
        let sig1_share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let sig1_share2 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
        let participants = vec![shares[0].participant_id, shares[1].participant_id];
        let signature1 =
            ThresholdBlsEngine::aggregate(&[sig1_share1, sig1_share2], &participants).unwrap();

        let sig2_share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let sig2_share2 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
        let signature2 =
            ThresholdBlsEngine::aggregate(&[sig2_share1, sig2_share2], &participants).unwrap();

        // BLS signatures are deterministic
        assert_eq!(signature1.bytes, signature2.bytes);

        // Both should verify
        assert!(ThresholdBlsEngine::verify(&group_pk, message, &signature1).unwrap());
        assert!(ThresholdBlsEngine::verify(&group_pk, message, &signature2).unwrap());
    }
}
