//! Distributed Key Generation (DKG) for threshold ECDSA
//!
//! This module implements a 3-round DKG protocol that allows n participants to
//! jointly generate ECDSA key shares without a trusted dealer. The protocol ensures
//! that no single participant ever has access to the complete private key.
//!
//! # Protocol Overview
//!
//! **Round 1 (Commitment):**
//! - Each participant generates a random polynomial of degree (t-1)
//! - Computes Feldman VSS commitments (C_i = a_i * G for each coefficient)
//! - Broadcasts commitments to all participants
//!
//! **Round 2 (Share Distribution):**
//! - Each participant evaluates their polynomial at each other participant's x-coordinate
//! - Sends the resulting secret share to that participant
//! - Verifies received shares against commitments
//!
//! **Finalization:**
//! - Each participant sums all received shares to get their final key share
//! - Computes the group public key from the constant term commitments
//! - Creates EcdsaKeyShare that's compatible with ThresholdEcdsaEngine
//!
//! # Security Properties
//!
//! - **No Trusted Dealer**: The private key is never materialized in full
//! - **Verifiability**: Feldman VSS allows detecting malicious shares
//! - **Threshold Security**: t-1 or fewer colluding parties learn nothing
//!
//! # Supported Curves
//!
//! - **P-256 (secp256r1)**: FIPS 140-3 approved
//! - **secp256k1**: Bitcoin/Ethereum compatible
//!
//! # Example
//!
//! ```ignore
//! use hsm_crypto_engine::threshold::ecdsa::dkg::*;
//! use hsm_crypto_engine::threshold::config::DkgConfig;
//! use hsm_crypto_engine::threshold::types::{EcdsaCurve, ParticipantId, ThresholdScheme};
//!
//! // Setup: 2-of-3 DKG for P-256
//! let participants = vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)];
//! let config = DkgConfig::new(ThresholdScheme::ThresholdEcdsaP256, 2, participants.clone()).unwrap();
//!
//! // Create DKG instances for each participant
//! let mut dkg1 = EcdsaDkg::new(config.clone(), ParticipantId(1), EcdsaCurve::P256).unwrap();
//! let mut dkg2 = EcdsaDkg::new(config.clone(), ParticipantId(2), EcdsaCurve::P256).unwrap();
//! let mut dkg3 = EcdsaDkg::new(config.clone(), ParticipantId(3), EcdsaCurve::P256).unwrap();
//!
//! // Round 1: Generate and exchange commitments
//! let r1_pkg1 = dkg1.round1_generate_commitments().unwrap();
//! let r1_pkg2 = dkg2.round1_generate_commitments().unwrap();
//! let r1_pkg3 = dkg3.round1_generate_commitments().unwrap();
//!
//! dkg1.round1_receive_commitments(vec![r1_pkg2.clone(), r1_pkg3.clone()]).unwrap();
//! dkg2.round1_receive_commitments(vec![r1_pkg1.clone(), r1_pkg3.clone()]).unwrap();
//! dkg3.round1_receive_commitments(vec![r1_pkg1.clone(), r1_pkg2.clone()]).unwrap();
//!
//! // Round 2: Generate and exchange shares
//! let r2_pkgs1 = dkg1.round2_generate_shares().unwrap();
//! let r2_pkgs2 = dkg2.round2_generate_shares().unwrap();
//! let r2_pkgs3 = dkg3.round2_generate_shares().unwrap();
//!
//! // Each participant receives shares addressed to them
//! dkg1.round2_receive_shares(vec![
//!     r2_pkgs2.iter().find(|p| p.receiver == ParticipantId(1)).unwrap().clone(),
//!     r2_pkgs3.iter().find(|p| p.receiver == ParticipantId(1)).unwrap().clone(),
//! ]).unwrap();
//! // ... similarly for dkg2, dkg3
//!
//! // Finalize: Generate key shares
//! let (share1, group_key1) = dkg1.finalize().unwrap();
//! let (share2, group_key2) = dkg2.finalize().unwrap();
//! let (share3, group_key3) = dkg3.finalize().unwrap();
//!
//! // All participants should have the same group public key
//! assert_eq!(group_key1.bytes, group_key2.bytes);
//! assert_eq!(group_key2.bytes, group_key3.bytes);
//! ```

use super::feldman::FeldmanVss;
use super::p256::P256ThresholdOps;
use super::secp256k1::Secp256k1ThresholdOps;
use super::types::{EcdsaGroupPublicKey, EcdsaKeyShare};
use crate::threshold::config::DkgConfig;
use crate::threshold::types::{EcdsaCurve, ParticipantId, ThresholdConfig, ThresholdError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// State of the ECDSA DKG protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcdsaDkgState {
    /// DKG has not started yet.
    NotStarted,
    /// Round 1 (commitment generation) is complete.
    Round1Complete,
    /// Round 2 (share distribution) is complete.
    Round2Complete,
    /// DKG completed successfully.
    Complete,
    /// DKG failed with an error.
    Failed(String),
}

impl fmt::Display for EcdsaDkgState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EcdsaDkgState::NotStarted => write!(f, "NotStarted"),
            EcdsaDkgState::Round1Complete => write!(f, "Round1Complete"),
            EcdsaDkgState::Round2Complete => write!(f, "Round2Complete"),
            EcdsaDkgState::Complete => write!(f, "Complete"),
            EcdsaDkgState::Failed(reason) => write!(f, "Failed({})", reason),
        }
    }
}

/// Round 1 package containing Feldman VSS commitments.
///
/// Each participant broadcasts this package after generating their polynomial.
/// The commitments allow others to verify shares received in Round 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdsaDkgRound1Package {
    /// The participant who created this package.
    pub sender: ParticipantId,
    /// Feldman VSS commitments (C_i = a_i * G for polynomial coefficients).
    /// Each commitment is a 33-byte compressed point.
    pub commitments: Vec<Vec<u8>>,
}

impl EcdsaDkgRound1Package {
    /// Create a new Round 1 package.
    pub fn new(sender: ParticipantId, commitments: Vec<Vec<u8>>) -> Self {
        Self {
            sender,
            commitments,
        }
    }
}

/// Round 2 package containing a secret share.
///
/// Each participant sends one package to each other participant.
/// The share must be verified against the sender's Round 1 commitments.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaDkgRound2Package {
    /// The participant who created this share.
    #[zeroize(skip)]
    pub sender: ParticipantId,
    /// The participant this share is for.
    #[zeroize(skip)]
    pub receiver: ParticipantId,
    /// The secret share f_sender(receiver) (32 bytes).
    pub share: Vec<u8>,
}

impl EcdsaDkgRound2Package {
    /// Create a new Round 2 package.
    pub fn new(sender: ParticipantId, receiver: ParticipantId, share: Vec<u8>) -> Self {
        Self {
            sender,
            receiver,
            share,
        }
    }
}

impl fmt::Debug for EcdsaDkgRound2Package {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaDkgRound2Package")
            .field("sender", &self.sender)
            .field("receiver", &self.receiver)
            .field("share", &"<redacted>")
            .finish()
    }
}

/// ECDSA Distributed Key Generation (DKG) protocol instance.
///
/// Each participant runs their own instance and exchanges messages with others.
pub struct EcdsaDkg {
    /// Configuration for this DKG.
    config: DkgConfig,
    /// This participant's identifier.
    participant_id: ParticipantId,
    /// The elliptic curve being used.
    curve: EcdsaCurve,
    /// Current protocol state.
    state: EcdsaDkgState,
    /// This participant's polynomial coefficients (secret).
    polynomial_coefficients: Vec<Vec<u8>>,
    /// This participant's own commitments.
    own_commitments: Vec<Vec<u8>>,
    /// Received commitments from other participants (indexed by sender ID).
    received_commitments: HashMap<u16, Vec<Vec<u8>>>,
    /// Received shares from other participants.
    received_shares: HashMap<u16, Vec<u8>>,
    /// This participant's share of their own polynomial (f_self(self)).
    own_share: Vec<u8>,
}

impl Drop for EcdsaDkg {
    fn drop(&mut self) {
        // Zeroize secret data
        for coeff in &mut self.polynomial_coefficients {
            coeff.zeroize();
        }
        for share in self.received_shares.values_mut() {
            share.zeroize();
        }
        self.own_share.zeroize();
    }
}

impl EcdsaDkg {
    /// Create a new DKG instance.
    ///
    /// # Arguments
    ///
    /// * `config` - The DKG configuration
    /// * `participant_id` - This participant's identifier
    /// * `curve` - The elliptic curve to use
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - The participant ID is not in the config's participant list
    /// - The configuration is invalid
    pub fn new(
        config: DkgConfig,
        participant_id: ParticipantId,
        curve: EcdsaCurve,
    ) -> Result<Self, ThresholdError> {
        // Validate config
        config.validate()?;

        // Check participant is in the list
        if !config.participants.contains(&participant_id) {
            return Err(ThresholdError::InvalidParticipant(format!(
                "Participant {} not in DKG participant list",
                participant_id
            )));
        }

        Ok(Self {
            config,
            participant_id,
            curve,
            state: EcdsaDkgState::NotStarted,
            polynomial_coefficients: Vec::new(),
            own_commitments: Vec::new(),
            received_commitments: HashMap::new(),
            received_shares: HashMap::new(),
            own_share: Vec::new(),
        })
    }

    /// Get the current DKG state.
    pub fn state(&self) -> &EcdsaDkgState {
        &self.state
    }

    /// Get this participant's ID.
    pub fn participant_id(&self) -> ParticipantId {
        self.participant_id
    }

    /// Get the curve being used.
    pub fn curve(&self) -> EcdsaCurve {
        self.curve
    }

    /// Round 1: Generate polynomial and commitments.
    ///
    /// Each participant generates a random polynomial of degree (t-1) where t is the threshold.
    /// The constant term contributes to the final secret key.
    /// Commitments are computed using Feldman VSS.
    ///
    /// # Returns
    ///
    /// A Round 1 package to broadcast to all other participants.
    ///
    /// # Errors
    ///
    /// Returns error if DKG is not in the NotStarted state.
    pub fn round1_generate_commitments(&mut self) -> Result<EcdsaDkgRound1Package, ThresholdError> {
        if self.state != EcdsaDkgState::NotStarted {
            return Err(ThresholdError::DkgInvalidState);
        }

        // Polynomial degree is (threshold - 1)
        let degree = self.config.threshold_config.threshold - 1;

        // Generate random polynomial with random constant term (our secret contribution)
        let coefficients = FeldmanVss::generate_polynomial(degree, None, self.curve)?;

        // Generate Feldman commitments
        let commitments = FeldmanVss::generate_commitments(&coefficients, self.curve)?;

        // Compute our own share f(self)
        let own_share =
            FeldmanVss::evaluate_polynomial(&coefficients, self.participant_id.0, self.curve)?;

        // Store state
        self.polynomial_coefficients = coefficients;
        self.own_commitments = commitments.clone();
        self.own_share = own_share;

        // Store our own commitments in the received map (for completeness)
        self.received_commitments
            .insert(self.participant_id.0, self.own_commitments.clone());

        Ok(EcdsaDkgRound1Package::new(self.participant_id, commitments))
    }

    /// Round 1: Receive commitments from other participants.
    ///
    /// After generating and broadcasting our commitments, we receive commitments
    /// from all other participants and store them for verification in Round 2.
    ///
    /// # Arguments
    ///
    /// * `packages` - Round 1 packages from other participants
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - DKG is not in the NotStarted state (called before generating own commitments)
    /// - Duplicate packages from the same sender
    /// - Package from unknown participant
    /// - Wrong number of commitments
    pub fn round1_receive_commitments(
        &mut self,
        packages: Vec<EcdsaDkgRound1Package>,
    ) -> Result<(), ThresholdError> {
        // Must have generated own commitments first
        if self.own_commitments.is_empty() {
            return Err(ThresholdError::DkgInvalidState);
        }

        let expected_commitment_count = self.config.threshold_config.threshold as usize;

        for package in packages {
            // Check sender is a valid participant
            if !self.config.participants.contains(&package.sender) {
                return Err(ThresholdError::InvalidParticipant(format!(
                    "Unknown participant {} in Round 1",
                    package.sender
                )));
            }

            // Skip our own package if received
            if package.sender == self.participant_id {
                continue;
            }

            // Check for duplicates
            if self.received_commitments.contains_key(&package.sender.0) {
                return Err(ThresholdError::InvalidParticipant(format!(
                    "Duplicate Round 1 package from {}",
                    package.sender
                )));
            }

            // Validate commitment count
            if package.commitments.len() != expected_commitment_count {
                return Err(ThresholdError::DkgFailed {
                    round: 1,
                    reason: format!(
                        "Wrong number of commitments from {}: expected {}, got {}",
                        package.sender,
                        expected_commitment_count,
                        package.commitments.len()
                    ),
                });
            }

            // Validate each commitment is a valid point
            for commitment in package.commitments.iter() {
                Self::validate_point(commitment, self.curve)
                    .map_err(|_| ThresholdError::InvalidCommitment(package.sender))?;
            }

            self.received_commitments
                .insert(package.sender.0, package.commitments);
        }

        // Check we have all commitments
        let total = self.config.participants.len();
        if self.received_commitments.len() == total {
            self.state = EcdsaDkgState::Round1Complete;
        }

        Ok(())
    }

    /// Round 2: Generate shares for all other participants.
    ///
    /// Evaluates our polynomial at each other participant's x-coordinate
    /// and creates encrypted share packages.
    ///
    /// # Returns
    ///
    /// A vector of Round 2 packages, one for each other participant.
    /// Each package should be sent only to its intended receiver.
    ///
    /// # Errors
    ///
    /// Returns error if DKG is not in Round1Complete state.
    pub fn round2_generate_shares(&mut self) -> Result<Vec<EcdsaDkgRound2Package>, ThresholdError> {
        if self.state != EcdsaDkgState::Round1Complete {
            return Err(ThresholdError::DkgInvalidState);
        }

        let mut packages = Vec::new();

        for &receiver in &self.config.participants {
            if receiver == self.participant_id {
                // Don't send share to ourselves
                continue;
            }

            // Evaluate our polynomial at the receiver's x-coordinate
            let share = FeldmanVss::evaluate_polynomial(
                &self.polynomial_coefficients,
                receiver.0,
                self.curve,
            )?;

            packages.push(EcdsaDkgRound2Package::new(
                self.participant_id,
                receiver,
                share,
            ));
        }

        // Store our own share (already computed in Round 1)
        self.received_shares
            .insert(self.participant_id.0, self.own_share.clone());

        Ok(packages)
    }

    /// Round 2: Receive and verify shares from other participants.
    ///
    /// Each received share is verified against the sender's Round 1 commitments
    /// using Feldman VSS verification.
    ///
    /// # Arguments
    ///
    /// * `packages` - Round 2 packages addressed to this participant
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - DKG is not in Round1Complete state
    /// - Package not addressed to this participant
    /// - Share fails Feldman VSS verification (potential malicious behavior)
    /// - Duplicate share from same sender
    pub fn round2_receive_shares(
        &mut self,
        packages: Vec<EcdsaDkgRound2Package>,
    ) -> Result<(), ThresholdError> {
        if self.state != EcdsaDkgState::Round1Complete {
            return Err(ThresholdError::DkgInvalidState);
        }

        for package in packages {
            // Verify package is addressed to us
            if package.receiver != self.participant_id {
                return Err(ThresholdError::DkgFailed {
                    round: 2,
                    reason: format!(
                        "Received share addressed to {} but we are {}",
                        package.receiver, self.participant_id
                    ),
                });
            }

            // Check sender is a valid participant
            if !self.config.participants.contains(&package.sender) {
                return Err(ThresholdError::InvalidParticipant(format!(
                    "Unknown sender {} in Round 2",
                    package.sender
                )));
            }

            // Skip our own share
            if package.sender == self.participant_id {
                continue;
            }

            // Check for duplicates
            if self.received_shares.contains_key(&package.sender.0) {
                return Err(ThresholdError::DkgFailed {
                    round: 2,
                    reason: format!("Duplicate share from {}", package.sender),
                });
            }

            // Get sender's commitments
            let sender_commitments = self
                .received_commitments
                .get(&package.sender.0)
                .ok_or(ThresholdError::DkgMissingCommitments(package.sender))?;

            // Verify share against commitments
            let valid = FeldmanVss::verify_share(
                self.participant_id,
                &package.share,
                sender_commitments,
                self.curve,
            )?;

            if !valid {
                return Err(ThresholdError::DkgInvalidShare(package.sender));
            }

            self.received_shares
                .insert(package.sender.0, package.share.clone());
        }

        // Check we have all shares
        let total = self.config.participants.len();
        if self.received_shares.len() == total {
            self.state = EcdsaDkgState::Round2Complete;
        }

        Ok(())
    }

    /// Finalize: Compute final key share and group public key.
    ///
    /// Sums all received shares to get the final secret share.
    /// Computes the group public key by summing all participants' constant term commitments.
    ///
    /// # Returns
    ///
    /// Tuple of (EcdsaKeyShare, EcdsaGroupPublicKey).
    /// The key share is compatible with ThresholdEcdsaEngine for signing.
    ///
    /// # Errors
    ///
    /// Returns error if DKG is not in Round2Complete state.
    pub fn finalize(mut self) -> Result<(EcdsaKeyShare, EcdsaGroupPublicKey), ThresholdError> {
        if self.state != EcdsaDkgState::Round2Complete {
            return Err(ThresholdError::DkgInvalidState);
        }

        // Sum all received shares to get our final secret share
        // x_i = sum_j f_j(i) where j iterates over all participants
        let mut final_share = FeldmanVss::zero_scalar(self.curve);
        for share in self.received_shares.values() {
            final_share = FeldmanVss::add_scalars(&final_share, share, self.curve)?;
        }

        // Compute group public key by summing all constant term commitments
        // Y = sum_j C_j[0] where C_j[0] is the first commitment from participant j
        let mut group_public_bytes = FeldmanVss::identity_point(self.curve);
        for commitments in self.received_commitments.values() {
            if commitments.is_empty() {
                return Err(ThresholdError::DkgFailed {
                    round: 3,
                    reason: "Empty commitments found during finalization".into(),
                });
            }
            group_public_bytes =
                FeldmanVss::add_points(&group_public_bytes, &commitments[0], self.curve)?;
        }

        // Compute our public share: final_share * G
        let public_share = Self::scalar_to_point(&final_share, self.curve)?;

        // Create threshold config
        let threshold_config = ThresholdConfig::new(
            self.config.threshold_config.threshold,
            self.config.threshold_config.total_participants,
        )?;

        // Create key share
        let key_share = EcdsaKeyShare::new(
            self.participant_id,
            threshold_config,
            final_share,
            public_share,
            group_public_bytes.clone(),
            self.curve,
        );

        // Create group public key
        let group_public_key =
            EcdsaGroupPublicKey::new(group_public_bytes, threshold_config, self.curve);

        // Update state (will be dropped anyway, but for consistency)
        self.state = EcdsaDkgState::Complete;

        Ok((key_share, group_public_key))
    }

    // Helper: validate a point is on the curve
    fn validate_point(bytes: &[u8], curve: EcdsaCurve) -> Result<(), ThresholdError> {
        match curve {
            EcdsaCurve::P256 => {
                P256ThresholdOps::point_from_bytes(bytes)?;
                Ok(())
            }
            EcdsaCurve::Secp256k1 => {
                Secp256k1ThresholdOps::point_from_bytes(bytes)?;
                Ok(())
            }
        }
    }

    // Helper: compute scalar * G
    fn scalar_to_point(scalar: &[u8], curve: EcdsaCurve) -> Result<Vec<u8>, ThresholdError> {
        match curve {
            EcdsaCurve::P256 => {
                let s = P256ThresholdOps::scalar_from_bytes(scalar)?;
                let p = P256ThresholdOps::scalar_to_point(&s);
                Ok(P256ThresholdOps::point_to_bytes(&p))
            }
            EcdsaCurve::Secp256k1 => {
                let s = Secp256k1ThresholdOps::scalar_from_bytes(scalar)?;
                let p = Secp256k1ThresholdOps::scalar_to_point(&s);
                Ok(Secp256k1ThresholdOps::point_to_bytes(&p))
            }
        }
    }
}

impl fmt::Debug for EcdsaDkg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaDkg")
            .field("participant_id", &self.participant_id)
            .field("curve", &self.curve)
            .field("state", &self.state)
            .field("polynomial_coefficients", &"<redacted>")
            .field(
                "own_commitments",
                &format!("[{} commitments]", self.own_commitments.len()),
            )
            .field(
                "received_commitments",
                &format!("{} participants", self.received_commitments.len()),
            )
            .field(
                "received_shares",
                &format!("{} shares", self.received_shares.len()),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::ecdsa::ThresholdEcdsaEngine;
    use crate::threshold::types::ThresholdScheme;

    /// Helper to run full DKG for n participants
    fn run_full_dkg(
        threshold: u16,
        total: u16,
        curve: EcdsaCurve,
    ) -> Result<(Vec<EcdsaKeyShare>, EcdsaGroupPublicKey), ThresholdError> {
        let participants: Vec<ParticipantId> = (1..=total).map(ParticipantId).collect();

        let scheme = match curve {
            EcdsaCurve::P256 => ThresholdScheme::ThresholdEcdsaP256,
            EcdsaCurve::Secp256k1 => ThresholdScheme::ThresholdEcdsaSecp256k1,
        };

        let config = DkgConfig::new(scheme, threshold, participants.clone())?;

        // Create DKG instances
        let mut dkgs: Vec<EcdsaDkg> = participants
            .iter()
            .map(|&p| EcdsaDkg::new(config.clone(), p, curve).unwrap())
            .collect();

        // Round 1: Generate and distribute commitments
        let mut r1_packages: Vec<EcdsaDkgRound1Package> = Vec::new();
        for dkg in &mut dkgs {
            r1_packages.push(dkg.round1_generate_commitments()?);
        }

        // Each participant receives commitments from others
        for (i, dkg) in dkgs.iter_mut().enumerate() {
            let others: Vec<_> = r1_packages
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, p)| p.clone())
                .collect();
            dkg.round1_receive_commitments(others)?;
        }

        // Round 2: Generate and distribute shares
        let mut r2_packages: Vec<Vec<EcdsaDkgRound2Package>> = Vec::new();
        for dkg in &mut dkgs {
            r2_packages.push(dkg.round2_generate_shares()?);
        }

        // Each participant receives shares addressed to them
        for (i, dkg) in dkgs.iter_mut().enumerate() {
            let receiver_id = participants[i];
            let shares: Vec<_> = r2_packages
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .flat_map(|(_, pkgs)| pkgs.iter().filter(|p| p.receiver == receiver_id).cloned())
                .collect();
            dkg.round2_receive_shares(shares)?;
        }

        // Finalize
        let results: Vec<_> = dkgs.into_iter().map(|dkg| dkg.finalize()).collect();

        let mut shares = Vec::new();
        let mut group_key = None;

        for result in results {
            let (share, gk) = result?;
            shares.push(share);
            if group_key.is_none() {
                group_key = Some(gk);
            }
        }

        Ok((shares, group_key.unwrap()))
    }

    #[test]
    fn test_ecdsa_dkg_2_of_3_p256() {
        let (shares, group_key) = run_full_dkg(2, 3, EcdsaCurve::P256).unwrap();

        assert_eq!(shares.len(), 3);
        assert!(group_key.is_fips_approved());

        // Check all shares have correct structure
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.participant_id.0, (i + 1) as u16);
            assert_eq!(share.config.threshold, 2);
            assert_eq!(share.config.total_participants, 3);
            assert_eq!(share.secret_share.len(), 32);
            assert_eq!(share.public_share.len(), 33);
            assert_eq!(share.curve, EcdsaCurve::P256);
        }

        // All shares should reference the same group public key
        for share in &shares {
            assert_eq!(share.group_public_key, group_key.bytes);
        }
    }

    #[test]
    fn test_ecdsa_dkg_3_of_5_secp256k1() {
        let (shares, group_key) = run_full_dkg(3, 5, EcdsaCurve::Secp256k1).unwrap();

        assert_eq!(shares.len(), 5);
        assert!(!group_key.is_fips_approved());

        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.participant_id.0, (i + 1) as u16);
            assert_eq!(share.config.threshold, 3);
            assert_eq!(share.config.total_participants, 5);
            assert_eq!(share.curve, EcdsaCurve::Secp256k1);
        }
    }

    #[test]
    fn test_dkg_invalid_share_detected() {
        // This test verifies that Feldman VSS catches tampered shares
        let participants = vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)];
        let config =
            DkgConfig::new(ThresholdScheme::ThresholdEcdsaP256, 2, participants.clone()).unwrap();

        let mut dkg1 = EcdsaDkg::new(config.clone(), ParticipantId(1), EcdsaCurve::P256).unwrap();
        let mut dkg2 = EcdsaDkg::new(config.clone(), ParticipantId(2), EcdsaCurve::P256).unwrap();
        let mut dkg3 = EcdsaDkg::new(config.clone(), ParticipantId(3), EcdsaCurve::P256).unwrap();

        // Round 1: All participants generate and exchange commitments
        let r1_pkg1 = dkg1.round1_generate_commitments().unwrap();
        let r1_pkg2 = dkg2.round1_generate_commitments().unwrap();
        let r1_pkg3 = dkg3.round1_generate_commitments().unwrap();

        dkg1.round1_receive_commitments(vec![r1_pkg2.clone(), r1_pkg3.clone()])
            .unwrap();
        dkg2.round1_receive_commitments(vec![r1_pkg1.clone(), r1_pkg3.clone()])
            .unwrap();
        dkg3.round1_receive_commitments(vec![r1_pkg1.clone(), r1_pkg2.clone()])
            .unwrap();

        // Round 2: Generate shares
        let _r2_pkgs1 = dkg1.round2_generate_shares().unwrap();
        let mut r2_pkgs2 = dkg2.round2_generate_shares().unwrap();
        let r2_pkgs3 = dkg3.round2_generate_shares().unwrap();

        // Tamper with the share from participant 2 to participant 1
        let tampered_pkg = r2_pkgs2
            .iter_mut()
            .find(|p| p.receiver == ParticipantId(1))
            .unwrap();
        tampered_pkg.share[0] ^= 0xFF;

        // Collect shares for participant 1 (from participant 2 (tampered) and 3)
        let shares_for_1: Vec<_> = r2_pkgs2
            .into_iter()
            .filter(|p| p.receiver == ParticipantId(1))
            .chain(
                r2_pkgs3
                    .into_iter()
                    .filter(|p| p.receiver == ParticipantId(1)),
            )
            .collect();

        // Receiving tampered share should fail verification
        let result = dkg1.round2_receive_shares(shares_for_1);
        assert!(matches!(result, Err(ThresholdError::DkgInvalidShare(_))));
    }

    #[test]
    fn test_dkg_all_same_group_key() {
        // Run DKG twice and verify different runs produce different keys
        // but within a run, all participants get the same key
        let (shares1, gk1) = run_full_dkg(2, 3, EcdsaCurve::P256).unwrap();
        let (shares2, gk2) = run_full_dkg(2, 3, EcdsaCurve::P256).unwrap();

        // All participants in run 1 have same group key
        for share in &shares1 {
            assert_eq!(share.group_public_key, gk1.bytes);
        }

        // All participants in run 2 have same group key
        for share in &shares2 {
            assert_eq!(share.group_public_key, gk2.bytes);
        }

        // Different runs produce different keys (with overwhelming probability)
        assert_ne!(gk1.bytes, gk2.bytes);
    }

    /// Ignored: exercises the threshold-ECDSA signing flow, which now fails closed
    /// (no `k^-1`; see `ThresholdEcdsaEngine::presign`). DKG correctness itself is
    /// still covered by `test_dkg_all_same_group_key` and `test_dkg_invalid_share_detected`.
    #[test]
    #[ignore = "requires correct threshold ECDSA (GG20/MtA)"]
    fn test_dkg_shares_sign_valid() {
        // Test that DKG-generated shares can be used to create valid threshold signatures
        let (shares, group_key) = run_full_dkg(2, 3, EcdsaCurve::P256).unwrap();

        let message = b"Test message for DKG-generated keys";
        let message_hash = ThresholdEcdsaEngine::hash_message(message);

        // Sign with participants 0 and 2
        let selected_indices = [0, 2];

        // Round 1: Generate nonces
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for &idx in &selected_indices {
            let (nonce, commitment) = ThresholdEcdsaEngine::generate_nonces(&shares[idx]).unwrap();
            nonces.push(nonce);
            commitments.push(commitment);
        }

        let participants: Vec<ParticipantId> = selected_indices
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

        // Verify signature has valid format
        assert_eq!(signature.r.len(), 32);
        assert_eq!(signature.s.len(), 32);
        assert_eq!(signature.curve, EcdsaCurve::P256);
    }

    /// Ignored: threshold-ECDSA signing flow fails closed (no `k^-1`).
    #[test]
    #[ignore = "requires correct threshold ECDSA (GG20/MtA)"]
    fn test_dkg_shares_sign_valid_secp256k1() {
        // Test DKG-generated secp256k1 shares can sign
        let (shares, group_key) = run_full_dkg(2, 3, EcdsaCurve::Secp256k1).unwrap();

        let message = b"Bitcoin transaction test";
        let message_hash = ThresholdEcdsaEngine::hash_message(message);

        // Sign with participants 1 and 2 (indices 0 and 1)
        let selected_indices = [0, 1];

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for &idx in &selected_indices {
            let (nonce, commitment) = ThresholdEcdsaEngine::generate_nonces(&shares[idx]).unwrap();
            nonces.push(nonce);
            commitments.push(commitment);
        }

        let participants: Vec<ParticipantId> = selected_indices
            .iter()
            .map(|&i| shares[i].participant_id)
            .collect();

        let presigs: Vec<_> = selected_indices
            .iter()
            .enumerate()
            .map(|(i, &idx)| {
                ThresholdEcdsaEngine::presign(&shares[idx], &nonces[i], &commitments, &participants)
                    .unwrap()
            })
            .collect();

        let sig_shares: Vec<_> = selected_indices
            .iter()
            .enumerate()
            .map(|(i, &idx)| {
                ThresholdEcdsaEngine::sign_share(&shares[idx], &presigs[i], &message_hash).unwrap()
            })
            .collect();

        let signature =
            ThresholdEcdsaEngine::aggregate(&group_key, &presigs[0], &sig_shares, &participants)
                .unwrap();

        assert_eq!(signature.curve, EcdsaCurve::Secp256k1);
        assert_eq!(signature.to_bytes().len(), 64);
    }

    /// Ignored: threshold-ECDSA signing flow fails closed (no `k^-1`).
    #[test]
    #[ignore = "requires correct threshold ECDSA (GG20/MtA)"]
    fn test_dkg_different_participant_subsets() {
        // Test that different subsets of participants can sign
        let (shares, group_key) = run_full_dkg(2, 4, EcdsaCurve::P256).unwrap();

        let message_hash = ThresholdEcdsaEngine::hash_message(b"subset test");

        // Try signing with participants [0, 1], [1, 2], [2, 3], [0, 3]
        let subsets = vec![[0, 1], [1, 2], [2, 3], [0, 3]];

        for subset in subsets {
            let mut nonces = Vec::new();
            let mut commitments = Vec::new();
            for &idx in &subset {
                let (nonce, commitment) =
                    ThresholdEcdsaEngine::generate_nonces(&shares[idx]).unwrap();
                nonces.push(nonce);
                commitments.push(commitment);
            }

            let participants: Vec<ParticipantId> =
                subset.iter().map(|&i| shares[i].participant_id).collect();

            let presigs: Vec<_> = subset
                .iter()
                .enumerate()
                .map(|(i, &idx)| {
                    ThresholdEcdsaEngine::presign(
                        &shares[idx],
                        &nonces[i],
                        &commitments,
                        &participants,
                    )
                    .unwrap()
                })
                .collect();

            let sig_shares: Vec<_> = subset
                .iter()
                .enumerate()
                .map(|(i, &idx)| {
                    ThresholdEcdsaEngine::sign_share(&shares[idx], &presigs[i], &message_hash)
                        .unwrap()
                })
                .collect();

            let signature = ThresholdEcdsaEngine::aggregate(
                &group_key,
                &presigs[0],
                &sig_shares,
                &participants,
            )
            .unwrap();

            assert_eq!(signature.to_bytes().len(), 64);
        }
    }

    #[test]
    fn test_dkg_state_transitions() {
        let participants = vec![ParticipantId(1), ParticipantId(2)];
        let config = DkgConfig::new(ThresholdScheme::ThresholdEcdsaP256, 2, participants).unwrap();

        let mut dkg = EcdsaDkg::new(config, ParticipantId(1), EcdsaCurve::P256).unwrap();

        // Initial state
        assert_eq!(*dkg.state(), EcdsaDkgState::NotStarted);

        // Can't receive commitments before generating own
        assert!(dkg.round1_receive_commitments(vec![]).is_err());

        // Can't generate shares before round 1 complete
        assert!(dkg.round2_generate_shares().is_err());

        // Generate commitments
        let _ = dkg.round1_generate_commitments().unwrap();
        // State doesn't change until all commitments received
        assert_eq!(*dkg.state(), EcdsaDkgState::NotStarted);
    }

    #[test]
    fn test_dkg_invalid_participant() {
        let participants = vec![ParticipantId(1), ParticipantId(2)];
        let config = DkgConfig::new(ThresholdScheme::ThresholdEcdsaP256, 2, participants).unwrap();

        // Try to create DKG for participant not in list
        let result = EcdsaDkg::new(config, ParticipantId(3), EcdsaCurve::P256);
        assert!(matches!(result, Err(ThresholdError::InvalidParticipant(_))));
    }

    /// Ignored: after the DKG-shape assertions it exercises the threshold-ECDSA
    /// signing flow, which now fails closed (no `k^-1`). DKG group-key agreement is
    /// covered by `test_dkg_all_same_group_key`.
    #[test]
    #[ignore = "requires correct threshold ECDSA (GG20/MtA)"]
    fn test_dkg_5_of_7() {
        // Test larger threshold configuration
        let (shares, group_key) = run_full_dkg(5, 7, EcdsaCurve::P256).unwrap();

        assert_eq!(shares.len(), 7);
        assert_eq!(group_key.config.threshold, 5);
        assert_eq!(group_key.config.total_participants, 7);

        // Verify signing with exactly 5 participants
        let message_hash = ThresholdEcdsaEngine::hash_message(b"5-of-7 test");
        let selected: Vec<usize> = vec![0, 2, 3, 5, 6];

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for &idx in &selected {
            let (nonce, commitment) = ThresholdEcdsaEngine::generate_nonces(&shares[idx]).unwrap();
            nonces.push(nonce);
            commitments.push(commitment);
        }

        let participants: Vec<ParticipantId> =
            selected.iter().map(|&i| shares[i].participant_id).collect();

        let presigs: Vec<_> = selected
            .iter()
            .enumerate()
            .map(|(i, &idx)| {
                ThresholdEcdsaEngine::presign(&shares[idx], &nonces[i], &commitments, &participants)
                    .unwrap()
            })
            .collect();

        let sig_shares: Vec<_> = selected
            .iter()
            .enumerate()
            .map(|(i, &idx)| {
                ThresholdEcdsaEngine::sign_share(&shares[idx], &presigs[i], &message_hash).unwrap()
            })
            .collect();

        let signature =
            ThresholdEcdsaEngine::aggregate(&group_key, &presigs[0], &sig_shares, &participants)
                .unwrap();

        assert_eq!(signature.to_bytes().len(), 64);
    }
}
