//! Distributed Key Generation (DKG)
//!
//! Allows participants to jointly generate a shared key without any
//! trusted dealer. Each participant generates their own contribution
//! and shares commitments with others through a three-round protocol.
//!
//! # Protocol Overview
//!
//! 1. **Round 1**: Each participant generates a secret polynomial and broadcasts
//!    a commitment (Round1Package) to all other participants.
//!
//! 2. **Round 2**: Each participant processes received Round1Packages and generates
//!    encrypted shares (Round2Packages) for each other participant.
//!
//! 3. **Round 3**: Each participant processes received Round2Packages to derive
//!    their final key share and the group public key.
//!
//! # Security
//!
//! - No single participant learns the group secret key
//! - Requires secure point-to-point channels for Round 2 packages
//! - Round 1 packages can be broadcast publicly
//! - Cheating participants can be detected through verification

use frost_ed25519 as frost;
use rand_core::OsRng;
use std::collections::BTreeMap;

use super::types::*;

/// Round 1 output to broadcast to all participants.
#[derive(Debug, Clone)]
pub struct DkgRound1Package {
    /// The participant who created this package.
    pub participant_id: ParticipantId,
    /// Serialized Round1Package to share with all other participants.
    pub package_bytes: Vec<u8>,
}

impl DkgRound1Package {
    /// Create a new DKG Round 1 package.
    pub fn new(participant_id: ParticipantId, package_bytes: Vec<u8>) -> Self {
        Self {
            participant_id,
            package_bytes,
        }
    }
}

/// Round 2 output to send to a specific participant (encrypted).
#[derive(Debug, Clone)]
pub struct DkgRound2Package {
    /// The participant who created this package.
    pub from: ParticipantId,
    /// The intended recipient of this package.
    pub to: ParticipantId,
    /// Serialized Round2Package (contains encrypted share for recipient).
    pub package_bytes: Vec<u8>,
}

impl DkgRound2Package {
    /// Create a new DKG Round 2 package.
    pub fn new(from: ParticipantId, to: ParticipantId, package_bytes: Vec<u8>) -> Self {
        Self {
            from,
            to,
            package_bytes,
        }
    }
}

/// State machine for DKG protocol.
///
/// Each participant maintains their own DKG instance and progresses through
/// the protocol rounds by processing packages from other participants.
pub struct DistributedKeyGeneration {
    config: ThresholdConfig,
    participant_id: ParticipantId,
    round: DkgRound,
}

/// Internal state tracking for DKG rounds.
enum DkgRound {
    /// Protocol not yet started.
    NotStarted,
    /// Round 1 complete, holding secret package for Round 2.
    Round1 {
        /// Serialized round1::SecretPackage.
        secret_package: Vec<u8>,
    },
    /// Round 2 complete, holding secret package for Round 3.
    Round2 {
        /// Serialized round2::SecretPackage.
        secret_package: Vec<u8>,
        /// Collected Round1 packages from all participants.
        round1_packages: BTreeMap<ParticipantId, Vec<u8>>,
    },
    /// DKG complete with final key share and group key.
    Complete {
        /// The participant's final key share.
        key_share: KeyShare,
        /// The group's public key.
        group_key: GroupPublicKey,
    },
}

impl DistributedKeyGeneration {
    /// Create a new DKG instance for a participant.
    ///
    /// # Arguments
    ///
    /// * `config` - The threshold configuration (t-of-n)
    /// * `participant_id` - This participant's identifier (must be in 1..=n)
    ///
    /// # Errors
    ///
    /// Returns error if participant_id is invalid for the configuration.
    pub fn new(
        config: ThresholdConfig,
        participant_id: ParticipantId,
    ) -> Result<Self, ThresholdError> {
        if participant_id.0 == 0 || participant_id.0 > config.total_participants {
            return Err(ThresholdError::InvalidParticipant(format!(
                "participant_id {} must be in range 1..={}",
                participant_id.0, config.total_participants
            )));
        }

        Ok(Self {
            config,
            participant_id,
            round: DkgRound::NotStarted,
        })
    }

    /// Get the participant ID.
    pub fn participant_id(&self) -> ParticipantId {
        self.participant_id
    }

    /// Get the threshold configuration.
    pub fn config(&self) -> ThresholdConfig {
        self.config
    }

    /// Check if DKG is complete.
    pub fn is_complete(&self) -> bool {
        matches!(self.round, DkgRound::Complete { .. })
    }

    /// Execute Round 1: Generate secret polynomial and broadcast commitment.
    ///
    /// This must be called before processing any other participants' packages.
    /// The returned package should be broadcast to all other participants.
    ///
    /// # Returns
    ///
    /// A DkgRound1Package to broadcast to all other participants.
    ///
    /// # Errors
    ///
    /// Returns error if Round 1 has already been executed.
    pub fn round1(&mut self) -> Result<DkgRound1Package, ThresholdError> {
        if !matches!(self.round, DkgRound::NotStarted) {
            return Err(ThresholdError::DkgFailed {
                round: 1,
                reason: "Round 1 already executed".into(),
            });
        }

        let identifier = frost::Identifier::try_from(self.participant_id.0).map_err(|e| {
            ThresholdError::DkgFailed {
                round: 1,
                reason: e.to_string(),
            }
        })?;

        let (secret_package, round1_package) = frost::keys::dkg::part1(
            identifier,
            self.config.total_participants,
            self.config.threshold,
            OsRng,
        )
        .map_err(|e| ThresholdError::DkgFailed {
            round: 1,
            reason: e.to_string(),
        })?;

        // Serialize the secret package (kept locally)
        let secret_bytes = secret_package
            .serialize()
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Serialize the public package (broadcast to others)
        let package_bytes = round1_package
            .serialize()
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        self.round = DkgRound::Round1 {
            secret_package: secret_bytes,
        };

        Ok(DkgRound1Package::new(self.participant_id, package_bytes))
    }

    /// Execute Round 2: Process Round 1 packages and generate shares for each participant.
    ///
    /// After receiving Round1Packages from all other participants, this generates
    /// individualized Round2Packages for each participant.
    ///
    /// # Arguments
    ///
    /// * `round1_packages` - Round 1 packages from all other participants
    ///
    /// # Returns
    ///
    /// A vector of DkgRound2Packages, one for each other participant.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Round 1 has not been completed
    /// - Not enough Round 1 packages received
    /// - Package verification fails
    pub fn round2(
        &mut self,
        round1_packages: Vec<DkgRound1Package>,
    ) -> Result<Vec<DkgRound2Package>, ThresholdError> {
        let secret_bytes = match &self.round {
            DkgRound::Round1 { secret_package } => secret_package.clone(),
            _ => {
                return Err(ThresholdError::DkgFailed {
                    round: 2,
                    reason: "Must complete Round 1 first".into(),
                })
            }
        };

        // Check we have packages from all other participants
        let expected_packages = (self.config.total_participants - 1) as usize;
        if round1_packages.len() < expected_packages {
            return Err(ThresholdError::InsufficientParticipants {
                required: self.config.total_participants - 1,
                provided: round1_packages.len() as u16,
            });
        }

        // Deserialize the secret package
        let round1_secret_package =
            frost::keys::dkg::round1::SecretPackage::deserialize(&secret_bytes)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Deserialize and collect round 1 packages (excluding our own)
        let mut round1_package_map = BTreeMap::new();
        let mut round1_packages_stored = BTreeMap::new();

        for pkg in round1_packages {
            if pkg.participant_id == self.participant_id {
                continue; // Skip our own package
            }

            let identifier = frost::Identifier::try_from(pkg.participant_id.0)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

            let package = frost::keys::dkg::round1::Package::deserialize(&pkg.package_bytes)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

            round1_package_map.insert(identifier, package);
            round1_packages_stored.insert(pkg.participant_id, pkg.package_bytes);
        }

        // Execute part2 of DKG
        let (round2_secret_package, round2_packages) =
            frost::keys::dkg::part2(round1_secret_package, &round1_package_map).map_err(|e| {
                ThresholdError::DkgFailed {
                    round: 2,
                    reason: e.to_string(),
                }
            })?;

        // Serialize the round 2 secret package
        let round2_secret_bytes = round2_secret_package
            .serialize()
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Convert round 2 packages to our format
        // FROST returns packages keyed by the recipient's identifier
        // We need to map these back to our ParticipantId
        let mut output_packages = Vec::new();
        for recipient_num in 1..=self.config.total_participants {
            if recipient_num == self.participant_id.0 {
                continue; // Skip ourselves
            }

            let recipient_identifier = frost::Identifier::try_from(recipient_num)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

            if let Some(package) = round2_packages.get(&recipient_identifier) {
                let package_bytes = package
                    .serialize()
                    .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

                output_packages.push(DkgRound2Package::new(
                    self.participant_id,
                    ParticipantId(recipient_num),
                    package_bytes,
                ));
            }
        }

        self.round = DkgRound::Round2 {
            secret_package: round2_secret_bytes,
            round1_packages: round1_packages_stored,
        };

        Ok(output_packages)
    }

    /// Execute Round 3 (Finalize): Process Round 2 packages and derive final keys.
    ///
    /// After receiving Round2Packages from all other participants, this derives
    /// the final key share and group public key.
    ///
    /// # Arguments
    ///
    /// * `round2_packages` - Round 2 packages from all other participants (addressed to us)
    ///
    /// # Returns
    ///
    /// Tuple of (KeyShare, GroupPublicKey) representing the participant's final keys.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Round 2 has not been completed
    /// - Not enough Round 2 packages received
    /// - Package verification fails
    pub fn finalize(
        &mut self,
        round2_packages: Vec<DkgRound2Package>,
    ) -> Result<(KeyShare, GroupPublicKey), ThresholdError> {
        let (round2_secret_bytes, round1_packages_stored) = match &self.round {
            DkgRound::Round2 {
                secret_package,
                round1_packages,
            } => (secret_package.clone(), round1_packages.clone()),
            _ => {
                return Err(ThresholdError::DkgFailed {
                    round: 3,
                    reason: "Must complete Round 2 first".into(),
                })
            }
        };

        // Deserialize the round 2 secret package
        let round2_secret_package =
            frost::keys::dkg::round2::SecretPackage::deserialize(&round2_secret_bytes)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Reconstruct round 1 package map for part3
        let mut round1_package_map = BTreeMap::new();
        for (pid, pkg_bytes) in round1_packages_stored {
            let identifier = frost::Identifier::try_from(pid.0)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

            let package = frost::keys::dkg::round1::Package::deserialize(&pkg_bytes)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

            round1_package_map.insert(identifier, package);
        }

        // Collect and deserialize round 2 packages addressed to us
        let mut round2_package_map = BTreeMap::new();

        for pkg in round2_packages {
            // Only process packages addressed to us
            if pkg.to != self.participant_id {
                continue;
            }

            let identifier = frost::Identifier::try_from(pkg.from.0)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

            let package = frost::keys::dkg::round2::Package::deserialize(&pkg.package_bytes)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

            round2_package_map.insert(identifier, package);
        }

        // Check we have packages from all other participants (after filtering)
        let expected_packages = (self.config.total_participants - 1) as usize;
        if round2_package_map.len() < expected_packages {
            return Err(ThresholdError::InsufficientParticipants {
                required: self.config.total_participants - 1,
                provided: round2_package_map.len() as u16,
            });
        }

        // Execute part3 of DKG
        let (key_package, pubkey_package) = frost::keys::dkg::part3(
            &round2_secret_package,
            &round1_package_map,
            &round2_package_map,
        )
        .map_err(|e| ThresholdError::DkgFailed {
            round: 3,
            reason: e.to_string(),
        })?;

        // Serialize the public key package
        let pubkey_package_bytes = pubkey_package
            .serialize()
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Get verifying key and verifying share bytes
        let verifying_key_bytes = pubkey_package
            .verifying_key()
            .serialize()
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        let verifying_share_bytes = key_package
            .verifying_share()
            .serialize()
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Create our types
        let key_share = KeyShare::new(
            self.participant_id,
            self.config,
            key_package.signing_share().serialize().to_vec(),
            verifying_share_bytes.clone(),
        );

        let group_key = GroupPublicKey::new(
            verifying_key_bytes.clone(),
            self.config,
            pubkey_package_bytes,
        );

        self.round = DkgRound::Complete {
            key_share: KeyShare::new(
                self.participant_id,
                self.config,
                key_package.signing_share().serialize().to_vec(),
                verifying_share_bytes,
            ),
            group_key: group_key.clone(),
        };

        Ok((key_share, group_key))
    }

    /// Get the final key share if DKG is complete.
    ///
    /// # Returns
    ///
    /// The participant's key share if DKG is complete, None otherwise.
    pub fn get_key_share(&self) -> Option<&KeyShare> {
        match &self.round {
            DkgRound::Complete { key_share, .. } => Some(key_share),
            _ => None,
        }
    }

    /// Get the group public key if DKG is complete.
    ///
    /// # Returns
    ///
    /// The group's public key if DKG is complete, None otherwise.
    pub fn get_group_key(&self) -> Option<&GroupPublicKey> {
        match &self.round {
            DkgRound::Complete { group_key, .. } => Some(group_key),
            _ => None,
        }
    }
}

/// Verify that Round 1 packages from all participants are consistent.
///
/// This can be used to detect cheating participants before proceeding to Round 2.
///
/// # Arguments
///
/// * `packages` - All Round 1 packages from participants
/// * `config` - The threshold configuration
///
/// # Returns
///
/// Ok(()) if all packages are valid and consistent.
///
/// # Errors
///
/// Returns error if:
/// - Not enough packages provided
/// - Any package fails verification
/// - Duplicate participant IDs found
pub fn verify_round1_packages(
    packages: &[DkgRound1Package],
    config: ThresholdConfig,
) -> Result<(), ThresholdError> {
    if packages.len() != config.total_participants as usize {
        return Err(ThresholdError::InsufficientParticipants {
            required: config.total_participants,
            provided: packages.len() as u16,
        });
    }

    // Check for duplicate participant IDs
    let mut seen_ids = std::collections::HashSet::new();
    for pkg in packages {
        if !seen_ids.insert(pkg.participant_id) {
            return Err(ThresholdError::InvalidParticipant(format!(
                "Duplicate participant ID: {}",
                pkg.participant_id
            )));
        }
    }

    // Verify each package can be deserialized
    for pkg in packages {
        frost::keys::dkg::round1::Package::deserialize(&pkg.package_bytes).map_err(|e| {
            ThresholdError::DkgFailed {
                round: 1,
                reason: format!("Invalid package from {}: {}", pkg.participant_id, e),
            }
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to run a complete DKG among n participants.
    fn run_dkg(config: ThresholdConfig) -> Vec<(KeyShare, GroupPublicKey)> {
        let n = config.total_participants as usize;

        // Create DKG instances for each participant
        let mut dkgs: Vec<_> = (1..=n as u16)
            .map(|i| DistributedKeyGeneration::new(config, ParticipantId(i)).unwrap())
            .collect();

        // Round 1: Each participant generates and broadcasts their package
        let round1_packages: Vec<DkgRound1Package> =
            dkgs.iter_mut().map(|dkg| dkg.round1().unwrap()).collect();

        // Round 2: Each participant processes Round 1 packages
        let mut all_round2_packages = Vec::new();
        for dkg in &mut dkgs {
            let packages = dkg.round2(round1_packages.clone()).unwrap();
            all_round2_packages.extend(packages);
        }

        // Round 3: Each participant processes Round 2 packages addressed to them
        let mut results = Vec::new();
        for dkg in &mut dkgs {
            let my_packages: Vec<DkgRound2Package> = all_round2_packages
                .iter()
                .filter(|pkg| pkg.to == dkg.participant_id())
                .cloned()
                .collect();

            let (key_share, group_key) = dkg.finalize(my_packages).unwrap();
            results.push((key_share, group_key));
        }

        results
    }

    #[test]
    fn test_dkg_2_of_3() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let results = run_dkg(config);

        assert_eq!(results.len(), 3);

        // All participants should have the same group public key
        let group_key_bytes = &results[0].1.bytes;
        for (_, group_key) in &results {
            assert_eq!(&group_key.bytes, group_key_bytes);
        }

        // Each participant should have a unique key share
        let mut seen_shares = std::collections::HashSet::new();
        for (key_share, _) in &results {
            assert!(seen_shares.insert(key_share.participant_id));
        }
    }

    #[test]
    fn test_dkg_3_of_5() {
        let config = ThresholdConfig::new(3, 5).unwrap();
        let results = run_dkg(config);

        assert_eq!(results.len(), 5);

        // All participants should have the same group public key
        let group_key_bytes = &results[0].1.bytes;
        for (_, group_key) in &results {
            assert_eq!(&group_key.bytes, group_key_bytes);
        }
    }

    #[test]
    fn test_dkg_keys_work_for_signing() {
        use super::super::frost::FrostEngine;

        let config = ThresholdConfig::new(2, 3).unwrap();
        let results = run_dkg(config);

        let key_shares: Vec<_> = results.iter().map(|(ks, _)| ks).collect();
        let group_key = &results[0].1;

        let message = b"Test message signed with DKG keys";

        // Generate nonces and commitments for first 2 participants
        let (nonce1, commitment1) = FrostEngine::generate_nonces(key_shares[0]).unwrap();
        let (nonce2, commitment2) = FrostEngine::generate_nonces(key_shares[1]).unwrap();
        let commitments = vec![commitment1, commitment2];

        // Generate signature shares
        let sig_share1 =
            FrostEngine::sign_share(key_shares[0], &nonce1, message, &commitments, group_key)
                .unwrap();
        let sig_share2 =
            FrostEngine::sign_share(key_shares[1], &nonce2, message, &commitments, group_key)
                .unwrap();

        // Aggregate and verify
        let signature = FrostEngine::aggregate_signatures(
            message,
            &commitments,
            &[sig_share1, sig_share2],
            group_key,
        )
        .unwrap();

        let valid = FrostEngine::verify(group_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_dkg_invalid_participant_id() {
        let config = ThresholdConfig::new(2, 3).unwrap();

        // Participant ID 0 should fail
        let result = DistributedKeyGeneration::new(config, ParticipantId(0));
        assert!(result.is_err());

        // Participant ID > n should fail
        let result = DistributedKeyGeneration::new(config, ParticipantId(4));
        assert!(result.is_err());
    }

    #[test]
    fn test_dkg_round_order_enforcement() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let mut dkg = DistributedKeyGeneration::new(config, ParticipantId(1)).unwrap();

        // Cannot execute Round 2 before Round 1
        let result = dkg.round2(vec![]);
        assert!(matches!(
            result,
            Err(ThresholdError::DkgFailed { round: 2, .. })
        ));

        // Execute Round 1
        let _pkg = dkg.round1().unwrap();

        // Cannot execute Round 1 again
        let result = dkg.round1();
        assert!(matches!(
            result,
            Err(ThresholdError::DkgFailed { round: 1, .. })
        ));
    }

    #[test]
    fn test_verify_round1_packages() {
        let config = ThresholdConfig::new(2, 3).unwrap();

        // Create valid packages
        let mut dkgs: Vec<_> = (1..=3)
            .map(|i| DistributedKeyGeneration::new(config, ParticipantId(i)).unwrap())
            .collect();

        let packages: Vec<_> = dkgs.iter_mut().map(|dkg| dkg.round1().unwrap()).collect();

        // Should pass verification
        verify_round1_packages(&packages, config).unwrap();
    }

    #[test]
    fn test_verify_round1_packages_insufficient() {
        let config = ThresholdConfig::new(2, 3).unwrap();

        let mut dkgs: Vec<_> = (1..=2)
            .map(|i| DistributedKeyGeneration::new(config, ParticipantId(i)).unwrap())
            .collect();

        let packages: Vec<_> = dkgs.iter_mut().map(|dkg| dkg.round1().unwrap()).collect();

        // Should fail - only 2 packages for 3-party scheme
        let result = verify_round1_packages(&packages, config);
        assert!(matches!(
            result,
            Err(ThresholdError::InsufficientParticipants { .. })
        ));
    }
}
