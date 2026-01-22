//! Signing Coordinator
//!
//! Coordinates the multi-round signing protocol among participants.
//! The coordinator collects commitments and signature shares, but does NOT
//! learn the secret key or have any special cryptographic privileges.
//!
//! # Security
//!
//! - The coordinator does not learn any secret information
//! - All participants verify commitments independently
//! - A malicious coordinator cannot forge signatures
//! - The coordinator can only cause denial-of-service by refusing to aggregate

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::frost::FrostEngine;
use super::types::*;

/// Unique identifier for a signing session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

impl SessionId {
    /// Create a new random session ID.
    pub fn new() -> Self {
        use rand_core::{OsRng, RngCore};
        Self(OsRng.next_u64())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// State of the signing session.
#[derive(Debug, Clone)]
pub enum SigningState {
    /// Collecting commitments from participants (Round 1).
    CollectingCommitments {
        /// The message being signed.
        message: Vec<u8>,
        /// Commitments received so far.
        commitments: HashMap<ParticipantId, SigningCommitment>,
    },
    /// Collecting signature shares from participants (Round 2).
    CollectingShares {
        /// The message being signed.
        message: Vec<u8>,
        /// All commitments from Round 1.
        commitments: Vec<SigningCommitment>,
        /// Signature shares received so far.
        shares: HashMap<ParticipantId, SignatureShare>,
    },
    /// Signing complete with final signature.
    Complete {
        /// The final aggregated signature.
        signature: ThresholdSignature,
    },
    /// Signing failed.
    Failed {
        /// The reason for failure.
        reason: String,
    },
}

/// Configuration for a signing session.
#[derive(Debug, Clone)]
pub struct SigningSessionConfig {
    /// Timeout for the entire session.
    pub session_timeout: Duration,
    /// Timeout waiting for commitments in Round 1.
    pub commitment_timeout: Duration,
    /// Timeout waiting for shares in Round 2.
    pub share_timeout: Duration,
}

impl Default for SigningSessionConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(300),   // 5 minutes
            commitment_timeout: Duration::from_secs(60), // 1 minute
            share_timeout: Duration::from_secs(60),      // 1 minute
        }
    }
}

/// Coordinates a threshold signing session.
///
/// The coordinator collects commitments and signature shares from participants,
/// then aggregates them into a final signature. The coordinator does not learn
/// any secret information.
pub struct SigningCoordinator {
    /// Unique session identifier.
    session_id: SessionId,
    /// Threshold configuration.
    config: ThresholdConfig,
    /// Group public key.
    group_public_key: GroupPublicKey,
    /// Current state.
    state: SigningState,
    /// Selected participants for this session.
    selected_participants: Vec<ParticipantId>,
    /// Session start time.
    started_at: Instant,
    /// Session configuration.
    session_config: SigningSessionConfig,
}

impl SigningCoordinator {
    /// Create a new signing coordinator and start a session.
    ///
    /// # Arguments
    ///
    /// * `config` - Threshold configuration
    /// * `group_public_key` - The group's public key
    /// * `message` - The message to sign
    /// * `participants` - The participants selected for this signing session
    ///
    /// # Errors
    ///
    /// Returns error if not enough participants are selected.
    pub fn new(
        config: ThresholdConfig,
        group_public_key: GroupPublicKey,
        message: Vec<u8>,
        participants: Vec<ParticipantId>,
    ) -> Result<Self, ThresholdError> {
        Self::with_config(
            config,
            group_public_key,
            message,
            participants,
            SigningSessionConfig::default(),
        )
    }

    /// Create a new signing coordinator with custom session configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Threshold configuration
    /// * `group_public_key` - The group's public key
    /// * `message` - The message to sign
    /// * `participants` - The participants selected for this signing session
    /// * `session_config` - Session timeout configuration
    ///
    /// # Errors
    ///
    /// Returns error if not enough participants are selected.
    pub fn with_config(
        config: ThresholdConfig,
        group_public_key: GroupPublicKey,
        message: Vec<u8>,
        participants: Vec<ParticipantId>,
        session_config: SigningSessionConfig,
    ) -> Result<Self, ThresholdError> {
        if participants.len() < config.threshold as usize {
            return Err(ThresholdError::InsufficientParticipants {
                required: config.threshold,
                provided: participants.len() as u16,
            });
        }

        Ok(Self {
            session_id: SessionId::new(),
            config,
            group_public_key,
            state: SigningState::CollectingCommitments {
                message,
                commitments: HashMap::new(),
            },
            selected_participants: participants,
            started_at: Instant::now(),
            session_config,
        })
    }

    /// Get the session ID.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Get the message being signed.
    pub fn message(&self) -> Option<&[u8]> {
        match &self.state {
            SigningState::CollectingCommitments { message, .. } => Some(message),
            SigningState::CollectingShares { message, .. } => Some(message),
            _ => None,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> &SigningState {
        &self.state
    }

    /// Check if the session has timed out.
    pub fn is_timed_out(&self) -> bool {
        self.started_at.elapsed() > self.session_config.session_timeout
    }

    /// Submit a commitment from a participant (Round 1).
    ///
    /// # Arguments
    ///
    /// * `commitment` - The participant's signing commitment
    ///
    /// # Returns
    ///
    /// - `Ok(None)` if waiting for more commitments
    /// - `Ok(Some(commitments))` if all commitments received
    /// - `Err` if the commitment is invalid or from an unexpected participant
    pub fn submit_commitment(
        &mut self,
        commitment: SigningCommitment,
    ) -> Result<Option<Vec<SigningCommitment>>, ThresholdError> {
        // Check session timeout
        if self.is_timed_out() {
            self.state = SigningState::Failed {
                reason: "Session timed out".into(),
            };
            return Err(ThresholdError::SessionError("Session timed out".into()));
        }

        let SigningState::CollectingCommitments {
            message,
            commitments,
        } = &mut self.state
        else {
            return Err(ThresholdError::SigningFailed(
                "Not in commitment collection phase".into(),
            ));
        };

        // Verify participant is selected for this session
        if !self
            .selected_participants
            .contains(&commitment.participant_id)
        {
            return Err(ThresholdError::InvalidParticipant(format!(
                "{} is not selected for this signing session",
                commitment.participant_id
            )));
        }

        // Check for duplicate commitment
        if commitments.contains_key(&commitment.participant_id) {
            return Err(ThresholdError::SigningFailed(format!(
                "Duplicate commitment from {}",
                commitment.participant_id
            )));
        }

        commitments.insert(commitment.participant_id, commitment);

        // Check if we have enough commitments
        if commitments.len() >= self.config.threshold as usize {
            let all_commitments: Vec<_> = commitments.values().cloned().collect();
            let message = message.clone();

            self.state = SigningState::CollectingShares {
                message,
                commitments: all_commitments.clone(),
                shares: HashMap::new(),
            };

            Ok(Some(all_commitments))
        } else {
            Ok(None)
        }
    }

    /// Submit a signature share from a participant (Round 2).
    ///
    /// # Arguments
    ///
    /// * `share` - The participant's signature share
    ///
    /// # Returns
    ///
    /// - `Ok(None)` if waiting for more shares
    /// - `Ok(Some(signature))` if signing is complete
    /// - `Err` if the share is invalid or from an unexpected participant
    pub fn submit_share(
        &mut self,
        share: SignatureShare,
    ) -> Result<Option<ThresholdSignature>, ThresholdError> {
        // Check session timeout
        if self.is_timed_out() {
            self.state = SigningState::Failed {
                reason: "Session timed out".into(),
            };
            return Err(ThresholdError::SessionError("Session timed out".into()));
        }

        let SigningState::CollectingShares {
            message,
            commitments,
            shares,
        } = &mut self.state
        else {
            return Err(ThresholdError::SigningFailed(
                "Not in share collection phase".into(),
            ));
        };

        // Verify participant is selected and submitted a commitment
        if !self.selected_participants.contains(&share.participant_id) {
            return Err(ThresholdError::InvalidParticipant(format!(
                "{} is not selected for this signing session",
                share.participant_id
            )));
        }

        if !commitments
            .iter()
            .any(|c| c.participant_id == share.participant_id)
        {
            return Err(ThresholdError::InvalidParticipant(format!(
                "{} did not submit a commitment",
                share.participant_id
            )));
        }

        // Check for duplicate share
        if shares.contains_key(&share.participant_id) {
            return Err(ThresholdError::SigningFailed(format!(
                "Duplicate share from {}",
                share.participant_id
            )));
        }

        shares.insert(share.participant_id, share);

        // Check if we have enough shares
        if shares.len() >= self.config.threshold as usize {
            let all_shares: Vec<_> = shares.values().cloned().collect();

            // Aggregate signatures
            match FrostEngine::aggregate_signatures(
                message,
                commitments,
                &all_shares,
                &self.group_public_key,
            ) {
                Ok(signature) => {
                    self.state = SigningState::Complete {
                        signature: signature.clone(),
                    };
                    Ok(Some(signature))
                }
                Err(e) => {
                    self.state = SigningState::Failed {
                        reason: e.to_string(),
                    };
                    Err(e)
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Get how many more participants are needed.
    pub fn participants_needed(&self) -> usize {
        match &self.state {
            SigningState::CollectingCommitments { commitments, .. } => {
                (self.config.threshold as usize).saturating_sub(commitments.len())
            }
            SigningState::CollectingShares { shares, .. } => {
                (self.config.threshold as usize).saturating_sub(shares.len())
            }
            _ => 0,
        }
    }

    /// Get the list of participants who have submitted commitments.
    pub fn committed_participants(&self) -> Vec<ParticipantId> {
        match &self.state {
            SigningState::CollectingCommitments { commitments, .. } => {
                commitments.keys().copied().collect()
            }
            SigningState::CollectingShares { commitments, .. } => {
                commitments.iter().map(|c| c.participant_id).collect()
            }
            _ => vec![],
        }
    }

    /// Get the list of participants who have submitted signature shares.
    pub fn signed_participants(&self) -> Vec<ParticipantId> {
        match &self.state {
            SigningState::CollectingShares { shares, .. } => shares.keys().copied().collect(),
            _ => vec![],
        }
    }

    /// Get the final signature if signing is complete.
    pub fn get_signature(&self) -> Option<&ThresholdSignature> {
        match &self.state {
            SigningState::Complete { signature } => Some(signature),
            _ => None,
        }
    }

    /// Abort the signing session.
    pub fn abort(&mut self, reason: &str) {
        self.state = SigningState::Failed {
            reason: reason.to_string(),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_env() -> (ThresholdConfig, GroupPublicKey, Vec<KeyShare>) {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();
        (config, group_key, shares)
    }

    #[test]
    fn test_coordinator_creation() {
        let (config, group_key, shares) = setup_test_env();
        let participants: Vec<_> = shares.iter().map(|s| s.participant_id).collect();

        let coordinator =
            SigningCoordinator::new(config, group_key, b"test".to_vec(), participants).unwrap();

        assert!(matches!(
            coordinator.state(),
            SigningState::CollectingCommitments { .. }
        ));
        assert_eq!(coordinator.participants_needed(), 2);
    }

    #[test]
    fn test_coordinator_insufficient_participants() {
        let (config, group_key, shares) = setup_test_env();

        // Only provide 1 participant (need 2)
        let result = SigningCoordinator::new(
            config,
            group_key,
            b"test".to_vec(),
            vec![shares[0].participant_id],
        );

        assert!(matches!(
            result,
            Err(ThresholdError::InsufficientParticipants { .. })
        ));
    }

    #[test]
    fn test_coordinator_full_flow() {
        let (config, group_key, shares) = setup_test_env();
        let participants: Vec<_> = shares.iter().take(2).map(|s| s.participant_id).collect();
        let message = b"Test message for coordinator";

        let mut coordinator =
            SigningCoordinator::new(config, group_key.clone(), message.to_vec(), participants)
                .unwrap();

        // Round 1: Submit commitments
        let (nonce1, commitment1) = FrostEngine::generate_nonces(&shares[0]).unwrap();
        let result = coordinator.submit_commitment(commitment1.clone()).unwrap();
        assert!(result.is_none()); // Need more commitments
        assert_eq!(coordinator.participants_needed(), 1);

        let (nonce2, commitment2) = FrostEngine::generate_nonces(&shares[1]).unwrap();
        let result = coordinator.submit_commitment(commitment2.clone()).unwrap();
        assert!(result.is_some()); // All commitments received
        assert_eq!(coordinator.participants_needed(), 2); // Now need shares

        let all_commitments = result.unwrap();

        // Round 2: Submit signature shares
        let sig_share1 =
            FrostEngine::sign_share(&shares[0], &nonce1, message, &all_commitments, &group_key)
                .unwrap();

        let result = coordinator.submit_share(sig_share1).unwrap();
        assert!(result.is_none()); // Need more shares
        assert_eq!(coordinator.participants_needed(), 1);

        let sig_share2 =
            FrostEngine::sign_share(&shares[1], &nonce2, message, &all_commitments, &group_key)
                .unwrap();

        let result = coordinator.submit_share(sig_share2).unwrap();
        assert!(result.is_some()); // Complete!

        let signature = result.unwrap();

        // Verify the signature
        let valid = FrostEngine::verify(&group_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_coordinator_rejects_unknown_participant() {
        let (config, group_key, shares) = setup_test_env();
        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        let mut coordinator =
            SigningCoordinator::new(config, group_key, b"test".to_vec(), participants).unwrap();

        // Try to submit commitment from participant 3 (not selected)
        let (_, commitment3) = FrostEngine::generate_nonces(&shares[2]).unwrap();
        let result = coordinator.submit_commitment(commitment3);

        assert!(matches!(result, Err(ThresholdError::InvalidParticipant(_))));
    }

    #[test]
    fn test_coordinator_rejects_duplicate_commitment() {
        let (config, group_key, shares) = setup_test_env();
        let participants: Vec<_> = shares.iter().take(2).map(|s| s.participant_id).collect();

        let mut coordinator =
            SigningCoordinator::new(config, group_key, b"test".to_vec(), participants).unwrap();

        let (_, commitment1) = FrostEngine::generate_nonces(&shares[0]).unwrap();
        coordinator.submit_commitment(commitment1.clone()).unwrap();

        // Try to submit another commitment from the same participant
        let (_, commitment1_dup) = FrostEngine::generate_nonces(&shares[0]).unwrap();
        let result = coordinator.submit_commitment(commitment1_dup);

        assert!(matches!(result, Err(ThresholdError::SigningFailed(_))));
    }

    #[test]
    fn test_coordinator_abort() {
        let (config, group_key, shares) = setup_test_env();
        let participants: Vec<_> = shares.iter().map(|s| s.participant_id).collect();

        let mut coordinator =
            SigningCoordinator::new(config, group_key, b"test".to_vec(), participants).unwrap();

        coordinator.abort("User cancelled");

        assert!(matches!(
            coordinator.state(),
            SigningState::Failed { reason } if reason == "User cancelled"
        ));
    }

    #[test]
    fn test_session_id_uniqueness() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();

        // While technically could collide, extremely unlikely with u64
        assert_ne!(id1, id2);
    }
}
