//! Extended configuration types for threshold cryptography operations
//!
//! This module provides configuration structures for signing sessions,
//! DKG operations, key refresh, and resharing.

use super::types::{ParticipantId, SessionId, ThresholdConfig, ThresholdError, ThresholdScheme};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for a threshold signing session.
///
/// Defines the parameters for a multi-party signing operation including
/// timeouts, participants, and scheme selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningSessionConfig {
    /// The threshold scheme to use.
    pub scheme: ThresholdScheme,

    /// The threshold configuration (t-of-n).
    pub threshold_config: ThresholdConfig,

    /// Maximum time to wait for a signing session to complete.
    pub session_timeout: Duration,

    /// Maximum time to wait for a single round to complete.
    pub round_timeout: Duration,

    /// Whether to require FIPS-approved operations.
    pub fips_mode: bool,

    /// Optional session identifier (auto-generated if not provided).
    pub session_id: Option<SessionId>,

    /// Expected participants for this session.
    pub participants: Vec<ParticipantId>,
}

impl SigningSessionConfig {
    /// Create a new signing session configuration.
    pub fn new(
        scheme: ThresholdScheme,
        threshold_config: ThresholdConfig,
        participants: Vec<ParticipantId>,
    ) -> Result<Self, ThresholdError> {
        // Validate that we have enough participants
        if participants.len() < threshold_config.threshold as usize {
            return Err(ThresholdError::InsufficientParticipants {
                required: threshold_config.threshold,
                provided: participants.len() as u16,
            });
        }

        Ok(Self {
            scheme,
            threshold_config,
            session_timeout: Duration::from_secs(300), // 5 minutes default
            round_timeout: Duration::from_secs(60),    // 1 minute per round
            fips_mode: false,
            session_id: None,
            participants,
        })
    }

    /// Set the session timeout.
    pub fn with_session_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = timeout;
        self
    }

    /// Set the round timeout.
    pub fn with_round_timeout(mut self, timeout: Duration) -> Self {
        self.round_timeout = timeout;
        self
    }

    /// Enable FIPS mode.
    pub fn with_fips_mode(mut self, enabled: bool) -> Self {
        self.fips_mode = enabled;
        self
    }

    /// Set a specific session ID.
    pub fn with_session_id(mut self, id: SessionId) -> Self {
        self.session_id = Some(id);
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ThresholdError> {
        // Check FIPS compliance if required
        if self.fips_mode && !self.scheme.is_fips_approved() {
            return Err(ThresholdError::FipsNotApproved(format!(
                "Scheme {} is not FIPS approved",
                self.scheme
            )));
        }

        // Check participant count
        if self.participants.len() < self.threshold_config.threshold as usize {
            return Err(ThresholdError::InsufficientParticipants {
                required: self.threshold_config.threshold,
                provided: self.participants.len() as u16,
            });
        }

        // Check for duplicate participants
        let mut seen = std::collections::HashSet::new();
        for p in &self.participants {
            if !seen.insert(p) {
                return Err(ThresholdError::InvalidParticipant(format!(
                    "Duplicate participant: {}",
                    p
                )));
            }
        }

        Ok(())
    }
}

impl Default for SigningSessionConfig {
    fn default() -> Self {
        Self {
            scheme: ThresholdScheme::FrostEd25519,
            threshold_config: ThresholdConfig {
                threshold: 2,
                total_participants: 3,
            },
            session_timeout: Duration::from_secs(300),
            round_timeout: Duration::from_secs(60),
            fips_mode: false,
            session_id: None,
            participants: vec![],
        }
    }
}

/// Configuration for Distributed Key Generation (DKG).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgConfig {
    /// The threshold scheme for key generation.
    pub scheme: ThresholdScheme,

    /// Threshold configuration (t-of-n).
    pub threshold_config: ThresholdConfig,

    /// All participants in the DKG.
    pub participants: Vec<ParticipantId>,

    /// Maximum time for each DKG round.
    pub round_timeout: Duration,

    /// Whether to require FIPS-approved operations.
    pub fips_mode: bool,
}

impl DkgConfig {
    /// Create a new DKG configuration.
    pub fn new(
        scheme: ThresholdScheme,
        threshold: u16,
        participants: Vec<ParticipantId>,
    ) -> Result<Self, ThresholdError> {
        let total = participants.len() as u16;
        let threshold_config = ThresholdConfig::new(threshold, total)?;

        Ok(Self {
            scheme,
            threshold_config,
            participants,
            round_timeout: Duration::from_secs(60),
            fips_mode: false,
        })
    }

    /// Set the round timeout.
    pub fn with_round_timeout(mut self, timeout: Duration) -> Self {
        self.round_timeout = timeout;
        self
    }

    /// Enable FIPS mode.
    pub fn with_fips_mode(mut self, enabled: bool) -> Self {
        self.fips_mode = enabled;
        self
    }

    /// Validate the DKG configuration.
    pub fn validate(&self) -> Result<(), ThresholdError> {
        // Check FIPS compliance
        if self.fips_mode && !self.scheme.is_fips_approved() {
            return Err(ThresholdError::FipsNotApproved(format!(
                "Scheme {} is not FIPS approved for DKG",
                self.scheme
            )));
        }

        // Check participant count matches config
        if self.participants.len() != self.threshold_config.total_participants as usize {
            return Err(ThresholdError::InvalidThreshold(format!(
                "Participant count ({}) doesn't match total_participants ({})",
                self.participants.len(),
                self.threshold_config.total_participants
            )));
        }

        // Check for duplicate participants
        let mut seen = std::collections::HashSet::new();
        for p in &self.participants {
            if !seen.insert(p) {
                return Err(ThresholdError::InvalidParticipant(format!(
                    "Duplicate participant in DKG: {}",
                    p
                )));
            }
        }

        // Validate participant IDs are non-zero
        for p in &self.participants {
            if p.0 == 0 {
                return Err(ThresholdError::InvalidParticipant(
                    "Participant ID 0 is not allowed".into(),
                ));
            }
        }

        Ok(())
    }
}

/// Configuration for key refresh operations.
///
/// Key refresh updates all shares while preserving the group public key,
/// providing proactive security against gradual key compromise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRefreshConfig {
    /// The threshold scheme.
    pub scheme: ThresholdScheme,

    /// Current threshold configuration.
    pub current_config: ThresholdConfig,

    /// New threshold (can be different from current).
    pub new_threshold: u16,

    /// Participants in the refresh operation.
    pub participants: Vec<ParticipantId>,

    /// Timeout for each refresh round.
    pub round_timeout: Duration,

    /// Whether to require FIPS-approved operations.
    pub fips_mode: bool,
}

impl KeyRefreshConfig {
    /// Create a new key refresh configuration with the same threshold.
    pub fn same_threshold(
        scheme: ThresholdScheme,
        current_config: ThresholdConfig,
        participants: Vec<ParticipantId>,
    ) -> Result<Self, ThresholdError> {
        if participants.len() < current_config.threshold as usize {
            return Err(ThresholdError::InsufficientParticipants {
                required: current_config.threshold,
                provided: participants.len() as u16,
            });
        }

        Ok(Self {
            scheme,
            current_config,
            new_threshold: current_config.threshold,
            participants,
            round_timeout: Duration::from_secs(60),
            fips_mode: false,
        })
    }

    /// Create a configuration that changes the threshold.
    pub fn with_new_threshold(
        scheme: ThresholdScheme,
        current_config: ThresholdConfig,
        new_threshold: u16,
        participants: Vec<ParticipantId>,
    ) -> Result<Self, ThresholdError> {
        // Validate new threshold
        if new_threshold == 0 {
            return Err(ThresholdError::InvalidThreshold(
                "New threshold must be > 0".into(),
            ));
        }
        if new_threshold > participants.len() as u16 {
            return Err(ThresholdError::InvalidThreshold(format!(
                "New threshold ({}) cannot exceed participant count ({})",
                new_threshold,
                participants.len()
            )));
        }

        // Need at least current threshold participants
        if participants.len() < current_config.threshold as usize {
            return Err(ThresholdError::InsufficientParticipants {
                required: current_config.threshold,
                provided: participants.len() as u16,
            });
        }

        Ok(Self {
            scheme,
            current_config,
            new_threshold,
            participants,
            round_timeout: Duration::from_secs(60),
            fips_mode: false,
        })
    }

    /// Set the round timeout.
    pub fn with_round_timeout(mut self, timeout: Duration) -> Self {
        self.round_timeout = timeout;
        self
    }

    /// Enable FIPS mode.
    pub fn with_fips_mode(mut self, enabled: bool) -> Self {
        self.fips_mode = enabled;
        self
    }

    /// Check if threshold is changing.
    pub fn is_threshold_changing(&self) -> bool {
        self.new_threshold != self.current_config.threshold
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ThresholdError> {
        if self.fips_mode && !self.scheme.is_fips_approved() {
            return Err(ThresholdError::FipsNotApproved(format!(
                "Scheme {} is not FIPS approved for key refresh",
                self.scheme
            )));
        }

        Ok(())
    }
}

/// Configuration for resharing operations.
///
/// Resharing allows changing the participant set and/or threshold
/// while preserving the group public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResharingConfig {
    /// The threshold scheme.
    pub scheme: ThresholdScheme,

    /// Old threshold configuration.
    pub old_config: ThresholdConfig,

    /// New threshold configuration.
    pub new_config: ThresholdConfig,

    /// Old participants (must have at least old_threshold active).
    pub old_participants: Vec<ParticipantId>,

    /// New participants (will receive new shares).
    pub new_participants: Vec<ParticipantId>,

    /// Timeout for resharing rounds.
    pub round_timeout: Duration,

    /// Whether to require FIPS-approved operations.
    pub fips_mode: bool,
}

impl ResharingConfig {
    /// Create a new resharing configuration.
    pub fn new(
        scheme: ThresholdScheme,
        old_config: ThresholdConfig,
        new_threshold: u16,
        old_participants: Vec<ParticipantId>,
        new_participants: Vec<ParticipantId>,
    ) -> Result<Self, ThresholdError> {
        // Need at least old threshold from old participants
        if old_participants.len() < old_config.threshold as usize {
            return Err(ThresholdError::ResharingInsufficientShares {
                required: old_config.threshold as usize,
                provided: old_participants.len(),
            });
        }

        // Validate new configuration
        let new_config = ThresholdConfig::new(new_threshold, new_participants.len() as u16)?;

        Ok(Self {
            scheme,
            old_config,
            new_config,
            old_participants,
            new_participants,
            round_timeout: Duration::from_secs(120),
            fips_mode: false,
        })
    }

    /// Set the round timeout.
    pub fn with_round_timeout(mut self, timeout: Duration) -> Self {
        self.round_timeout = timeout;
        self
    }

    /// Enable FIPS mode.
    pub fn with_fips_mode(mut self, enabled: bool) -> Self {
        self.fips_mode = enabled;
        self
    }

    /// Check if participants are changing.
    pub fn is_participant_set_changing(&self) -> bool {
        self.old_participants != self.new_participants
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ThresholdError> {
        if self.fips_mode && !self.scheme.is_fips_approved() {
            return Err(ThresholdError::FipsNotApproved(format!(
                "Scheme {} is not FIPS approved for resharing",
                self.scheme
            )));
        }

        // Check for overlap between old and new participants
        // (common participants can keep some verification context)
        let old_set: std::collections::HashSet<_> = self.old_participants.iter().collect();
        let new_set: std::collections::HashSet<_> = self.new_participants.iter().collect();
        let _overlap: Vec<_> = old_set.intersection(&new_set).collect();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_session_config() {
        let config = SigningSessionConfig::new(
            ThresholdScheme::FrostEd25519,
            ThresholdConfig::new(2, 3).unwrap(),
            vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)],
        )
        .unwrap();

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_signing_session_fips_validation() {
        let config = SigningSessionConfig::new(
            ThresholdScheme::ThresholdEcdsaSecp256k1, // Not FIPS approved
            ThresholdConfig::new(2, 3).unwrap(),
            vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)],
        )
        .unwrap()
        .with_fips_mode(true);

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_dkg_config() {
        let config = DkgConfig::new(
            ThresholdScheme::ThresholdEcdsaP256,
            2,
            vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)],
        )
        .unwrap();

        assert!(config.validate().is_ok());
        assert_eq!(config.threshold_config.threshold, 2);
        assert_eq!(config.threshold_config.total_participants, 3);
    }

    #[test]
    fn test_key_refresh_config() {
        let current = ThresholdConfig::new(2, 3).unwrap();
        let config = KeyRefreshConfig::same_threshold(
            ThresholdScheme::FrostEd25519,
            current,
            vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)],
        )
        .unwrap();

        assert!(!config.is_threshold_changing());
    }

    #[test]
    fn test_resharing_config() {
        let old_config = ThresholdConfig::new(2, 3).unwrap();
        let config = ResharingConfig::new(
            ThresholdScheme::ThresholdBls12381,
            old_config,
            3, // New threshold
            vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)],
            vec![
                ParticipantId(1),
                ParticipantId(2),
                ParticipantId(3),
                ParticipantId(4),
                ParticipantId(5),
            ],
        )
        .unwrap();

        assert!(config.is_participant_set_changing());
        assert_eq!(config.new_config.threshold, 3);
        assert_eq!(config.new_config.total_participants, 5);
    }
}
