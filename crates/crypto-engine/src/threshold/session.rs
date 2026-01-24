//! Threshold signing session management
//!
//! This module provides session tracking and state management for
//! multi-round threshold signing protocols.

use super::config::SigningSessionConfig;
use super::types::{
    ParticipantId, SessionId, SignatureShare, SigningCommitment, ThresholdError, ThresholdScheme,
    ThresholdSignature,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// State of a threshold signing session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session created, waiting for commitments (Round 1).
    AwaitingCommitments,

    /// Commitments received, waiting for signature shares (Round 2).
    AwaitingSignatureShares,

    /// All shares received, aggregating signature.
    Aggregating,

    /// Session completed successfully.
    Complete,

    /// Session failed.
    Failed,

    /// Session expired due to timeout.
    Expired,
}

impl SessionState {
    /// Check if the session is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SessionState::Complete | SessionState::Failed | SessionState::Expired
        )
    }

    /// Check if the session can accept commitments.
    pub fn can_accept_commitments(&self) -> bool {
        matches!(self, SessionState::AwaitingCommitments)
    }

    /// Check if the session can accept signature shares.
    pub fn can_accept_shares(&self) -> bool {
        matches!(self, SessionState::AwaitingSignatureShares)
    }
}

/// Participant's state within a signing session.
#[derive(Debug, Clone)]
pub struct ParticipantSessionState {
    /// The participant's ID.
    pub participant_id: ParticipantId,

    /// Whether commitment has been received.
    pub commitment_received: bool,

    /// Whether signature share has been received.
    pub share_received: bool,

    /// Timestamp of last activity.
    pub last_activity: Instant,
}

impl ParticipantSessionState {
    /// Create a new participant state.
    pub fn new(participant_id: ParticipantId) -> Self {
        Self {
            participant_id,
            commitment_received: false,
            share_received: false,
            last_activity: Instant::now(),
        }
    }
}

/// A threshold signing session.
///
/// Tracks the state of a multi-party signing operation, including
/// received commitments and signature shares from each participant.
#[derive(Debug)]
pub struct ThresholdSession {
    /// Unique session identifier.
    pub id: SessionId,

    /// Session configuration.
    pub config: SigningSessionConfig,

    /// Current session state.
    pub state: SessionState,

    /// The message being signed.
    pub message: Vec<u8>,

    /// Per-participant state.
    participants: HashMap<ParticipantId, ParticipantSessionState>,

    /// Collected commitments.
    commitments: HashMap<ParticipantId, SigningCommitment>,

    /// Collected signature shares.
    signature_shares: HashMap<ParticipantId, SignatureShare>,

    /// The final signature (if complete).
    signature: Option<ThresholdSignature>,

    /// Error message (if failed).
    error: Option<String>,

    /// Session creation time.
    created_at: Instant,

    /// Last state change time.
    last_updated: Instant,
}

impl ThresholdSession {
    /// Create a new signing session.
    pub fn new(config: SigningSessionConfig, message: Vec<u8>) -> Result<Self, ThresholdError> {
        config.validate()?;

        let session_id = config.session_id.clone().unwrap_or_else(SessionId::new);

        let participants: HashMap<ParticipantId, ParticipantSessionState> = config
            .participants
            .iter()
            .map(|p| (*p, ParticipantSessionState::new(*p)))
            .collect();

        Ok(Self {
            id: session_id,
            config,
            state: SessionState::AwaitingCommitments,
            message,
            participants,
            commitments: HashMap::new(),
            signature_shares: HashMap::new(),
            signature: None,
            error: None,
            created_at: Instant::now(),
            last_updated: Instant::now(),
        })
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.id
    }

    /// Get the threshold scheme.
    pub fn scheme(&self) -> ThresholdScheme {
        self.config.scheme
    }

    /// Get the current state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.config.session_timeout
    }

    /// Check if current round has timed out.
    pub fn is_round_timed_out(&self) -> bool {
        self.last_updated.elapsed() > self.config.round_timeout
    }

    /// Add a commitment from a participant.
    pub fn add_commitment(&mut self, commitment: SigningCommitment) -> Result<(), ThresholdError> {
        // Check session state
        if !self.state.can_accept_commitments() {
            return Err(ThresholdError::SessionError(format!(
                "Cannot accept commitments in state {:?}",
                self.state
            )));
        }

        // Check timeout
        if self.is_expired() {
            self.state = SessionState::Expired;
            return Err(ThresholdError::SessionExpired(self.id.clone()));
        }

        // Verify participant is expected
        let participant_id = commitment.participant_id;
        if !self.participants.contains_key(&participant_id) {
            return Err(ThresholdError::InvalidParticipant(format!(
                "Unexpected participant: {}",
                participant_id
            )));
        }

        // Check for duplicate
        if self.commitments.contains_key(&participant_id) {
            return Err(ThresholdError::SessionError(format!(
                "Duplicate commitment from {}",
                participant_id
            )));
        }

        // Store commitment
        self.commitments.insert(participant_id, commitment);
        if let Some(state) = self.participants.get_mut(&participant_id) {
            state.commitment_received = true;
            state.last_activity = Instant::now();
        }
        self.last_updated = Instant::now();

        // Check if we have enough commitments to proceed
        if self.commitments.len() >= self.config.threshold_config.threshold as usize {
            self.state = SessionState::AwaitingSignatureShares;
        }

        Ok(())
    }

    /// Add a signature share from a participant.
    pub fn add_signature_share(&mut self, share: SignatureShare) -> Result<(), ThresholdError> {
        // Check session state
        if !self.state.can_accept_shares() {
            return Err(ThresholdError::SessionError(format!(
                "Cannot accept signature shares in state {:?}",
                self.state
            )));
        }

        // Check timeout
        if self.is_expired() {
            self.state = SessionState::Expired;
            return Err(ThresholdError::SessionExpired(self.id.clone()));
        }

        // Verify participant is expected and has submitted commitment
        let participant_id = share.participant_id;
        if !self.commitments.contains_key(&participant_id) {
            return Err(ThresholdError::SessionError(format!(
                "No commitment from participant {} - cannot accept share",
                participant_id
            )));
        }

        // Check for duplicate
        if self.signature_shares.contains_key(&participant_id) {
            return Err(ThresholdError::SessionError(format!(
                "Duplicate signature share from {}",
                participant_id
            )));
        }

        // Store share
        self.signature_shares.insert(participant_id, share);
        if let Some(state) = self.participants.get_mut(&participant_id) {
            state.share_received = true;
            state.last_activity = Instant::now();
        }
        self.last_updated = Instant::now();

        // Check if we have enough shares
        if self.signature_shares.len() >= self.config.threshold_config.threshold as usize {
            self.state = SessionState::Aggregating;
        }

        Ok(())
    }

    /// Get the collected commitments.
    pub fn commitments(&self) -> Vec<SigningCommitment> {
        self.commitments.values().cloned().collect()
    }

    /// Get the collected signature shares.
    pub fn signature_shares(&self) -> Vec<SignatureShare> {
        self.signature_shares.values().cloned().collect()
    }

    /// Get the participants who have submitted commitments.
    pub fn committed_participants(&self) -> Vec<ParticipantId> {
        self.commitments.keys().copied().collect()
    }

    /// Get the participants who have submitted signature shares.
    pub fn signed_participants(&self) -> Vec<ParticipantId> {
        self.signature_shares.keys().copied().collect()
    }

    /// Get participants who haven't submitted their commitment yet.
    pub fn pending_commitment_participants(&self) -> Vec<ParticipantId> {
        self.participants
            .keys()
            .filter(|p| !self.commitments.contains_key(p))
            .copied()
            .collect()
    }

    /// Get participants who haven't submitted their signature share yet.
    pub fn pending_share_participants(&self) -> Vec<ParticipantId> {
        self.commitments
            .keys()
            .filter(|p| !self.signature_shares.contains_key(p))
            .copied()
            .collect()
    }

    /// Check if the session is ready for aggregation.
    pub fn is_ready_for_aggregation(&self) -> bool {
        self.state == SessionState::Aggregating
            && self.signature_shares.len() >= self.config.threshold_config.threshold as usize
    }

    /// Mark the session as complete with the final signature.
    pub fn complete(&mut self, signature: ThresholdSignature) {
        self.signature = Some(signature);
        self.state = SessionState::Complete;
        self.last_updated = Instant::now();
    }

    /// Mark the session as failed.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
        self.state = SessionState::Failed;
        self.last_updated = Instant::now();
    }

    /// Get the final signature (if session is complete).
    pub fn signature(&self) -> Option<&ThresholdSignature> {
        self.signature.as_ref()
    }

    /// Get the error message (if session failed).
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Get session age.
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Get time since last update.
    pub fn time_since_update(&self) -> std::time::Duration {
        self.last_updated.elapsed()
    }

    /// Get progress summary.
    pub fn progress(&self) -> SessionProgress {
        SessionProgress {
            state: self.state,
            commitments_received: self.commitments.len(),
            commitments_required: self.config.threshold_config.threshold as usize,
            shares_received: self.signature_shares.len(),
            shares_required: self.config.threshold_config.threshold as usize,
            total_participants: self.config.threshold_config.total_participants as usize,
        }
    }
}

/// Progress information for a signing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProgress {
    /// Current session state.
    pub state: SessionState,

    /// Number of commitments received.
    pub commitments_received: usize,

    /// Number of commitments required (threshold).
    pub commitments_required: usize,

    /// Number of signature shares received.
    pub shares_received: usize,

    /// Number of shares required (threshold).
    pub shares_required: usize,

    /// Total number of participants.
    pub total_participants: usize,
}

impl SessionProgress {
    /// Get commitment progress as a percentage.
    pub fn commitment_progress_percent(&self) -> f64 {
        (self.commitments_received as f64 / self.commitments_required as f64) * 100.0
    }

    /// Get signature share progress as a percentage.
    pub fn share_progress_percent(&self) -> f64 {
        if self.shares_required == 0 {
            0.0
        } else {
            (self.shares_received as f64 / self.shares_required as f64) * 100.0
        }
    }
}

/// Manager for multiple concurrent signing sessions.
#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: HashMap<SessionId, ThresholdSession>,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Create a new signing session.
    pub fn create_session(
        &mut self,
        config: SigningSessionConfig,
        message: Vec<u8>,
    ) -> Result<SessionId, ThresholdError> {
        let session = ThresholdSession::new(config, message)?;
        let id = session.id.clone();
        self.sessions.insert(id.clone(), session);
        Ok(id)
    }

    /// Get a session by ID.
    pub fn get_session(&self, id: &SessionId) -> Option<&ThresholdSession> {
        self.sessions.get(id)
    }

    /// Get a mutable session by ID.
    pub fn get_session_mut(&mut self, id: &SessionId) -> Option<&mut ThresholdSession> {
        self.sessions.get_mut(id)
    }

    /// Remove a session.
    pub fn remove_session(&mut self, id: &SessionId) -> Option<ThresholdSession> {
        self.sessions.remove(id)
    }

    /// Get all session IDs.
    pub fn session_ids(&self) -> Vec<SessionId> {
        self.sessions.keys().cloned().collect()
    }

    /// Get count of active sessions.
    pub fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| !s.state.is_terminal())
            .count()
    }

    /// Clean up expired sessions.
    pub fn cleanup_expired(&mut self) -> usize {
        let expired: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();
        for id in expired {
            self.sessions.remove(&id);
        }
        count
    }

    /// Clean up completed/failed sessions older than the given duration.
    pub fn cleanup_old_terminal(&mut self, max_age: std::time::Duration) -> usize {
        let old: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.state.is_terminal() && s.age() > max_age)
            .map(|(id, _)| id.clone())
            .collect();

        let count = old.len();
        for id in old {
            self.sessions.remove(&id);
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::types::ThresholdConfig;

    fn test_config() -> SigningSessionConfig {
        SigningSessionConfig::new(
            ThresholdScheme::FrostEd25519,
            ThresholdConfig::new(2, 3).unwrap(),
            vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)],
        )
        .unwrap()
    }

    #[test]
    fn test_session_creation() {
        let session = ThresholdSession::new(test_config(), b"test message".to_vec()).unwrap();
        assert_eq!(session.state(), SessionState::AwaitingCommitments);
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_commitment_flow() {
        let mut session = ThresholdSession::new(test_config(), b"test".to_vec()).unwrap();

        // Add first commitment
        let commit1 = SigningCommitment::new(ParticipantId(1), vec![0u8; 64]);
        session.add_commitment(commit1).unwrap();
        assert_eq!(session.state(), SessionState::AwaitingCommitments);

        // Add second commitment (meets threshold)
        let commit2 = SigningCommitment::new(ParticipantId(2), vec![0u8; 64]);
        session.add_commitment(commit2).unwrap();
        assert_eq!(session.state(), SessionState::AwaitingSignatureShares);
    }

    #[test]
    fn test_session_duplicate_commitment_rejected() {
        let mut session = ThresholdSession::new(test_config(), b"test".to_vec()).unwrap();

        let commit = SigningCommitment::new(ParticipantId(1), vec![0u8; 64]);
        session.add_commitment(commit.clone()).unwrap();

        // Duplicate should fail
        assert!(session.add_commitment(commit).is_err());
    }

    #[test]
    fn test_session_manager() {
        let mut manager = SessionManager::new();

        let id = manager
            .create_session(test_config(), b"test".to_vec())
            .unwrap();

        assert!(manager.get_session(&id).is_some());
        assert_eq!(manager.active_session_count(), 1);

        manager.remove_session(&id);
        assert!(manager.get_session(&id).is_none());
    }

    #[test]
    fn test_session_progress() {
        let session = ThresholdSession::new(test_config(), b"test".to_vec()).unwrap();
        let progress = session.progress();

        assert_eq!(progress.commitments_received, 0);
        assert_eq!(progress.commitments_required, 2);
        assert_eq!(progress.total_participants, 3);
    }
}
