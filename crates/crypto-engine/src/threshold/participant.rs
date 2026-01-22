//! Signing Participant
//!
//! Represents a party holding a key share who can participate in threshold
//! signing sessions. Each participant manages their own state and can
//! participate in multiple concurrent signing sessions.
//!
//! # Security
//!
//! - Key shares must be stored securely
//! - Nonces must never be reused across sessions
//! - Participants should verify they're signing the expected message
//! - Sessions are automatically cleaned up after signing

use std::collections::HashMap;

use super::frost::FrostEngine;
use super::types::*;

/// Active signing session state for a participant.
struct SigningSession {
    /// The message being signed.
    message: Vec<u8>,
    /// The nonce for this session (secret).
    nonce: SigningNonce,
    /// The commitment generated for this session.
    commitment: SigningCommitment,
}

/// A participant in the threshold signing scheme.
///
/// Manages a key share and can participate in signing sessions.
/// Each participant can handle multiple concurrent signing sessions.
pub struct SigningParticipant {
    /// The participant's secret key share.
    key_share: KeyShare,
    /// The group's public key.
    group_public_key: GroupPublicKey,
    /// Active signing sessions keyed by message hash.
    active_sessions: HashMap<Vec<u8>, SigningSession>,
    /// Maximum concurrent sessions allowed.
    max_sessions: usize,
}

impl SigningParticipant {
    /// Create a new signing participant from a key share.
    ///
    /// # Arguments
    ///
    /// * `key_share` - The participant's secret key share
    /// * `group_public_key` - The group's public key
    ///
    /// # Returns
    ///
    /// A new SigningParticipant ready to participate in signing sessions.
    pub fn new(key_share: KeyShare, group_public_key: GroupPublicKey) -> Self {
        Self {
            key_share,
            group_public_key,
            active_sessions: HashMap::new(),
            max_sessions: 16, // Default limit
        }
    }

    /// Create a new signing participant with a custom session limit.
    ///
    /// # Arguments
    ///
    /// * `key_share` - The participant's secret key share
    /// * `group_public_key` - The group's public key
    /// * `max_sessions` - Maximum number of concurrent sessions
    pub fn with_max_sessions(
        key_share: KeyShare,
        group_public_key: GroupPublicKey,
        max_sessions: usize,
    ) -> Self {
        Self {
            key_share,
            group_public_key,
            active_sessions: HashMap::new(),
            max_sessions,
        }
    }

    /// Get the participant's ID.
    pub fn id(&self) -> ParticipantId {
        self.key_share.participant_id
    }

    /// Get the group's public key.
    pub fn group_public_key(&self) -> &GroupPublicKey {
        &self.group_public_key
    }

    /// Get the threshold configuration.
    pub fn config(&self) -> ThresholdConfig {
        self.key_share.config
    }

    /// Start a new signing session for a message.
    ///
    /// Generates fresh nonces and a commitment. The commitment should be
    /// sent to the coordinator or other participants.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to be signed
    ///
    /// # Returns
    ///
    /// A SigningCommitment to share with the coordinator.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Maximum concurrent sessions reached
    /// - A session for this message already exists
    /// - Nonce generation fails
    pub fn start_signing(&mut self, message: Vec<u8>) -> Result<SigningCommitment, ThresholdError> {
        // Check session limit
        if self.active_sessions.len() >= self.max_sessions {
            return Err(ThresholdError::SessionError(format!(
                "Maximum concurrent sessions ({}) reached",
                self.max_sessions
            )));
        }

        // Use message hash as session key to handle duplicate messages
        let session_key = Self::hash_message(&message);

        // Check for existing session
        if self.active_sessions.contains_key(&session_key) {
            return Err(ThresholdError::SessionError(
                "Session already exists for this message".into(),
            ));
        }

        // Generate nonces and commitment
        let (nonce, commitment) = FrostEngine::generate_nonces(&self.key_share)?;

        // Store session
        self.active_sessions.insert(
            session_key,
            SigningSession {
                message,
                nonce,
                commitment: commitment.clone(),
            },
        );

        Ok(commitment)
    }

    /// Generate a signature share after receiving all commitments.
    ///
    /// # Arguments
    ///
    /// * `message` - The message being signed (must match start_signing)
    /// * `all_commitments` - All commitments from participating signers
    ///
    /// # Returns
    ///
    /// A SignatureShare to send to the coordinator.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - No active session for this message
    /// - Message doesn't match the session
    /// - Not enough commitments
    /// - Signing fails
    ///
    /// # Note
    ///
    /// The session is consumed after signing. Start a new session to sign again.
    pub fn sign(
        &mut self,
        message: &[u8],
        all_commitments: &[SigningCommitment],
    ) -> Result<SignatureShare, ThresholdError> {
        let session_key = Self::hash_message(message);

        let session = self.active_sessions.remove(&session_key).ok_or_else(|| {
            ThresholdError::SessionError("No active session for this message".into())
        })?;

        // Verify message matches
        if session.message != message {
            // Put session back
            self.active_sessions.insert(session_key, session);
            return Err(ThresholdError::SigningFailed(
                "Message does not match session".into(),
            ));
        }

        // Verify our commitment is in the list
        let our_commitment_found = all_commitments
            .iter()
            .any(|c| c.participant_id == self.key_share.participant_id);

        if !our_commitment_found {
            // Put session back
            self.active_sessions.insert(session_key, session);
            return Err(ThresholdError::SigningFailed(
                "Our commitment not found in the commitment list".into(),
            ));
        }

        // Generate signature share
        FrostEngine::sign_share(
            &self.key_share,
            &session.nonce,
            message,
            all_commitments,
            &self.group_public_key,
        )
        // Session is consumed (dropped) here, nonce is zeroized
    }

    /// Abort a signing session for a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to abort signing for
    ///
    /// # Returns
    ///
    /// `true` if a session was aborted, `false` if no session existed.
    pub fn abort_signing(&mut self, message: &[u8]) -> bool {
        let session_key = Self::hash_message(message);
        self.active_sessions.remove(&session_key).is_some()
    }

    /// Check if there's an active session for a message.
    pub fn has_session(&self, message: &[u8]) -> bool {
        let session_key = Self::hash_message(message);
        self.active_sessions.contains_key(&session_key)
    }

    /// Get the number of active sessions.
    pub fn active_session_count(&self) -> usize {
        self.active_sessions.len()
    }

    /// Clear all active sessions.
    ///
    /// Use with caution - this will invalidate any in-progress signing.
    pub fn clear_sessions(&mut self) {
        self.active_sessions.clear();
    }

    /// Get the commitment for an active session.
    ///
    /// Useful if the commitment needs to be re-sent.
    pub fn get_commitment(&self, message: &[u8]) -> Option<SigningCommitment> {
        let session_key = Self::hash_message(message);
        self.active_sessions
            .get(&session_key)
            .map(|s| s.commitment.clone())
    }

    /// Compute a hash of the message for session lookup.
    fn hash_message(message: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    }
}

impl std::fmt::Debug for SigningParticipant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningParticipant")
            .field("participant_id", &self.key_share.participant_id)
            .field("config", &self.key_share.config)
            .field("active_sessions", &self.active_sessions.len())
            .field("max_sessions", &self.max_sessions)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_participants() -> (GroupPublicKey, Vec<SigningParticipant>) {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        let participants: Vec<_> = shares
            .into_iter()
            .map(|share| SigningParticipant::new(share, group_key.clone()))
            .collect();

        (group_key, participants)
    }

    #[test]
    fn test_participant_creation() {
        let (group_key, participants) = setup_participants();

        assert_eq!(participants.len(), 3);
        for (i, p) in participants.iter().enumerate() {
            assert_eq!(p.config().threshold, 2);
            assert_eq!(p.config().total_participants, 3);
            assert_eq!(p.active_session_count(), 0);
        }
    }

    #[test]
    fn test_start_signing() {
        let (_, mut participants) = setup_participants();
        let message = b"Test message";

        let commitment = participants[0].start_signing(message.to_vec()).unwrap();

        assert_eq!(commitment.participant_id, participants[0].id());
        assert!(participants[0].has_session(message));
        assert_eq!(participants[0].active_session_count(), 1);
    }

    #[test]
    fn test_full_signing_flow() {
        let (group_key, mut participants) = setup_participants();
        let message = b"Test message for participant signing";

        // Start signing for first 2 participants
        let commitment1 = participants[0].start_signing(message.to_vec()).unwrap();
        let commitment2 = participants[1].start_signing(message.to_vec()).unwrap();

        let all_commitments = vec![commitment1, commitment2];

        // Generate signature shares
        let sig_share1 = participants[0].sign(message, &all_commitments).unwrap();
        let sig_share2 = participants[1].sign(message, &all_commitments).unwrap();

        // Sessions should be consumed
        assert!(!participants[0].has_session(message));
        assert!(!participants[1].has_session(message));

        // Aggregate and verify
        let signature = FrostEngine::aggregate_signatures(
            message,
            &all_commitments,
            &[sig_share1, sig_share2],
            &group_key,
        )
        .unwrap();

        let valid = FrostEngine::verify(&group_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_abort_signing() {
        let (_, mut participants) = setup_participants();
        let message = b"Test message";

        participants[0].start_signing(message.to_vec()).unwrap();
        assert!(participants[0].has_session(message));

        let aborted = participants[0].abort_signing(message);
        assert!(aborted);
        assert!(!participants[0].has_session(message));

        // Abort non-existent session
        let aborted = participants[0].abort_signing(message);
        assert!(!aborted);
    }

    #[test]
    fn test_session_limit() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        let mut participant =
            SigningParticipant::with_max_sessions(shares.into_iter().next().unwrap(), group_key, 2);

        // Can start 2 sessions
        participant.start_signing(b"message1".to_vec()).unwrap();
        participant.start_signing(b"message2".to_vec()).unwrap();

        // Third should fail
        let result = participant.start_signing(b"message3".to_vec());
        assert!(matches!(result, Err(ThresholdError::SessionError(_))));
    }

    #[test]
    fn test_duplicate_session_rejected() {
        let (_, mut participants) = setup_participants();
        let message = b"Test message";

        participants[0].start_signing(message.to_vec()).unwrap();

        // Try to start another session for the same message
        let result = participants[0].start_signing(message.to_vec());
        assert!(matches!(result, Err(ThresholdError::SessionError(_))));
    }

    #[test]
    fn test_sign_without_session_fails() {
        let (_, mut participants) = setup_participants();
        let message = b"Test message";

        // Try to sign without starting a session
        let result = participants[0].sign(message, &[]);
        assert!(matches!(result, Err(ThresholdError::SessionError(_))));
    }

    #[test]
    fn test_get_commitment() {
        let (_, mut participants) = setup_participants();
        let message = b"Test message";

        let commitment = participants[0].start_signing(message.to_vec()).unwrap();
        let retrieved = participants[0].get_commitment(message).unwrap();

        assert_eq!(commitment.participant_id, retrieved.participant_id);
        assert_eq!(commitment.commitment_bytes, retrieved.commitment_bytes);
    }

    #[test]
    fn test_clear_sessions() {
        let (_, mut participants) = setup_participants();

        participants[0].start_signing(b"message1".to_vec()).unwrap();
        participants[0].start_signing(b"message2".to_vec()).unwrap();
        assert_eq!(participants[0].active_session_count(), 2);

        participants[0].clear_sessions();
        assert_eq!(participants[0].active_session_count(), 0);
    }

    #[test]
    fn test_concurrent_sessions() {
        let (group_key, mut participants) = setup_participants();
        let message1 = b"First message";
        let message2 = b"Second message";

        // Start sessions for both messages
        let commit1_p0 = participants[0].start_signing(message1.to_vec()).unwrap();
        let commit2_p0 = participants[0].start_signing(message2.to_vec()).unwrap();
        let commit1_p1 = participants[1].start_signing(message1.to_vec()).unwrap();
        let commit2_p1 = participants[1].start_signing(message2.to_vec()).unwrap();

        assert_eq!(participants[0].active_session_count(), 2);
        assert_eq!(participants[1].active_session_count(), 2);

        // Sign message 1
        let commitments1 = vec![commit1_p0, commit1_p1];
        let share1_p0 = participants[0].sign(message1, &commitments1).unwrap();
        let share1_p1 = participants[1].sign(message1, &commitments1).unwrap();

        // Sign message 2
        let commitments2 = vec![commit2_p0, commit2_p1];
        let share2_p0 = participants[0].sign(message2, &commitments2).unwrap();
        let share2_p1 = participants[1].sign(message2, &commitments2).unwrap();

        // Verify both signatures
        let sig1 = FrostEngine::aggregate_signatures(
            message1,
            &commitments1,
            &[share1_p0, share1_p1],
            &group_key,
        )
        .unwrap();

        let sig2 = FrostEngine::aggregate_signatures(
            message2,
            &commitments2,
            &[share2_p0, share2_p1],
            &group_key,
        )
        .unwrap();

        assert!(FrostEngine::verify(&group_key, message1, &sig1).unwrap());
        assert!(FrostEngine::verify(&group_key, message2, &sig2).unwrap());
    }
}
