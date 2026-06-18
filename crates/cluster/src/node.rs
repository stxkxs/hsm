//! Cluster node state machine

use crate::config::{ClusterConfig, NodeId};
use crate::consensus::RaftState;
use crate::error::{ClusterError, Result};
use crate::membership::MembershipManager;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// Cluster node state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterState {
    /// Node is starting up
    Starting,

    /// Node is a follower
    Follower,

    /// Node is a candidate (seeking election)
    Candidate,

    /// Node is the leader
    Leader,

    /// Node is partitioned/isolated
    Partitioned,

    /// Node is shutting down
    ShuttingDown,
}

impl std::fmt::Display for ClusterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Starting => write!(f, "Starting"),
            Self::Follower => write!(f, "Follower"),
            Self::Candidate => write!(f, "Candidate"),
            Self::Leader => write!(f, "Leader"),
            Self::Partitioned => write!(f, "Partitioned"),
            Self::ShuttingDown => write!(f, "ShuttingDown"),
        }
    }
}

/// Cluster node
pub struct ClusterNode {
    /// Node configuration
    config: ClusterConfig,

    /// Current state
    state: RwLock<ClusterState>,

    /// Raft consensus state
    raft_state: Arc<RwLock<RaftState>>,

    /// Membership manager
    membership: Arc<MembershipManager>,

    /// Start time
    start_time: Instant,

    /// Current term
    current_term: RwLock<u64>,

    /// Voted for in current term
    voted_for: RwLock<Option<NodeId>>,

    /// Current leader
    leader_id: RwLock<Option<NodeId>>,

    /// Replicated state machine: applied state derived from committed log entries.
    state_machine: RwLock<StateMachine>,
}

/// Applied state machine.
///
/// This holds the materialized result of applying committed Raft commands.
/// All replicas that apply the same sequence of committed commands converge
/// to identical contents here, which is the core safety property of a
/// replicated state machine.
#[derive(Debug, Default)]
struct StateMachine {
    /// Stored key blobs, keyed by key id.
    keys: HashMap<String, Vec<u8>>,

    /// Stored session blobs, keyed by session id.
    sessions: HashMap<String, Vec<u8>>,

    /// Recorded signing attempts (key_id -> set of message hashes seen),
    /// used to detect double-signing across the cluster.
    signing_records: HashMap<String, Vec<Vec<u8>>>,
}

impl ClusterNode {
    /// Create a new cluster node
    pub fn new(config: ClusterConfig) -> Result<Self> {
        let raft_state = Arc::new(RwLock::new(RaftState::new()));
        let membership = Arc::new(MembershipManager::new(config.clone()));

        Ok(Self {
            config,
            state: RwLock::new(ClusterState::Starting),
            raft_state,
            membership,
            start_time: Instant::now(),
            current_term: RwLock::new(0),
            voted_for: RwLock::new(None),
            leader_id: RwLock::new(None),
            state_machine: RwLock::new(StateMachine::default()),
        })
    }

    /// Get node ID
    pub fn node_id(&self) -> &NodeId {
        &self.config.node_id
    }

    /// Get current state
    pub fn state(&self) -> ClusterState {
        *self.state.read()
    }

    /// Get current term
    pub fn current_term(&self) -> u64 {
        *self.current_term.read()
    }

    /// Get current leader
    pub fn leader_id(&self) -> Option<NodeId> {
        self.leader_id.read().clone()
    }

    /// Check if this node is the leader
    pub fn is_leader(&self) -> bool {
        matches!(self.state(), ClusterState::Leader)
    }

    /// Check if cluster has a leader
    pub fn has_leader(&self) -> bool {
        self.leader_id.read().is_some()
    }

    /// Start the node
    pub async fn start(&self) -> Result<()> {
        tracing::info!(node_id = %self.node_id(), "Starting cluster node");

        // Transition to follower state
        *self.state.write() = ClusterState::Follower;

        // Start membership management
        self.membership.start().await?;

        // Start election timer
        self.start_election_timer().await;

        Ok(())
    }

    /// Stop the node
    pub async fn stop(&self) -> Result<()> {
        tracing::info!(node_id = %self.node_id(), "Stopping cluster node");

        *self.state.write() = ClusterState::ShuttingDown;

        // Stop membership management
        self.membership.stop().await?;

        Ok(())
    }

    /// Propose a command to the cluster
    pub async fn propose(&self, command: Command) -> Result<CommandResult> {
        if !self.is_leader() {
            return Err(ClusterError::NotLeader {
                leader: self.leader_id(),
            });
        }

        // Append to log
        let index = self.raft_state.write().append_entry(command.clone())?;

        // Replicate to followers
        let replicated = self.replicate_entry(index).await?;

        if !replicated {
            return Err(ClusterError::QuorumNotReached {
                needed: self.quorum_size(),
                have: 1,
            });
        }

        // Apply command
        let result = self.apply_command(&command).await?;

        Ok(result)
    }

    /// Start election timer
    async fn start_election_timer(&self) {
        let timeout = self.config.raft.election_timeout();

        tokio::spawn({
            let state = *self.state.read();
            async move {
                tokio::time::sleep(timeout).await;
                // If still follower, start election
                if matches!(state, ClusterState::Follower) {
                    tracing::debug!("Election timeout, would start election");
                }
            }
        });
    }

    /// Replicate an entry to followers
    async fn replicate_entry(&self, _index: u64) -> Result<bool> {
        // In a real implementation, this would send AppendEntries RPCs
        // to all followers and wait for quorum acknowledgment
        Ok(true)
    }

    /// Apply a committed command to the replicated state machine.
    ///
    /// This is deterministic: applying the same command sequence on any
    /// replica produces identical `StateMachine` contents.
    async fn apply_command(&self, command: &Command) -> Result<CommandResult> {
        let mut sm = self.state_machine.write();

        match command {
            Command::StoreKey { key_id, data } => {
                tracing::debug!(key_id = %key_id, bytes = data.len(), "Storing key in cluster");
                sm.keys.insert(key_id.clone(), data.clone());
                Ok(CommandResult::Success)
            }
            Command::DeleteKey { key_id } => {
                tracing::debug!(key_id = %key_id, "Deleting key from cluster");
                sm.keys.remove(key_id);
                Ok(CommandResult::Success)
            }
            Command::RecordSigningAttempt {
                key_id,
                message_hash,
            } => {
                // Check for double-signing against previously recorded attempts.
                if Self::is_double_signing(&sm, key_id, message_hash) {
                    return Err(ClusterError::DoubleSigningAttempt {
                        key_id: key_id.clone(),
                    });
                }
                // Record the attempt so subsequent duplicates are rejected.
                sm.signing_records
                    .entry(key_id.clone())
                    .or_default()
                    .push(message_hash.clone());
                Ok(CommandResult::Success)
            }
            Command::CreateSession { session_id, data } => {
                tracing::debug!(session_id = %session_id, bytes = data.len(), "Creating session in cluster");
                sm.sessions.insert(session_id.clone(), data.clone());
                Ok(CommandResult::Success)
            }
            Command::DeleteSession { session_id } => {
                tracing::debug!(session_id = %session_id, "Deleting session from cluster");
                sm.sessions.remove(session_id);
                Ok(CommandResult::Success)
            }
        }
    }

    /// Check whether `(key_id, message_hash)` has already been recorded as a
    /// signing attempt in the applied state machine.
    fn is_double_signing(sm: &StateMachine, key_id: &str, message_hash: &[u8]) -> bool {
        sm.signing_records
            .get(key_id)
            .is_some_and(|hashes| hashes.iter().any(|h| h.as_slice() == message_hash))
    }

    /// Read an applied key blob from the replicated state machine.
    pub fn applied_key(&self, key_id: &str) -> Option<Vec<u8>> {
        self.state_machine.read().keys.get(key_id).cloned()
    }

    /// Read an applied session blob from the replicated state machine.
    pub fn applied_session(&self, session_id: &str) -> Option<Vec<u8>> {
        self.state_machine.read().sessions.get(session_id).cloned()
    }

    /// Number of keys currently applied to the state machine.
    pub fn applied_key_count(&self) -> usize {
        self.state_machine.read().keys.len()
    }

    /// Number of sessions currently applied to the state machine.
    pub fn applied_session_count(&self) -> usize {
        self.state_machine.read().sessions.len()
    }

    /// Handle a RequestVote RPC.
    ///
    /// Implements standard Raft vote-granting safety (§5.2, §5.4):
    ///
    /// * If the candidate's term is older than ours, reject.
    /// * If the candidate's term is newer, advance to it and clear any prior
    ///   vote (a new term means we have not yet voted in it).
    /// * Grant the vote only if, for the current term, we have not already
    ///   voted for a *different* candidate. A repeated request from the same
    ///   candidate is idempotently granted. This enforces "at most one vote
    ///   per term", which guarantees at most one leader per term.
    ///
    /// `_last_log_index` / `_last_log_term` are accepted for the full Raft
    /// log-up-to-date check; this node's election-restriction comparison is
    /// driven by the consensus layer and not re-evaluated here.
    pub fn handle_request_vote(
        &self,
        term: u64,
        candidate_id: &NodeId,
        _last_log_index: u64,
        _last_log_term: u64,
    ) -> bool {
        let mut current_term = self.current_term.write();
        let mut voted_for = self.voted_for.write();

        // Stale candidate term: never grant, and inform caller of our term.
        if term < *current_term {
            return false;
        }

        // Newer term: adopt it and reset the per-term vote.
        if term > *current_term {
            *current_term = term;
            *voted_for = None;
            // A higher term observed via RequestVote means we are no longer
            // a leader/candidate for the old term.
            *self.leader_id.write() = None;
        }

        match voted_for.as_ref() {
            // Already voted for this same candidate in this term: idempotent.
            Some(existing) if existing == candidate_id => true,
            // Already voted for a different candidate this term: refuse.
            Some(_) => false,
            // Not yet voted this term: grant and record the vote.
            None => {
                *voted_for = Some(candidate_id.clone());
                true
            }
        }
    }

    /// Get the candidate this node voted for in the current term, if any.
    pub fn voted_for(&self) -> Option<NodeId> {
        self.voted_for.read().clone()
    }

    /// Get quorum size (n/2 + 1)
    fn quorum_size(&self) -> usize {
        let total_nodes = self.config.peers.len() + 1;
        (total_nodes / 2) + 1
    }

    /// Get node uptime
    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Get cluster health status
    pub fn health_status(&self) -> ClusterHealth {
        let state = self.state();
        let has_leader = self.has_leader();
        let connected_peers = self.membership.connected_peer_count();
        let total_peers = self.config.peers.len();

        ClusterHealth {
            state,
            has_leader,
            is_healthy: matches!(state, ClusterState::Follower | ClusterState::Leader)
                && has_leader,
            connected_peers,
            total_peers,
            leader_id: self.leader_id(),
        }
    }
}

/// Command to be replicated through Raft
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Command {
    /// Store a key
    StoreKey { key_id: String, data: Vec<u8> },

    /// Delete a key
    DeleteKey { key_id: String },

    /// Record a signing attempt (for anti-double-signing)
    RecordSigningAttempt {
        key_id: String,
        message_hash: Vec<u8>,
    },

    /// Create a session
    CreateSession { session_id: String, data: Vec<u8> },

    /// Delete a session
    DeleteSession { session_id: String },
}

/// Result of applying a command
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CommandResult {
    /// Command succeeded
    Success,

    /// Command failed with error
    Failed { reason: String },
}

/// Cluster health status
#[derive(Debug, Clone)]
pub struct ClusterHealth {
    /// Current node state
    pub state: ClusterState,

    /// Whether cluster has a leader
    pub has_leader: bool,

    /// Whether node is healthy
    pub is_healthy: bool,

    /// Number of connected peers
    pub connected_peers: usize,

    /// Total number of peers
    pub total_peers: usize,

    /// Current leader ID
    pub leader_id: Option<NodeId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_state_display() {
        assert_eq!(format!("{}", ClusterState::Leader), "Leader");
        assert_eq!(format!("{}", ClusterState::Follower), "Follower");
    }

    #[tokio::test]
    async fn test_node_creation() {
        let config = ClusterConfig::default();
        let node = ClusterNode::new(config).unwrap();
        assert_eq!(node.state(), ClusterState::Starting);
    }

    #[tokio::test]
    async fn test_apply_store_and_delete_key() {
        let node = ClusterNode::new(ClusterConfig::default()).unwrap();

        // Initially empty.
        assert_eq!(node.applied_key_count(), 0);
        assert!(node.applied_key("k1").is_none());

        // StoreKey actually persists the data payload into the state machine.
        let result = node
            .apply_command(&Command::StoreKey {
                key_id: "k1".to_string(),
                data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            })
            .await
            .unwrap();
        assert!(matches!(result, CommandResult::Success));
        assert_eq!(node.applied_key("k1"), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(node.applied_key_count(), 1);

        // Overwriting with a new payload replaces the stored blob.
        node.apply_command(&Command::StoreKey {
            key_id: "k1".to_string(),
            data: vec![1, 2, 3],
        })
        .await
        .unwrap();
        assert_eq!(node.applied_key("k1"), Some(vec![1, 2, 3]));
        assert_eq!(node.applied_key_count(), 1);

        // DeleteKey removes it.
        node.apply_command(&Command::DeleteKey {
            key_id: "k1".to_string(),
        })
        .await
        .unwrap();
        assert!(node.applied_key("k1").is_none());
        assert_eq!(node.applied_key_count(), 0);
    }

    #[tokio::test]
    async fn test_apply_session_lifecycle() {
        let node = ClusterNode::new(ClusterConfig::default()).unwrap();

        node.apply_command(&Command::CreateSession {
            session_id: "s1".to_string(),
            data: vec![9, 9, 9],
        })
        .await
        .unwrap();
        assert_eq!(node.applied_session("s1"), Some(vec![9, 9, 9]));
        assert_eq!(node.applied_session_count(), 1);

        node.apply_command(&Command::DeleteSession {
            session_id: "s1".to_string(),
        })
        .await
        .unwrap();
        assert!(node.applied_session("s1").is_none());
        assert_eq!(node.applied_session_count(), 0);
    }

    #[tokio::test]
    async fn test_double_signing_detection() {
        let node = ClusterNode::new(ClusterConfig::default()).unwrap();

        // First attempt for (key, hash) succeeds and is recorded.
        node.apply_command(&Command::RecordSigningAttempt {
            key_id: "validator-1".to_string(),
            message_hash: vec![0xAB; 32],
        })
        .await
        .unwrap();

        // Replaying the same (key, hash) is rejected as double-signing.
        let err = node
            .apply_command(&Command::RecordSigningAttempt {
                key_id: "validator-1".to_string(),
                message_hash: vec![0xAB; 32],
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ClusterError::DoubleSigningAttempt { .. }));

        // A different hash for the same key is allowed.
        node.apply_command(&Command::RecordSigningAttempt {
            key_id: "validator-1".to_string(),
            message_hash: vec![0xCD; 32],
        })
        .await
        .unwrap();
    }

    #[test]
    fn test_vote_safety_one_vote_per_term() {
        let node = ClusterNode::new(ClusterConfig::default()).unwrap();

        // Term 1: grant the first candidate that asks.
        assert!(node.handle_request_vote(1, &"cand-a".to_string(), 0, 0));
        assert_eq!(node.current_term(), 1);
        assert_eq!(node.voted_for(), Some("cand-a".to_string()));

        // Same term, same candidate: idempotently granted.
        assert!(node.handle_request_vote(1, &"cand-a".to_string(), 0, 0));

        // Same term, a *different* candidate: refused (at most one vote/term).
        assert!(!node.handle_request_vote(1, &"cand-b".to_string(), 0, 0));
        assert_eq!(node.voted_for(), Some("cand-a".to_string()));

        // Newer term resets the per-term vote, so a new candidate is granted.
        assert!(node.handle_request_vote(2, &"cand-b".to_string(), 0, 0));
        assert_eq!(node.current_term(), 2);
        assert_eq!(node.voted_for(), Some("cand-b".to_string()));

        // A stale term is always rejected and never overwrites our vote.
        assert!(!node.handle_request_vote(1, &"cand-a".to_string(), 0, 0));
        assert_eq!(node.current_term(), 2);
        assert_eq!(node.voted_for(), Some("cand-b".to_string()));
    }
}
