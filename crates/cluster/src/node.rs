//! Cluster node state machine

use crate::config::{ClusterConfig, NodeId};
use crate::consensus::RaftState;
use crate::error::{ClusterError, Result};
use crate::membership::MembershipManager;
use parking_lot::RwLock;
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

    /// Apply a command to the state machine
    async fn apply_command(&self, command: &Command) -> Result<CommandResult> {
        match command {
            Command::StoreKey { key_id, data } => {
                tracing::debug!(key_id = %key_id, "Storing key in cluster");
                Ok(CommandResult::Success)
            }
            Command::DeleteKey { key_id } => {
                tracing::debug!(key_id = %key_id, "Deleting key from cluster");
                Ok(CommandResult::Success)
            }
            Command::RecordSigningAttempt {
                key_id,
                message_hash,
            } => {
                // Check for double-signing
                if self.check_double_signing(key_id, message_hash)? {
                    return Err(ClusterError::DoubleSigningAttempt {
                        key_id: key_id.clone(),
                    });
                }
                Ok(CommandResult::Success)
            }
            Command::CreateSession { session_id, data } => {
                tracing::debug!(session_id = %session_id, "Creating session in cluster");
                Ok(CommandResult::Success)
            }
            Command::DeleteSession { session_id } => {
                tracing::debug!(session_id = %session_id, "Deleting session from cluster");
                Ok(CommandResult::Success)
            }
        }
    }

    /// Check for double-signing attempt
    fn check_double_signing(&self, _key_id: &str, _message_hash: &[u8]) -> Result<bool> {
        // In a real implementation, this would check the signing database
        Ok(false)
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
}
