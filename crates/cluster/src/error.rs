//! Cluster error types

use thiserror::Error;

/// Result type for cluster operations
pub type Result<T> = std::result::Result<T, ClusterError>;

/// Cluster error types
#[derive(Debug, Error)]
pub enum ClusterError {
    /// Node is not the leader
    #[error("Not the leader. Leader is: {leader:?}")]
    NotLeader { leader: Option<String> },

    /// No leader currently elected
    #[error("No leader elected")]
    NoLeader,

    /// Quorum not reached
    #[error("Quorum not reached: need {needed}, have {have}")]
    QuorumNotReached { needed: usize, have: usize },

    /// Node not found
    #[error("Node not found: {0}")]
    NodeNotFound(String),

    /// Node already exists
    #[error("Node already exists: {0}")]
    NodeAlreadyExists(String),

    /// Replication failed
    #[error("Replication failed: {0}")]
    ReplicationFailed(String),

    /// Consensus timeout
    #[error("Consensus timeout after {0}ms")]
    ConsensusTimeout(u64),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Transport error
    #[error("Transport error: {0}")]
    Transport(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Split-brain detected
    #[error("Split-brain detected")]
    SplitBrain,

    /// Double-signing attempt detected
    #[error("Double-signing attempt detected for key {key_id}")]
    DoubleSigningAttempt { key_id: String },

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<sled::Error> for ClusterError {
    fn from(err: sled::Error) -> Self {
        ClusterError::Storage(err.to_string())
    }
}

impl From<serde_json::Error> for ClusterError {
    fn from(err: serde_json::Error) -> Self {
        ClusterError::Serialization(err.to_string())
    }
}
