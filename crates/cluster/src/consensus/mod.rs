//! Raft consensus implementation

pub mod log;
pub mod state;

pub use log::{LogEntry, RaftLog};
pub use state::RaftState;

use crate::config::NodeId;
use crate::error::Result;
use crate::node::Command;
use serde::{Deserialize, Serialize};

/// Raft message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftMessage {
    /// Request vote (election)
    RequestVote(RequestVoteRequest),

    /// Request vote response
    RequestVoteResponse(RequestVoteResponse),

    /// Append entries (log replication / heartbeat)
    AppendEntries(AppendEntriesRequest),

    /// Append entries response
    AppendEntriesResponse(AppendEntriesResponse),

    /// Install snapshot
    InstallSnapshot(InstallSnapshotRequest),

    /// Install snapshot response
    InstallSnapshotResponse(InstallSnapshotResponse),

    /// Pre-vote request (prevents disruption from partitioned nodes)
    PreVote(PreVoteRequest),

    /// Pre-vote response
    PreVoteResponse(PreVoteResponse),
}

/// Request vote request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteRequest {
    /// Candidate's term
    pub term: u64,

    /// Candidate requesting vote
    pub candidate_id: NodeId,

    /// Index of candidate's last log entry
    pub last_log_index: u64,

    /// Term of candidate's last log entry
    pub last_log_term: u64,
}

/// Request vote response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteResponse {
    /// Current term, for candidate to update itself
    pub term: u64,

    /// True means candidate received vote
    pub vote_granted: bool,
}

/// Append entries request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesRequest {
    /// Leader's term
    pub term: u64,

    /// Leader's ID
    pub leader_id: NodeId,

    /// Index of log entry immediately preceding new ones
    pub prev_log_index: u64,

    /// Term of prev_log_index entry
    pub prev_log_term: u64,

    /// Log entries to store (empty for heartbeat)
    pub entries: Vec<LogEntry>,

    /// Leader's commit index
    pub leader_commit: u64,
}

/// Append entries response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesResponse {
    /// Current term, for leader to update itself
    pub term: u64,

    /// True if follower contained entry matching prev_log_index and prev_log_term
    pub success: bool,

    /// Index of the last entry the follower has (for fast catch-up)
    pub match_index: Option<u64>,
}

/// Install snapshot request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshotRequest {
    /// Leader's term
    pub term: u64,

    /// Leader's ID
    pub leader_id: NodeId,

    /// Index of the last entry included in snapshot
    pub last_included_index: u64,

    /// Term of the last entry included in snapshot
    pub last_included_term: u64,

    /// Byte offset in the snapshot file
    pub offset: u64,

    /// Raw snapshot data
    pub data: Vec<u8>,

    /// True if this is the last chunk
    pub done: bool,
}

/// Install snapshot response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshotResponse {
    /// Current term, for leader to update itself
    pub term: u64,
}

/// Pre-vote request (Raft pre-vote extension)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreVoteRequest {
    /// Next term the candidate would request
    pub term: u64,

    /// Candidate requesting pre-vote
    pub candidate_id: NodeId,

    /// Index of candidate's last log entry
    pub last_log_index: u64,

    /// Term of candidate's last log entry
    pub last_log_term: u64,
}

/// Pre-vote response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreVoteResponse {
    /// Current term
    pub term: u64,

    /// True if would vote for candidate
    pub vote_granted: bool,
}
