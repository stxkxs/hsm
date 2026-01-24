//! Raft state machine

use super::log::RaftLog;
use crate::error::Result;
use crate::node::Command;

/// Raft state
pub struct RaftState {
    /// Persistent log
    log: RaftLog,

    /// Current term
    current_term: u64,

    /// Voted for in current term
    voted_for: Option<String>,
}

impl RaftState {
    /// Create a new Raft state
    pub fn new() -> Self {
        Self {
            log: RaftLog::new(),
            current_term: 0,
            voted_for: None,
        }
    }

    /// Get current term
    pub fn current_term(&self) -> u64 {
        self.current_term
    }

    /// Update term
    pub fn update_term(&mut self, term: u64) {
        if term > self.current_term {
            self.current_term = term;
            self.voted_for = None;
        }
    }

    /// Get voted for
    pub fn voted_for(&self) -> Option<&str> {
        self.voted_for.as_deref()
    }

    /// Vote for a candidate
    pub fn vote_for(&mut self, candidate_id: String) {
        self.voted_for = Some(candidate_id);
    }

    /// Append an entry to the log
    pub fn append_entry(&mut self, command: Command) -> Result<u64> {
        self.log.append(self.current_term, command)
    }

    /// Get last log index
    pub fn last_log_index(&self) -> u64 {
        self.log.last_index()
    }

    /// Get last log term
    pub fn last_log_term(&self) -> u64 {
        self.log.last_term()
    }

    /// Get commit index
    pub fn commit_index(&self) -> u64 {
        self.log.commit_index()
    }

    /// Commit up to index
    pub fn commit(&mut self, index: u64) {
        self.log.commit(index);
    }

    /// Get log reference
    pub fn log(&self) -> &RaftLog {
        &self.log
    }

    /// Get mutable log reference
    pub fn log_mut(&mut self) -> &mut RaftLog {
        &mut self.log
    }
}

impl Default for RaftState {
    fn default() -> Self {
        Self::new()
    }
}
