//! Raft log implementation

use crate::error::{ClusterError, Result};
use crate::node::Command;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Entry index
    pub index: u64,

    /// Term when entry was received by leader
    pub term: u64,

    /// Command to apply
    pub command: Command,

    /// Timestamp when entry was created
    pub timestamp: i64,
}

/// Raft log
pub struct RaftLog {
    /// Log entries (in-memory)
    entries: VecDeque<LogEntry>,

    /// First index in the log (after compaction)
    first_index: u64,

    /// Last applied index
    last_applied: u64,

    /// Commit index
    commit_index: u64,

    /// Persistent storage (optional)
    storage: Option<sled::Db>,
}

impl RaftLog {
    /// Create a new in-memory log
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            first_index: 1,
            last_applied: 0,
            commit_index: 0,
            storage: None,
        }
    }

    /// Create a log with persistent storage
    pub fn with_storage(path: &str) -> Result<Self> {
        let storage = sled::open(path)?;

        let mut log = Self {
            entries: VecDeque::new(),
            first_index: 1,
            last_applied: 0,
            commit_index: 0,
            storage: Some(storage),
        };

        // Load existing entries
        log.load_from_storage()?;

        Ok(log)
    }

    /// Get the last index in the log
    pub fn last_index(&self) -> u64 {
        if self.entries.is_empty() {
            self.first_index.saturating_sub(1)
        } else {
            self.first_index + self.entries.len() as u64 - 1
        }
    }

    /// Get the last term in the log
    pub fn last_term(&self) -> u64 {
        self.entries.back().map(|e| e.term).unwrap_or(0)
    }

    /// Get an entry by index
    pub fn get(&self, index: u64) -> Option<&LogEntry> {
        if index < self.first_index {
            return None;
        }
        let offset = (index - self.first_index) as usize;
        self.entries.get(offset)
    }

    /// Append a new entry
    pub fn append(&mut self, term: u64, command: Command) -> Result<u64> {
        let index = self.last_index() + 1;
        let entry = LogEntry {
            index,
            term,
            command,
            timestamp: chrono::Utc::now().timestamp(),
        };

        // Persist if storage is available
        if let Some(storage) = &self.storage {
            let key = format!("log:{}", index);
            let value = serde_json::to_vec(&entry)?;
            storage.insert(key.as_bytes(), value)?;
            storage.flush()?;
        }

        self.entries.push_back(entry);
        Ok(index)
    }

    /// Append multiple entries (for replication)
    pub fn append_entries(
        &mut self,
        prev_index: u64,
        prev_term: u64,
        entries: Vec<LogEntry>,
    ) -> Result<bool> {
        // Check if we have the previous entry
        if prev_index > 0 {
            if let Some(prev_entry) = self.get(prev_index) {
                if prev_entry.term != prev_term {
                    // Conflict: delete this and all following entries
                    self.truncate_after(prev_index)?;
                    return Ok(false);
                }
            } else if prev_index >= self.first_index {
                // Missing entry
                return Ok(false);
            }
        }

        // Append new entries
        for entry in entries {
            // Skip if already have this entry
            if entry.index <= self.last_index() {
                if let Some(existing) = self.get(entry.index) {
                    if existing.term == entry.term {
                        continue;
                    }
                    // Conflict: truncate
                    self.truncate_after(entry.index)?;
                }
            }

            // Persist if storage is available
            if let Some(storage) = &self.storage {
                let key = format!("log:{}", entry.index);
                let value = serde_json::to_vec(&entry)?;
                storage.insert(key.as_bytes(), value)?;
            }

            self.entries.push_back(entry);
        }

        if let Some(storage) = &self.storage {
            storage.flush()?;
        }

        Ok(true)
    }

    /// Truncate log after given index
    fn truncate_after(&mut self, index: u64) -> Result<()> {
        while self.last_index() > index {
            if let Some(entry) = self.entries.pop_back() {
                if let Some(storage) = &self.storage {
                    let key = format!("log:{}", entry.index);
                    storage.remove(key.as_bytes())?;
                }
            }
        }
        Ok(())
    }

    /// Update commit index
    pub fn commit(&mut self, index: u64) {
        if index > self.commit_index {
            self.commit_index = index;
        }
    }

    /// Get commit index
    pub fn commit_index(&self) -> u64 {
        self.commit_index
    }

    /// Get last applied index
    pub fn last_applied(&self) -> u64 {
        self.last_applied
    }

    /// Mark index as applied
    pub fn mark_applied(&mut self, index: u64) {
        if index > self.last_applied {
            self.last_applied = index;
        }
    }

    /// Get entries to apply (between last_applied and commit_index)
    pub fn entries_to_apply(&self) -> Vec<&LogEntry> {
        let mut entries = Vec::new();
        for index in (self.last_applied + 1)..=self.commit_index {
            if let Some(entry) = self.get(index) {
                entries.push(entry);
            }
        }
        entries
    }

    /// Get entries from given index (for replication)
    pub fn entries_from(&self, start_index: u64) -> Vec<LogEntry> {
        let mut entries = Vec::new();
        for index in start_index..=self.last_index() {
            if let Some(entry) = self.get(index) {
                entries.push(entry.clone());
            }
        }
        entries
    }

    /// Compact log up to given index (create snapshot)
    pub fn compact(&mut self, index: u64) -> Result<()> {
        if index < self.first_index {
            return Ok(());
        }

        // Remove entries before the given index
        while self.first_index <= index {
            if let Some(entry) = self.entries.pop_front() {
                if let Some(storage) = &self.storage {
                    let key = format!("log:{}", entry.index);
                    storage.remove(key.as_bytes())?;
                }
            }
            self.first_index += 1;
        }

        if let Some(storage) = &self.storage {
            storage.flush()?;
        }

        Ok(())
    }

    /// Load entries from storage
    fn load_from_storage(&mut self) -> Result<()> {
        if let Some(storage) = &self.storage {
            // Find the range of entries
            let prefix = b"log:";
            for item in storage.scan_prefix(prefix) {
                let (key, value) = item?;
                let entry: LogEntry = serde_json::from_slice(&value)?;
                self.entries.push_back(entry);
            }

            // Sort by index
            let mut vec: Vec<_> = self.entries.drain(..).collect();
            vec.sort_by_key(|e| e.index);
            self.entries = vec.into();

            // Update first_index
            if let Some(first) = self.entries.front() {
                self.first_index = first.index;
            }
        }

        Ok(())
    }

    /// Get log size
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if log is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for RaftLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_append() {
        let mut log = RaftLog::new();
        let cmd = Command::DeleteKey {
            key_id: "test".to_string(),
        };

        let index = log.append(1, cmd).unwrap();
        assert_eq!(index, 1);
        assert_eq!(log.last_index(), 1);
        assert_eq!(log.last_term(), 1);
    }

    #[test]
    fn test_log_get() {
        let mut log = RaftLog::new();
        let cmd = Command::DeleteKey {
            key_id: "test".to_string(),
        };

        log.append(1, cmd.clone()).unwrap();

        let entry = log.get(1).unwrap();
        assert_eq!(entry.index, 1);
        assert_eq!(entry.term, 1);
    }

    #[test]
    fn test_log_commit() {
        let mut log = RaftLog::new();
        let cmd = Command::DeleteKey {
            key_id: "test".to_string(),
        };

        log.append(1, cmd.clone()).unwrap();
        log.append(1, cmd.clone()).unwrap();

        log.commit(2);
        assert_eq!(log.commit_index(), 2);

        let to_apply = log.entries_to_apply();
        assert_eq!(to_apply.len(), 2);
    }
}
