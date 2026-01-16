//! Write-Ahead Journal
//!
//! Implements write-ahead logging for atomic operations and crash recovery.
//!
//! # Journal Replay Mechanism
//!
//! The write-ahead log ensures ACID semantics for all storage operations:
//!
//! ## Write Protocol
//!
//! ```text
//! 1. append()      - Add operation to pending queue (in-memory)
//! 2. commit()      - Serialize entries with checksums, write to disk, fsync
//! 3. [operation]   - Perform the actual file system mutation
//! 4. truncate()    - Clear journal after successful recovery (startup only)
//! ```
//!
//! ## Journal File Format
//!
//! Each journal entry is stored with length-prefixing and checksumming:
//!
//! ```text
//! ┌────────────────┬──────────────────────────────┐
//! │ Length (4B LE) │ Checksummed Entry            │
//! ├────────────────┼──────────────────────────────┤
//! │ u32            │ ChecksummedData<JournalEntry>│
//! └────────────────┴──────────────────────────────┘
//! ```
//!
//! The `ChecksummedData` wrapper contains:
//! - Serialized `JournalEntry` (postcard)
//! - SHA-256 checksum of the entry
//!
//! ## Replay Algorithm
//!
//! During recovery, [`WriteAheadLog::replay`] reads the journal file:
//!
//! 1. Read 4-byte length prefix (little-endian u32)
//! 2. Read `length` bytes of checksummed entry
//! 3. Deserialize `ChecksummedData`
//! 4. Verify SHA-256 checksum
//! 5. Deserialize `JournalEntry`
//! 6. Repeat until end of file
//!
//! ## Corruption Handling
//!
//! The replay process is designed to handle partial writes gracefully:
//!
//! - **Incomplete Length Prefix**: Stop reading (clean truncation point)
//! - **Incomplete Entry Data**: Stop reading (partial write, discard)
//! - **Checksum Mismatch**: Skip entry, continue with next (corrupted data)
//! - **Deserialization Failure**: Skip entry, continue (invalid format)
//!
//! This ensures that even if the system crashes during journal write,
//! recovery can proceed with all valid entries.
//!
//! # Examples
//!
//! ## Basic Journaling
//!
//! ```rust,no_run
//! use hsm_storage::journal::{WriteAheadLog, JournalOp};
//! use hsm_storage::KeyId;
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let journal_path = PathBuf::from("/data/journal/wal.log");
//! let mut journal = WriteAheadLog::new(journal_path)?;
//!
//! // Queue operations (in-memory, not durable yet)
//! journal.append(JournalOp::StoreKey {
//!     key_id: KeyId::new("key1"),
//!     namespace: "prod".to_string(),
//!     data: vec![1, 2, 3],
//! })?;
//!
//! // Commit to disk (fsync, now durable)
//! journal.commit()?;
//!
//! // Now safe to perform the actual file operations
//! // If we crash before completing, replay will re-apply this operation
//! # Ok(())
//! # }
//! ```
//!
//! ## Recovery from Journal
//!
//! ```rust,no_run
//! use hsm_storage::journal::WriteAheadLog;
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // After a crash, replay the journal
//! let journal_path = PathBuf::from("/data/journal/wal.log");
//! let journal = WriteAheadLog::new(journal_path.clone())?;
//!
//! // Get all operations that need to be replayed
//! let entries = journal.replay()?;
//!
//! for entry in entries {
//!     println!("Replaying operation #{}: {:?}", entry.sequence, entry.operation);
//!     // Apply the operation to the file system
//!     // Operations are idempotent, so safe to re-apply
//! }
//!
//! // After successful replay, truncate the journal
//! let mut journal = WriteAheadLog::new(journal_path)?;
//! journal.truncate()?;
//! # Ok(())
//! # }
//! ```

use crate::backend::{StorageError, StorageResult};
use crate::checksum::ChecksummedData;
use crate::KeyId;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Journal operation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JournalOp {
    /// Store a key
    StoreKey {
        key_id: KeyId,
        namespace: String,
        data: Vec<u8>,
    },
    /// Delete a key
    DeleteKey { key_id: KeyId, namespace: String },
    /// Create a namespace
    CreateNamespace { namespace: String },
    /// Delete a namespace
    DeleteNamespace { namespace: String },
}

/// A journal entry with checksum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Sequence number for ordering
    pub sequence: u64,
    /// The operation to perform
    pub operation: JournalOp,
    /// Timestamp when entry was created
    pub timestamp: u64,
}

impl JournalEntry {
    /// Create a new journal entry
    fn new(sequence: u64, operation: JournalOp) -> Self {
        Self {
            sequence,
            operation,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Write-ahead log for atomic operations
pub struct WriteAheadLog {
    /// Path to the journal file
    journal_path: PathBuf,
    /// Current sequence number
    sequence: u64,
    /// Pending entries not yet committed
    pending: Vec<JournalEntry>,
}

impl WriteAheadLog {
    /// Create a new write-ahead log
    ///
    /// # Arguments
    ///
    /// * `journal_path` - Path to store the journal file
    ///
    /// # Errors
    ///
    /// Returns an error if the journal directory cannot be created
    pub fn new(journal_path: PathBuf) -> StorageResult<Self> {
        // Create parent directory if needed
        if let Some(parent) = journal_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let sequence = if journal_path.exists() {
            Self::read_last_sequence(&journal_path)?
        } else {
            0
        };

        Ok(Self {
            journal_path,
            sequence,
            pending: Vec::new(),
        })
    }

    /// Append an operation to the journal
    ///
    /// # Arguments
    ///
    /// * `operation` - The operation to journal
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the journal fails
    pub fn append(&mut self, operation: JournalOp) -> StorageResult<()> {
        self.sequence += 1;
        let entry = JournalEntry::new(self.sequence, operation);
        self.pending.push(entry);
        Ok(())
    }

    /// Commit all pending operations to disk
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Serialization fails
    /// - File write fails
    /// - fsync fails
    pub fn commit(&mut self) -> StorageResult<()> {
        if self.pending.is_empty() {
            return Ok(());
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)?;

        for entry in &self.pending {
            // Serialize entry
            let entry_bytes = postcard::to_allocvec(entry).map_err(|e| {
                StorageError::Serialization(format!("Failed to serialize journal entry: {}", e))
            })?;

            // Create checksummed data
            let checksummed = ChecksummedData::new(entry_bytes);
            let checksummed_bytes = postcard::to_allocvec(&checksummed).map_err(|e| {
                StorageError::Serialization(format!("Failed to serialize checksummed entry: {}", e))
            })?;

            // Write length prefix + data
            let len = checksummed_bytes.len() as u32;
            file.write_all(&len.to_le_bytes())?;
            file.write_all(&checksummed_bytes)?;
        }

        // Ensure data is written to disk
        file.sync_all()?;

        self.pending.clear();
        Ok(())
    }

    /// Replay the journal and return all operations
    ///
    /// This method is resilient to corruption - it will skip incomplete or
    /// corrupted entries and continue processing valid entries. This ensures
    /// that the system can recover even if the journal was partially corrupted.
    ///
    /// # Errors
    ///
    /// Returns an error only if the file cannot be opened or read.
    /// Corrupted entries are logged and skipped.
    pub fn replay(&self) -> StorageResult<Vec<JournalEntry>> {
        if !self.journal_path.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let mut file = File::open(&self.journal_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let mut offset = 0;
        while offset < buffer.len() {
            // Read length prefix
            if offset + 4 > buffer.len() {
                // Incomplete length prefix at end of file - stop here
                break;
            }

            let len = u32::from_le_bytes([
                buffer[offset],
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
            ]) as usize;
            offset += 4;

            // Read checksummed entry
            if offset + len > buffer.len() {
                // Incomplete journal entry at end of file - stop here
                break;
            }

            // Try to deserialize and verify entry, skip if corrupted
            if let Ok(checksummed) =
                postcard::from_bytes::<ChecksummedData>(&buffer[offset..offset + len])
            {
                if let Ok(entry_bytes) = checksummed.into_verified_data() {
                    if let Ok(entry) = postcard::from_bytes::<JournalEntry>(&entry_bytes) {
                        entries.push(entry);
                    }
                    // If entry deserialization fails, skip this entry
                }
                // If checksum verification fails, skip this entry
            }
            // If checksummed data deserialization fails, skip this entry

            offset += len;
        }

        Ok(entries)
    }

    /// Truncate the journal (used after successful recovery)
    ///
    /// # Errors
    ///
    /// Returns an error if file operations fail
    pub fn truncate(&mut self) -> StorageResult<()> {
        if self.journal_path.exists() {
            fs::remove_file(&self.journal_path)?;
        }
        self.sequence = 0;
        self.pending.clear();
        Ok(())
    }

    /// Check if there are pending operations
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Get the number of pending operations
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Read the last sequence number from the journal
    fn read_last_sequence(journal_path: &Path) -> StorageResult<u64> {
        let entries = Self::read_entries(journal_path)?;
        Ok(entries.last().map(|e| e.sequence).unwrap_or(0))
    }

    /// Read all entries from the journal file
    fn read_entries(journal_path: &Path) -> StorageResult<Vec<JournalEntry>> {
        if !journal_path.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let mut file = File::open(journal_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let mut offset = 0;
        while offset < buffer.len() {
            if offset + 4 > buffer.len() {
                break; // Incomplete entry, stop
            }

            let len = u32::from_le_bytes([
                buffer[offset],
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + len > buffer.len() {
                break; // Incomplete entry, stop
            }

            if let Ok(checksummed) =
                postcard::from_bytes::<ChecksummedData>(&buffer[offset..offset + len])
            {
                if let Ok(entry_bytes) = checksummed.into_verified_data() {
                    if let Ok(entry) = postcard::from_bytes::<JournalEntry>(&entry_bytes) {
                        entries.push(entry);
                    }
                }
            }

            offset += len;
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_journal_creation() {
        let temp_dir = TempDir::new().unwrap();
        let journal_path = temp_dir.path().join("journal.log");
        let journal = WriteAheadLog::new(journal_path).unwrap();
        assert_eq!(journal.sequence, 0);
        assert!(!journal.has_pending());
    }

    #[test]
    fn test_append_and_commit() {
        let temp_dir = TempDir::new().unwrap();
        let journal_path = temp_dir.path().join("journal.log");
        let mut journal = WriteAheadLog::new(journal_path).unwrap();

        let op = JournalOp::StoreKey {
            key_id: KeyId::new("test-key"),
            namespace: "test".to_string(),
            data: vec![1, 2, 3],
        };

        journal.append(op).unwrap();
        assert!(journal.has_pending());
        assert_eq!(journal.pending_count(), 1);

        journal.commit().unwrap();
        assert!(!journal.has_pending());
    }

    #[test]
    fn test_replay() {
        let temp_dir = TempDir::new().unwrap();
        let journal_path = temp_dir.path().join("journal.log");

        // Write some operations
        {
            let mut journal = WriteAheadLog::new(journal_path.clone()).unwrap();

            journal
                .append(JournalOp::StoreKey {
                    key_id: KeyId::new("key1"),
                    namespace: "ns1".to_string(),
                    data: vec![1, 2, 3],
                })
                .unwrap();

            journal
                .append(JournalOp::DeleteKey {
                    key_id: KeyId::new("key2"),
                    namespace: "ns1".to_string(),
                })
                .unwrap();

            journal.commit().unwrap();
        }

        // Replay in a new journal instance
        {
            let journal = WriteAheadLog::new(journal_path).unwrap();
            let entries = journal.replay().unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].sequence, 1);
            assert_eq!(entries[1].sequence, 2);
        }
    }

    #[test]
    fn test_truncate() {
        let temp_dir = TempDir::new().unwrap();
        let journal_path = temp_dir.path().join("journal.log");

        let mut journal = WriteAheadLog::new(journal_path.clone()).unwrap();

        journal
            .append(JournalOp::CreateNamespace {
                namespace: "test".to_string(),
            })
            .unwrap();

        journal.commit().unwrap();
        assert!(journal_path.exists());

        journal.truncate().unwrap();
        assert!(!journal_path.exists());
        assert_eq!(journal.sequence, 0);
    }

    #[test]
    fn test_multiple_commits() {
        let temp_dir = TempDir::new().unwrap();
        let journal_path = temp_dir.path().join("journal.log");
        let mut journal = WriteAheadLog::new(journal_path).unwrap();

        // First commit
        journal
            .append(JournalOp::StoreKey {
                key_id: KeyId::new("key1"),
                namespace: "ns1".to_string(),
                data: vec![1],
            })
            .unwrap();
        journal.commit().unwrap();

        // Second commit
        journal
            .append(JournalOp::StoreKey {
                key_id: KeyId::new("key2"),
                namespace: "ns1".to_string(),
                data: vec![2],
            })
            .unwrap();
        journal.commit().unwrap();

        // Replay should get both
        let entries = journal.replay().unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_sequence_numbering() {
        let temp_dir = TempDir::new().unwrap();
        let journal_path = temp_dir.path().join("journal.log");
        let mut journal = WriteAheadLog::new(journal_path.clone()).unwrap();

        for i in 1..=5 {
            journal
                .append(JournalOp::StoreKey {
                    key_id: KeyId::new(format!("key{}", i)),
                    namespace: "ns1".to_string(),
                    data: vec![i as u8],
                })
                .unwrap();
        }

        journal.commit().unwrap();

        let entries = journal.replay().unwrap();
        assert_eq!(entries.len(), 5);
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.sequence, (i + 1) as u64);
        }
    }
}
