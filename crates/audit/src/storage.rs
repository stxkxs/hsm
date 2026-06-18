use crate::checkpoint::{Checkpoint, CheckpointError};
use crate::event::AuditEvent;
use parking_lot::RwLock;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("File rotation failed: {0}")]
    RotationFailed(String),

    #[error("Invalid log file format")]
    InvalidFormat,

    #[error("Checkpoint error: {0}")]
    Checkpoint(#[from] CheckpointError),
}

/// Configuration for log storage
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Base directory for log files
    pub base_dir: PathBuf,

    /// Maximum size of a log file before rotation (bytes)
    pub max_file_size: u64,

    /// Maximum number of rotated log files to keep
    pub max_files: usize,

    /// Whether to sync after each write
    pub sync_writes: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::from("./audit_logs"),
            max_file_size: 100 * 1024 * 1024, // 100 MB
            max_files: 10,
            sync_writes: true,
        }
    }
}

/// Storage backend for audit logs
pub struct AuditStorage {
    config: StorageConfig,
    current_file: Arc<RwLock<Option<BufWriter<File>>>>,
    current_path: Arc<RwLock<PathBuf>>,
    current_size: Arc<RwLock<u64>>,
    /// Test-only fault injection: when set, `write_event` returns an IO error
    /// without writing anything. Used to exercise the durable-write-first
    /// ordering in the loggers.
    #[cfg(test)]
    fail_writes: Arc<std::sync::atomic::AtomicBool>,
}

impl AuditStorage {
    /// Create a new audit storage instance
    pub fn new(config: StorageConfig) -> Result<Self, StorageError> {
        // Create base directory if it doesn't exist
        std::fs::create_dir_all(&config.base_dir)?;

        let current_path = Self::get_current_log_path(&config.base_dir);

        let storage = Self {
            config,
            current_file: Arc::new(RwLock::new(None)),
            current_path: Arc::new(RwLock::new(current_path.clone())),
            current_size: Arc::new(RwLock::new(0)),
            #[cfg(test)]
            fail_writes: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        storage.open_current_file()?;

        Ok(storage)
    }

    /// Get the path for the current log file
    fn get_current_log_path(base_dir: &Path) -> PathBuf {
        base_dir.join("audit.log")
    }

    /// Get the path for a rotated log file
    fn get_rotated_log_path(base_dir: &Path, index: usize) -> PathBuf {
        base_dir.join(format!("audit.log.{}", index))
    }

    /// Open the current log file
    fn open_current_file(&self) -> Result<(), StorageError> {
        let path = self.current_path.read().clone();

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        let metadata = file.metadata()?;
        let size = metadata.len();

        *self.current_size.write() = size;
        *self.current_file.write() = Some(BufWriter::new(file));

        Ok(())
    }

    /// Test-only: enable or disable injected write failures.
    #[cfg(test)]
    pub(crate) fn set_fail_writes(&self, fail: bool) {
        self.fail_writes
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// Write an event to storage
    pub fn write_event(&self, event: &AuditEvent) -> Result<(), StorageError> {
        #[cfg(test)]
        if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected write failure",
            )));
        }

        // Check if rotation is needed
        if *self.current_size.read() >= self.config.max_file_size {
            self.rotate()?;
        }

        let json = serde_json::to_string(event)?;
        let line = format!("{}\n", json);

        let mut file_guard = self.current_file.write();
        let file = file_guard.as_mut().ok_or_else(|| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Log file not open",
            ))
        })?;

        file.write_all(line.as_bytes())?;

        if self.config.sync_writes {
            file.flush()?;
        }

        *self.current_size.write() += line.len() as u64;

        Ok(())
    }

    /// Rotate log files
    fn rotate(&self) -> Result<(), StorageError> {
        // Flush and close current file
        {
            let mut file_guard = self.current_file.write();
            if let Some(file) = file_guard.as_mut() {
                file.flush()?;
            }
            *file_guard = None;
        }

        // Rotate existing files
        for i in (1..self.config.max_files).rev() {
            let old_path = Self::get_rotated_log_path(&self.config.base_dir, i);
            let new_path = Self::get_rotated_log_path(&self.config.base_dir, i + 1);

            if old_path.exists() {
                if i + 1 > self.config.max_files {
                    // Delete oldest file
                    std::fs::remove_file(&old_path)?;
                } else {
                    std::fs::rename(&old_path, &new_path)?;
                }
            }
        }

        // Rename current file to .1
        let current_path = self.current_path.read().clone();
        let rotated_path = Self::get_rotated_log_path(&self.config.base_dir, 1);

        if current_path.exists() {
            std::fs::rename(&current_path, &rotated_path)?;
        }

        // Open new current file
        *self.current_size.write() = 0;
        self.open_current_file()?;

        Ok(())
    }

    /// Read all events from a log file
    pub fn read_events(&self, path: &Path) -> Result<Vec<AuditEvent>, StorageError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let event: AuditEvent = serde_json::from_str(&line)?;
            events.push(event);
        }

        Ok(events)
    }

    /// Read all events from the current log file
    pub fn read_current_events(&self) -> Result<Vec<AuditEvent>, StorageError> {
        let path = self.current_path.read().clone();
        self.read_events(&path)
    }

    /// Read all events from all log files (current + rotated)
    pub fn read_all_events(&self) -> Result<Vec<AuditEvent>, StorageError> {
        let mut all_events = Vec::new();

        // Read rotated files in reverse order (oldest first)
        for i in (1..=self.config.max_files).rev() {
            let path = Self::get_rotated_log_path(&self.config.base_dir, i);
            if path.exists() {
                let events = self.read_events(&path)?;
                all_events.extend(events);
            }
        }

        // Read current file
        let current_events = self.read_current_events()?;
        all_events.extend(current_events);

        Ok(all_events)
    }

    /// Get the current log file path
    pub fn current_log_path(&self) -> PathBuf {
        self.current_path.read().clone()
    }

    /// Get the current log file size
    pub fn current_size(&self) -> u64 {
        *self.current_size.read()
    }

    /// Flush any buffered writes
    pub fn flush(&self) -> Result<(), StorageError> {
        let mut file_guard = self.current_file.write();
        if let Some(file) = file_guard.as_mut() {
            file.flush()?;
        }
        Ok(())
    }

    /// Force a log rotation
    pub fn force_rotation(&self) -> Result<(), StorageError> {
        self.rotate()
    }

    /// Path to the checkpoint file.
    fn checkpoint_path(&self) -> PathBuf {
        self.config.base_dir.join("checkpoint.json")
    }

    /// Persist a checkpoint atomically (write-temp-then-rename).
    ///
    /// The checkpoint commits to the latest sequence + Merkle root so that a
    /// later restart can detect tail truncation of the log. The write is
    /// atomic: a crash mid-write leaves the previous checkpoint intact rather
    /// than a half-written one.
    pub fn write_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), StorageError> {
        let path = self.checkpoint_path();
        let tmp = path.with_extension("json.tmp");

        let json = checkpoint.to_json()?;
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(json.as_bytes())?;
            f.write_all(b"\n")?;
            f.flush()?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Read the latest persisted checkpoint, if any.
    ///
    /// Returns `Ok(None)` when no checkpoint exists yet (fresh log). A present
    /// but unparseable checkpoint is surfaced as an error so the caller can
    /// fail closed rather than silently ignoring it.
    pub fn read_checkpoint(&self) -> Result<Option<Checkpoint>, StorageError> {
        let path = self.checkpoint_path();
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(&path)?;
        let line = contents.trim();
        if line.is_empty() {
            return Ok(None);
        }
        let checkpoint = Checkpoint::from_json(line)?;
        Ok(Some(checkpoint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventType, OperationResult};
    use chrono::Utc;
    use tempfile::TempDir;

    fn create_test_event(seq: u64) -> AuditEvent {
        AuditEvent::builder()
            .sequence(seq)
            .event_type(EventType::Sign)
            .operation("test_op")
            .namespace("test")
            .client_id("client_1")
            .result(OperationResult::Success)
            .timestamp(Utc::now())
            .build()
            .unwrap()
    }

    #[test]
    fn test_storage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let storage = AuditStorage::new(config).unwrap();
        assert_eq!(storage.current_size(), 0);
    }

    #[test]
    fn test_write_event() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let storage = AuditStorage::new(config).unwrap();
        let event = create_test_event(1);

        storage.write_event(&event).unwrap();
        assert!(storage.current_size() > 0);
    }

    #[test]
    fn test_read_events() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let storage = AuditStorage::new(config).unwrap();

        // Write some events
        for i in 1..=5 {
            let event = create_test_event(i);
            storage.write_event(&event).unwrap();
        }

        storage.flush().unwrap();

        // Read them back
        let events = storage.read_current_events().unwrap();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[4].sequence, 5);
    }

    #[test]
    fn test_log_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            max_file_size: 1024, // Small size to trigger rotation
            max_files: 3,
            sync_writes: true,
        };

        let storage = AuditStorage::new(config.clone()).unwrap();

        // Write enough events to trigger rotation
        for i in 1..=100 {
            let event = create_test_event(i);
            storage.write_event(&event).unwrap();
        }

        // Check that rotated files exist
        let rotated_path = AuditStorage::get_rotated_log_path(&config.base_dir, 1);
        assert!(rotated_path.exists());
    }

    #[test]
    fn test_read_all_events() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            max_file_size: 10000, // Larger size to hold all events
            max_files: 10,
            sync_writes: true,
        };

        let storage = AuditStorage::new(config).unwrap();

        // Write events
        for i in 1..=50 {
            let event = create_test_event(i);
            storage.write_event(&event).unwrap();
        }

        storage.flush().unwrap();

        // Read all events
        let all_events = storage.read_all_events().unwrap();
        assert_eq!(all_events.len(), 50);

        // Check sequence order
        for (i, event) in all_events.iter().enumerate() {
            assert_eq!(event.sequence, (i + 1) as u64);
        }
    }

    #[test]
    fn test_force_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let storage = AuditStorage::new(config.clone()).unwrap();

        // Write some events
        for i in 1..=5 {
            let event = create_test_event(i);
            storage.write_event(&event).unwrap();
        }

        let size_before = storage.current_size();
        assert!(size_before > 0);

        // Force rotation
        storage.force_rotation().unwrap();

        let size_after = storage.current_size();
        assert_eq!(size_after, 0);

        // Check rotated file exists
        let rotated_path = AuditStorage::get_rotated_log_path(&config.base_dir, 1);
        assert!(rotated_path.exists());
    }

    #[test]
    fn test_max_files_limit() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            max_file_size: 100,
            max_files: 3,
            sync_writes: true,
        };

        let storage = AuditStorage::new(config.clone()).unwrap();

        // Write enough to create multiple rotations
        for i in 1..=200 {
            let event = create_test_event(i);
            storage.write_event(&event).unwrap();
        }

        // Check that we don't exceed max_files
        for i in 1..=config.max_files {
            let path = AuditStorage::get_rotated_log_path(&config.base_dir, i);
            assert!(path.exists() || i > 1); // First might exist
        }

        // Check that older files are deleted
        let old_path = AuditStorage::get_rotated_log_path(&config.base_dir, config.max_files + 1);
        assert!(!old_path.exists());
    }
}
