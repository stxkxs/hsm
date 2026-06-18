//! Enhanced storage with compression, encryption, and durability guarantees

use crate::event::AuditEvent;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use parking_lot::RwLock;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnhancedStorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Postcard serialization error: {0}")]
    Postcard(#[from] postcard::Error),

    #[error("Compression error: {0}")]
    Compression(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("File rotation failed: {0}")]
    RotationFailed(String),

    #[error("Invalid log file format")]
    InvalidFormat,
}

/// Configuration for enhanced log storage
#[derive(Debug, Clone)]
pub struct EnhancedStorageConfig {
    /// Base directory for log files
    pub base_dir: PathBuf,

    /// Maximum size of a log file before rotation (bytes)
    pub max_file_size: u64,

    /// Maximum number of rotated log files to keep
    pub max_files: usize,

    /// Whether to fsync after each batch write (durability)
    pub durable_writes: bool,

    /// Enable compression with zstd
    pub enable_compression: bool,

    /// Compression level (1-21, higher = better compression, slower)
    pub compression_level: i32,

    /// Enable encryption at rest
    pub enable_encryption: bool,

    /// Encryption key (32 bytes for AES-256)
    pub encryption_key: Option<Vec<u8>>,
}

impl Default for EnhancedStorageConfig {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::from("./audit_logs"),
            max_file_size: 100 * 1024 * 1024, // 100 MB
            max_files: 10,
            durable_writes: true,
            enable_compression: true,
            compression_level: 3,
            enable_encryption: false,
            encryption_key: None,
        }
    }
}

/// Enhanced storage backend with compression, encryption, and durability
pub struct EnhancedAuditStorage {
    config: EnhancedStorageConfig,
    current_file: Arc<RwLock<Option<BufWriter<File>>>>,
    current_path: Arc<RwLock<PathBuf>>,
    current_size: Arc<RwLock<u64>>,
    cipher: Option<Aes256Gcm>,
}

impl EnhancedAuditStorage {
    /// Create a new enhanced audit storage instance
    pub fn new(config: EnhancedStorageConfig) -> Result<Self, EnhancedStorageError> {
        // Create base directory if it doesn't exist
        std::fs::create_dir_all(&config.base_dir)?;

        let current_path = Self::get_current_log_path(&config.base_dir);

        // Initialize cipher if encryption is enabled
        let cipher = if config.enable_encryption {
            let key_bytes = config.encryption_key.as_ref().ok_or_else(|| {
                EnhancedStorageError::Encryption(
                    "Encryption enabled but no key provided".to_string(),
                )
            })?;

            if key_bytes.len() != 32 {
                return Err(EnhancedStorageError::Encryption(
                    "Encryption key must be 32 bytes".to_string(),
                ));
            }

            let key = Key::<Aes256Gcm>::from_slice(key_bytes);
            Some(Aes256Gcm::new(key))
        } else {
            None
        };

        let storage = Self {
            config,
            current_file: Arc::new(RwLock::new(None)),
            current_path: Arc::new(RwLock::new(current_path.clone())),
            current_size: Arc::new(RwLock::new(0)),
            cipher,
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
    fn open_current_file(&self) -> Result<(), EnhancedStorageError> {
        let path = self.current_path.read().clone();

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        let metadata = file.metadata()?;
        let size = metadata.len();

        *self.current_size.write() = size;
        *self.current_file.write() = Some(BufWriter::new(file));

        Ok(())
    }

    /// Serialize and optionally compress/encrypt an event
    fn serialize_event(&self, event: &AuditEvent) -> Result<Vec<u8>, EnhancedStorageError> {
        // Serialize to postcard for efficiency
        let mut data = postcard::to_allocvec(event)?;

        // Compress if enabled
        if self.config.enable_compression {
            data = zstd::encode_all(&data[..], self.config.compression_level)
                .map_err(|e| EnhancedStorageError::Compression(e.to_string()))?;
        }

        // Encrypt if enabled
        if let Some(cipher) = &self.cipher {
            // Use sequence number as nonce (guaranteed unique)
            let nonce_bytes = self.create_nonce(event.sequence);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = cipher
                .encrypt(nonce, data.as_ref())
                .map_err(|e| EnhancedStorageError::Encryption(e.to_string()))?;

            // Prepend nonce to ciphertext
            let mut encrypted_data = nonce_bytes.to_vec();
            encrypted_data.extend_from_slice(&ciphertext);
            data = encrypted_data;
        }

        Ok(data)
    }

    /// Deserialize and optionally decrypt/decompress an event
    fn deserialize_event(&self, data: &[u8]) -> Result<AuditEvent, EnhancedStorageError> {
        let mut data = data.to_vec();

        // Decrypt if enabled
        if let Some(cipher) = &self.cipher {
            if data.len() < 12 {
                return Err(EnhancedStorageError::Decryption(
                    "Data too short for encrypted event".to_string(),
                ));
            }

            // Extract nonce and ciphertext
            let nonce = Nonce::from_slice(&data[0..12]);
            let ciphertext = &data[12..];

            data = cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| EnhancedStorageError::Decryption(e.to_string()))?;
        }

        // Decompress if enabled
        if self.config.enable_compression {
            data = zstd::decode_all(&data[..])
                .map_err(|e| EnhancedStorageError::Compression(e.to_string()))?;
        }

        // Deserialize from postcard
        let event = postcard::from_bytes(&data)?;

        Ok(event)
    }

    /// Create a unique nonce from sequence number
    fn create_nonce(&self, sequence: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&sequence.to_le_bytes());
        // Remaining 4 bytes stay as 0
        nonce
    }

    /// Write an event to storage
    pub fn write_event(&self, event: &AuditEvent) -> Result<(), EnhancedStorageError> {
        // Check if rotation is needed
        if *self.current_size.read() >= self.config.max_file_size {
            self.rotate()?;
        }

        let data = self.serialize_event(event)?;

        // Write length prefix + data
        let len = data.len() as u32;
        let len_bytes = len.to_le_bytes();

        let mut file_guard = self.current_file.write();
        let file = file_guard.as_mut().ok_or_else(|| {
            EnhancedStorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Log file not open",
            ))
        })?;

        file.write_all(&len_bytes)?;
        file.write_all(&data)?;

        let written = 4 + data.len() as u64;
        *self.current_size.write() += written;

        Ok(())
    }

    /// Write a batch of events with durability guarantee
    pub fn write_batch_durable(&self, events: &[AuditEvent]) -> Result<(), EnhancedStorageError> {
        for event in events {
            self.write_event(event)?;
        }

        if self.config.durable_writes {
            self.sync_all()?;
        }

        Ok(())
    }

    /// Sync all writes to disk (fsync)
    pub fn sync_all(&self) -> Result<(), EnhancedStorageError> {
        let mut file_guard = self.current_file.write();
        if let Some(file) = file_guard.as_mut() {
            file.flush()?;
            file.get_mut().sync_all()?;
        }
        Ok(())
    }

    /// Rotate log files
    fn rotate(&self) -> Result<(), EnhancedStorageError> {
        // Flush and close current file
        {
            let mut file_guard = self.current_file.write();
            if let Some(file) = file_guard.as_mut() {
                file.flush()?;
                if self.config.durable_writes {
                    file.get_mut().sync_all()?;
                }
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
    pub fn read_events(&self, path: &Path) -> Result<Vec<AuditEvent>, EnhancedStorageError> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut events = Vec::new();

        loop {
            // Read length prefix
            let mut len_bytes = [0u8; 4];
            match reader.read_exact(&mut len_bytes) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }

            let len = u32::from_le_bytes(len_bytes) as usize;

            // Read data
            let mut data = vec![0u8; len];
            reader.read_exact(&mut data)?;

            let event = self.deserialize_event(&data)?;
            events.push(event);
        }

        Ok(events)
    }

    /// Read all events from the current log file
    pub fn read_current_events(&self) -> Result<Vec<AuditEvent>, EnhancedStorageError> {
        let path = self.current_path.read().clone();
        if !path.exists() {
            return Ok(Vec::new());
        }
        self.read_events(&path)
    }

    /// Read all events from all log files (current + rotated)
    pub fn read_all_events(&self) -> Result<Vec<AuditEvent>, EnhancedStorageError> {
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
    pub fn flush(&self) -> Result<(), EnhancedStorageError> {
        let mut file_guard = self.current_file.write();
        if let Some(file) = file_guard.as_mut() {
            file.flush()?;
            // Sync to disk to ensure data is actually written
            file.get_mut().sync_all()?;
        }
        Ok(())
    }

    /// Force a log rotation
    pub fn force_rotation(&self) -> Result<(), EnhancedStorageError> {
        self.rotate()
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
    fn test_enhanced_storage_basic() {
        let temp_dir = TempDir::new().unwrap();
        let config = EnhancedStorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            enable_compression: false,
            enable_encryption: false,
            ..Default::default()
        };

        let storage = EnhancedAuditStorage::new(config).unwrap();

        let event = create_test_event(1);
        storage.write_event(&event).unwrap();
        storage.flush().unwrap();

        let events = storage.read_current_events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sequence, 1);
    }

    #[test]
    fn test_compression() {
        let temp_dir = TempDir::new().unwrap();
        let config = EnhancedStorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            enable_compression: true,
            compression_level: 3,
            enable_encryption: false,
            ..Default::default()
        };

        let storage = EnhancedAuditStorage::new(config).unwrap();

        for i in 1..=10 {
            let event = create_test_event(i);
            storage.write_event(&event).unwrap();
        }
        storage.flush().unwrap();

        let events = storage.read_current_events().unwrap();
        assert_eq!(events.len(), 10);

        // Verify file size is reasonable (compression should help)
        let size = storage.current_size();
        assert!(size > 0);
        println!("Compressed size for 10 events: {} bytes", size);
    }

    #[test]
    fn test_encryption() {
        let temp_dir = TempDir::new().unwrap();
        let key = vec![42u8; 32]; // Test key

        let config = EnhancedStorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            enable_compression: false,
            enable_encryption: true,
            encryption_key: Some(key.clone()),
            ..Default::default()
        };

        let storage = EnhancedAuditStorage::new(config).unwrap();

        for i in 1..=5 {
            let event = create_test_event(i);
            storage.write_event(&event).unwrap();
        }
        storage.flush().unwrap();

        let events = storage.read_current_events().unwrap();
        assert_eq!(events.len(), 5);

        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.sequence, (i + 1) as u64);
        }
    }

    #[test]
    fn test_compression_and_encryption() {
        let temp_dir = TempDir::new().unwrap();
        let key = vec![123u8; 32];

        let config = EnhancedStorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            enable_compression: true,
            compression_level: 5,
            enable_encryption: true,
            encryption_key: Some(key),
            ..Default::default()
        };

        let storage = EnhancedAuditStorage::new(config).unwrap();

        for i in 1..=20 {
            let event = create_test_event(i);
            storage.write_event(&event).unwrap();
        }
        storage.flush().unwrap();

        let events = storage.read_current_events().unwrap();
        assert_eq!(events.len(), 20);
    }

    #[test]
    fn test_durable_writes() {
        let temp_dir = TempDir::new().unwrap();
        let config = EnhancedStorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            durable_writes: true,
            ..Default::default()
        };

        let storage = EnhancedAuditStorage::new(config).unwrap();

        let events: Vec<_> = (1..=5).map(create_test_event).collect();
        storage.write_batch_durable(&events).unwrap();

        let read_events = storage.read_current_events().unwrap();
        assert_eq!(read_events.len(), 5);
    }

    #[test]
    fn test_rotation_with_enhancements() {
        let temp_dir = TempDir::new().unwrap();
        let config = EnhancedStorageConfig {
            base_dir: temp_dir.path().to_path_buf(),
            max_file_size: 1024,
            enable_compression: true,
            ..Default::default()
        };

        let storage = EnhancedAuditStorage::new(config.clone()).unwrap();

        // Write enough events to trigger rotation
        for i in 1..=100 {
            let event = create_test_event(i);
            storage.write_event(&event).unwrap();
        }

        storage.flush().unwrap();

        // Check that rotated file exists
        let rotated_path = EnhancedAuditStorage::get_rotated_log_path(&config.base_dir, 1);
        assert!(rotated_path.exists());

        // Read all events
        // Note: with max_files=10 (default), older events are deleted during rotation
        // So we won't have all 100 events, only the most recent ones that fit in max_files
        let all_events = storage.read_all_events().unwrap();
        assert!(!all_events.is_empty());
        assert!(all_events.len() <= 100);

        // Verify the events we have are sequential and valid
        for (i, event) in all_events.iter().enumerate() {
            if i > 0 {
                assert_eq!(event.sequence, all_events[i - 1].sequence + 1);
            }
        }
    }
}
