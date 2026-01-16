use crate::event::{AuditEvent, AuditEventBuilder, EventType};
use crate::hash_chain::{HashChain, HashChainError};
use crate::merkle_tree::MerkleTree;
use crate::storage::{AuditStorage, StorageConfig, StorageError};
use chrono::Utc;
use parking_lot::{Mutex, RwLock};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Hash chain error: {0}")]
    HashChain(#[from] HashChainError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Event build error: {0}")]
    EventBuild(&'static str),

    #[error("Logger is disabled")]
    Disabled,
}

/// Configuration for the audit logger
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Storage configuration
    pub storage: StorageConfig,

    /// Whether the logger is enabled
    pub enabled: bool,

    /// Whether to rebuild Merkle tree on startup
    pub rebuild_merkle_on_start: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            storage: StorageConfig::default(),
            enabled: true,
            rebuild_merkle_on_start: true,
        }
    }
}

/// Main audit logger combining hash chain, Merkle tree, and storage
pub struct AuditLogger {
    config: AuditConfig,
    hash_chain: Arc<HashChain>,
    merkle_tree: Arc<RwLock<MerkleTree>>,
    storage: Arc<AuditStorage>,
    log_mutex: Arc<Mutex<()>>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(config: AuditConfig) -> Result<Self, AuditError> {
        let storage = Arc::new(AuditStorage::new(config.storage.clone())?);
        let hash_chain = Arc::new(HashChain::new());
        let merkle_tree = Arc::new(RwLock::new(MerkleTree::new()));

        let logger = Self {
            config,
            hash_chain,
            merkle_tree,
            storage,
            log_mutex: Arc::new(Mutex::new(())),
        };

        // Rebuild state from existing logs if configured
        if logger.config.rebuild_merkle_on_start {
            logger.rebuild_from_storage()?;
        }

        Ok(logger)
    }

    /// Rebuild hash chain and Merkle tree from storage
    fn rebuild_from_storage(&self) -> Result<(), AuditError> {
        let events = self.storage.read_current_events()?;

        for event in events {
            // Add to hash chain (will verify sequence)
            self.hash_chain.append(event.clone())?;

            // Add to Merkle tree
            self.merkle_tree.write().update(&event.current_hash);
        }

        Ok(())
    }

    /// Log an audit event
    pub fn log(&self, builder: AuditEventBuilder) -> Result<u64, AuditError> {
        if !self.config.enabled {
            return Err(AuditError::Disabled);
        }

        // Lock to ensure atomic sequence generation and event creation
        let _guard = self.log_mutex.lock();

        // Get next sequence number
        let sequence = self.hash_chain.current_sequence() + 1;

        // Build event with sequence and prev_hash
        let event = builder
            .sequence(sequence)
            .prev_hash(self.hash_chain.last_hash())
            .timestamp(Utc::now())
            .build()
            .map_err(AuditError::EventBuild)?;

        // Append to hash chain
        let hash = self.hash_chain.append(event.clone())?;

        // Update Merkle tree
        self.merkle_tree.write().update(&hash);

        // Persist to storage
        self.storage.write_event(&event)?;

        Ok(sequence)
    }

    /// Log a successful operation
    pub fn log_success(
        &self,
        event_type: EventType,
        operation: impl Into<String>,
        namespace: impl Into<String>,
        client_id: impl Into<String>,
        key_id: Option<String>,
    ) -> Result<u64, AuditError> {
        let mut builder = AuditEvent::builder()
            .event_type(event_type)
            .operation(operation)
            .namespace(namespace)
            .client_id(client_id)
            .success();

        if let Some(kid) = key_id {
            builder = builder.key_id(kid);
        }

        self.log(builder)
    }

    /// Log a failed operation
    pub fn log_failure(
        &self,
        event_type: EventType,
        operation: impl Into<String>,
        namespace: impl Into<String>,
        client_id: impl Into<String>,
        key_id: Option<String>,
        reason: impl Into<String>,
    ) -> Result<u64, AuditError> {
        let mut builder = AuditEvent::builder()
            .event_type(event_type)
            .operation(operation)
            .namespace(namespace)
            .client_id(client_id)
            .failure(reason);

        if let Some(kid) = key_id {
            builder = builder.key_id(kid);
        }

        self.log(builder)
    }

    /// Verify the integrity of the audit chain
    pub fn verify_integrity(&self) -> Result<(), AuditError> {
        self.hash_chain.verify_all()?;
        Ok(())
    }

    /// Verify a range of events
    pub fn verify_range(&self, from: u64, to: u64) -> Result<(), AuditError> {
        self.hash_chain.verify(from, to)?;
        Ok(())
    }

    /// Get the Merkle root hash
    pub fn get_merkle_root(&self) -> Result<String, AuditError> {
        self.merkle_tree
            .read()
            .get_root()
            .map_err(|_| AuditError::EventBuild("Merkle tree is empty"))
    }

    /// Get an event by sequence number
    pub fn get_event(&self, sequence: u64) -> Result<AuditEvent, AuditError> {
        Ok(self.hash_chain.get_event(sequence)?)
    }

    /// Get events in a range
    pub fn get_events_range(&self, from: u64, to: u64) -> Result<Vec<AuditEvent>, AuditError> {
        Ok(self.hash_chain.get_events_range(from, to)?)
    }

    /// Get the current sequence number
    pub fn current_sequence(&self) -> u64 {
        self.hash_chain.current_sequence()
    }

    /// Get the number of events logged
    pub fn event_count(&self) -> usize {
        self.hash_chain.len()
    }

    /// Flush buffered writes to storage
    pub fn flush(&self) -> Result<(), AuditError> {
        self.storage.flush()?;
        Ok(())
    }

    /// Force a log rotation
    pub fn rotate(&self) -> Result<(), AuditError> {
        self.storage.force_rotation()?;
        Ok(())
    }

    /// Get all events from storage (including rotated files)
    pub fn get_all_events_from_storage(&self) -> Result<Vec<AuditEvent>, AuditError> {
        Ok(self.storage.read_all_events()?)
    }

    /// Get reference to hash chain for advanced operations
    pub fn hash_chain(&self) -> &Arc<HashChain> {
        &self.hash_chain
    }

    /// Get reference to Merkle tree for advanced operations
    pub fn merkle_tree(&self) -> &Arc<RwLock<MerkleTree>> {
        &self.merkle_tree
    }

    /// Get reference to storage for advanced operations
    pub fn storage(&self) -> &Arc<AuditStorage> {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperationResult;
    use tempfile::TempDir;

    fn create_test_config() -> AuditConfig {
        let temp_dir = TempDir::new().unwrap();
        AuditConfig {
            storage: StorageConfig {
                base_dir: temp_dir.path().to_path_buf(),
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: false,
        }
    }

    #[test]
    fn test_logger_creation() {
        let config = create_test_config();
        let logger = AuditLogger::new(config).unwrap();
        assert_eq!(logger.current_sequence(), 0);
        assert_eq!(logger.event_count(), 0);
    }

    #[test]
    fn test_log_success() {
        let config = create_test_config();
        let logger = AuditLogger::new(config).unwrap();

        let seq = logger
            .log_success(
                EventType::KeyGeneration,
                "generate_key",
                "default",
                "client_1",
                Some("key_123".to_string()),
            )
            .unwrap();

        assert_eq!(seq, 1);
        assert_eq!(logger.current_sequence(), 1);
        assert_eq!(logger.event_count(), 1);
    }

    #[test]
    fn test_log_failure() {
        let config = create_test_config();
        let logger = AuditLogger::new(config).unwrap();

        let seq = logger
            .log_failure(
                EventType::Sign,
                "sign_data",
                "default",
                "client_1",
                None,
                "Invalid key",
            )
            .unwrap();

        assert_eq!(seq, 1);

        let event = logger.get_event(1).unwrap();
        assert_eq!(
            event.result,
            OperationResult::Failure {
                reason: "Invalid key".to_string()
            }
        );
    }

    #[test]
    fn test_log_multiple_events() {
        let config = create_test_config();
        let logger = AuditLogger::new(config).unwrap();

        for i in 1..=10 {
            logger
                .log_success(
                    EventType::Sign,
                    format!("operation_{}", i),
                    "default",
                    "client_1",
                    None,
                )
                .unwrap();
        }

        assert_eq!(logger.current_sequence(), 10);
        assert_eq!(logger.event_count(), 10);
    }

    #[test]
    fn test_verify_integrity() {
        let config = create_test_config();
        let logger = AuditLogger::new(config).unwrap();

        for i in 1..=5 {
            logger
                .log_success(
                    EventType::Encrypt,
                    format!("op_{}", i),
                    "default",
                    "client_1",
                    None,
                )
                .unwrap();
        }

        assert!(logger.verify_integrity().is_ok());
    }

    #[test]
    fn test_verify_range() {
        let config = create_test_config();
        let logger = AuditLogger::new(config).unwrap();

        for i in 1..=10 {
            logger
                .log_success(
                    EventType::Sign,
                    format!("op_{}", i),
                    "default",
                    "client_1",
                    None,
                )
                .unwrap();
        }

        assert!(logger.verify_range(1, 5).is_ok());
        assert!(logger.verify_range(5, 10).is_ok());
        assert!(logger.verify_range(1, 10).is_ok());
    }

    #[test]
    fn test_get_event() {
        let config = create_test_config();
        let logger = AuditLogger::new(config).unwrap();

        logger
            .log_success(
                EventType::KeyGeneration,
                "test_op",
                "default",
                "client_1",
                None,
            )
            .unwrap();

        let event = logger.get_event(1).unwrap();
        assert_eq!(event.sequence, 1);
        assert_eq!(event.operation, "test_op");
    }

    #[test]
    fn test_get_events_range() {
        let config = create_test_config();
        let logger = AuditLogger::new(config).unwrap();

        for i in 1..=10 {
            logger
                .log_success(
                    EventType::Sign,
                    format!("op_{}", i),
                    "default",
                    "client_1",
                    None,
                )
                .unwrap();
        }

        let events = logger.get_events_range(3, 7).unwrap();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].sequence, 3);
        assert_eq!(events[4].sequence, 7);
    }

    #[test]
    fn test_merkle_root() {
        let config = create_test_config();
        let logger = AuditLogger::new(config).unwrap();

        logger
            .log_success(EventType::Sign, "op_1", "default", "client_1", None)
            .unwrap();

        let root1 = logger.get_merkle_root().unwrap();
        assert!(!root1.is_empty());

        logger
            .log_success(EventType::Sign, "op_2", "default", "client_1", None)
            .unwrap();

        let root2 = logger.get_merkle_root().unwrap();
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_disabled_logger() {
        let temp_dir = TempDir::new().unwrap();
        let config = AuditConfig {
            storage: StorageConfig {
                base_dir: temp_dir.path().to_path_buf(),
                ..Default::default()
            },
            enabled: false,
            rebuild_merkle_on_start: false,
        };

        let logger = AuditLogger::new(config).unwrap();

        let result = logger.log_success(EventType::Sign, "op", "default", "client_1", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let base_dir = temp_dir.path().to_path_buf();

        // Create logger and write events
        {
            let config = AuditConfig {
                storage: StorageConfig {
                    base_dir: base_dir.clone(),
                    ..Default::default()
                },
                enabled: true,
                rebuild_merkle_on_start: false,
            };

            let logger = AuditLogger::new(config).unwrap();

            for i in 1..=5 {
                logger
                    .log_success(
                        EventType::Sign,
                        format!("op_{}", i),
                        "default",
                        "client_1",
                        None,
                    )
                    .unwrap();
            }

            logger.flush().unwrap();
        }

        // Create new logger and verify it can rebuild state
        {
            let config = AuditConfig {
                storage: StorageConfig {
                    base_dir: base_dir.clone(),
                    ..Default::default()
                },
                enabled: true,
                rebuild_merkle_on_start: true,
            };

            let logger = AuditLogger::new(config).unwrap();

            assert_eq!(logger.current_sequence(), 5);
            assert_eq!(logger.event_count(), 5);
            assert!(logger.verify_integrity().is_ok());
        }
    }

    #[test]
    fn test_custom_event() {
        let config = create_test_config();
        let logger = AuditLogger::new(config).unwrap();

        let builder = AuditEvent::builder()
            .event_type(EventType::ConfigChange)
            .operation("update_config")
            .namespace("system")
            .client_id("admin")
            .success()
            .metadata(serde_json::json!({
                "setting": "max_connections",
                "old_value": 100,
                "new_value": 200
            }));

        let seq = logger.log(builder).unwrap();
        assert_eq!(seq, 1);

        let event = logger.get_event(1).unwrap();
        assert!(event.metadata.is_some());
    }

    #[test]
    fn test_high_throughput() {
        let config = create_test_config();
        let logger = AuditLogger::new(config).unwrap();

        let start = std::time::Instant::now();
        let count = 1000;

        for i in 1..=count {
            logger
                .log_success(
                    EventType::Sign,
                    format!("op_{}", i),
                    "default",
                    "client_1",
                    None,
                )
                .unwrap();
        }

        let duration = start.elapsed();
        let ops_per_sec = count as f64 / duration.as_secs_f64();

        println!("Throughput: {:.0} ops/sec", ops_per_sec);

        assert_eq!(logger.current_sequence(), count);
        assert!(logger.verify_integrity().is_ok());
    }
}
