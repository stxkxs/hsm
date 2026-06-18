//! Asynchronous audit logger with batching and backpressure
//!
//! This module provides high-performance asynchronous logging with:
//! - Non-blocking event submission via bounded channels
//! - Automatic batching for improved throughput
//! - Backpressure handling when queue is full
//! - Background writer task for I/O operations

use crate::checkpoint::{Checkpoint, CheckpointError};
use crate::event::{AuditEvent, AuditEventBuilder, EventType};
use crate::hash_chain::HashChain;
use crate::merkle_tree::MerkleTree;
use crate::storage::{AuditStorage, StorageConfig, StorageError};
use parking_lot::RwLock;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Debug, Error)]
pub enum AsyncAuditError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Event build error: {0}")]
    EventBuild(&'static str),

    #[error("Logger is disabled")]
    Disabled,

    #[error("Queue full - backpressure applied")]
    QueueFull,

    #[error("Logger shutdown")]
    Shutdown,

    #[error("Channel send error")]
    ChannelSend,

    #[error("Checkpoint verification failed: {0}")]
    Checkpoint(#[from] CheckpointError),
}

/// Configuration for async audit logger
#[derive(Debug, Clone)]
pub struct AsyncAuditConfig {
    /// Storage configuration
    pub storage: StorageConfig,

    /// Whether the logger is enabled
    pub enabled: bool,

    /// Whether to rebuild Merkle tree on startup
    pub rebuild_merkle_on_start: bool,

    /// Channel capacity (max events in queue)
    pub channel_capacity: usize,

    /// Batch size for writing events
    pub batch_size: usize,

    /// Batch timeout in milliseconds (flush if no new events)
    pub batch_timeout_ms: u64,

    /// Optional key for checkpoint integrity tags (HMAC-SHA256). See
    /// [`crate::checkpoint`] for the tamper-evidence model. `None` falls back
    /// to a keyless hash usable only for dev/test.
    pub checkpoint_key: Option<Vec<u8>>,
}

impl Default for AsyncAuditConfig {
    fn default() -> Self {
        Self {
            storage: StorageConfig::default(),
            enabled: true,
            rebuild_merkle_on_start: true,
            channel_capacity: 10000,
            batch_size: 100,
            batch_timeout_ms: 100,
            checkpoint_key: None,
        }
    }
}

/// Event to be logged asynchronously
struct LogRequest {
    builder: AuditEventBuilder,
    response: tokio::sync::oneshot::Sender<Result<u64, AsyncAuditError>>,
}

/// Asynchronous audit logger
pub struct AsyncAuditLogger {
    config: AsyncAuditConfig,
    tx: Arc<RwLock<Option<mpsc::Sender<LogRequest>>>>,
    writer_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    hash_chain: Arc<HashChain>,
    merkle_tree: Arc<RwLock<MerkleTree>>,
    storage: Arc<AuditStorage>,
}

impl AsyncAuditLogger {
    /// Create a new async audit logger with background writer task
    pub fn new(config: AsyncAuditConfig) -> Result<Self, AsyncAuditError> {
        let storage = Arc::new(AuditStorage::new(config.storage.clone())?);
        let hash_chain = Arc::new(HashChain::new());
        let merkle_tree = Arc::new(RwLock::new(MerkleTree::new()));

        // Rebuild state from existing logs if configured
        if config.rebuild_merkle_on_start {
            let events = storage.read_current_events()?;
            for event in events {
                hash_chain
                    .append(event.clone())
                    .map_err(|_e| AsyncAuditError::EventBuild("Failed to rebuild hash chain"))?;
                merkle_tree.write().update(&event.current_hash);
            }

            // Tail-truncation guard: verify the rebuilt live tip against the
            // persisted checkpoint. A tip behind the checkpoint indicates
            // deleted events; fail closed by refusing to start.
            if let Some(checkpoint) = storage.read_checkpoint()? {
                let live_seq = hash_chain.current_sequence();
                let live_root = merkle_tree.read().get_root().ok();
                checkpoint.verify_against_live(
                    live_seq,
                    live_root.as_deref(),
                    config.checkpoint_key.as_deref(),
                )?;
            }
        }

        // Create channel for log requests
        let (tx, rx) = mpsc::channel(config.channel_capacity);

        // Spawn background writer task
        let writer_handle = Self::spawn_writer_task(
            rx,
            Arc::clone(&hash_chain),
            Arc::clone(&merkle_tree),
            Arc::clone(&storage),
            config.clone(),
        );

        Ok(Self {
            config,
            tx: Arc::new(RwLock::new(Some(tx))),
            writer_handle: Arc::new(RwLock::new(Some(writer_handle))),
            hash_chain,
            merkle_tree,
            storage,
        })
    }

    /// Spawn the background writer task
    fn spawn_writer_task(
        mut rx: mpsc::Receiver<LogRequest>,
        hash_chain: Arc<HashChain>,
        merkle_tree: Arc<RwLock<MerkleTree>>,
        storage: Arc<AuditStorage>,
        config: AsyncAuditConfig,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut batch: Vec<LogRequest> = Vec::with_capacity(config.batch_size);
            let timeout = tokio::time::Duration::from_millis(config.batch_timeout_ms);
            let checkpoint_key = config.checkpoint_key.clone();

            loop {
                batch.clear();

                // Wait for first event with timeout
                let first_event = tokio::time::timeout(timeout, rx.recv()).await;

                match first_event {
                    Ok(Some(request)) => {
                        batch.push(request);
                    }
                    Ok(None) => {
                        // Channel closed, exit loop
                        break;
                    }
                    Err(_) => {
                        // Timeout, continue to check for shutdown
                        continue;
                    }
                }

                // Collect more events without blocking (up to batch size)
                while batch.len() < config.batch_size {
                    match rx.try_recv() {
                        Ok(request) => batch.push(request),
                        Err(_) => break,
                    }
                }

                // Process batch (take ownership for processing)
                let batch_to_process = std::mem::take(&mut batch);
                Self::process_batch(
                    batch_to_process,
                    &hash_chain,
                    &merkle_tree,
                    &storage,
                    checkpoint_key.as_deref(),
                )
                .await;
            }
        })
    }

    /// Process a batch of log requests
    async fn process_batch(
        batch: Vec<LogRequest>,
        hash_chain: &Arc<HashChain>,
        merkle_tree: &Arc<RwLock<MerkleTree>>,
        storage: &Arc<AuditStorage>,
        checkpoint_key: Option<&[u8]>,
    ) {
        for request in batch {
            let result = Self::process_single_event(
                &request.builder,
                hash_chain,
                merkle_tree,
                storage,
                checkpoint_key,
            );

            // Send response back to caller
            let _ = request.response.send(result);
        }

        // Flush to storage
        if let Err(e) = storage.flush() {
            eprintln!("Failed to flush audit batch: {:?}", e);
        }
    }

    /// Process a single event
    fn process_single_event(
        builder: &AuditEventBuilder,
        hash_chain: &Arc<HashChain>,
        merkle_tree: &Arc<RwLock<MerkleTree>>,
        storage: &Arc<AuditStorage>,
        checkpoint_key: Option<&[u8]>,
    ) -> Result<u64, AsyncAuditError> {
        // Get next sequence number
        let sequence = hash_chain.current_sequence() + 1;

        // Build event with sequence and prev_hash. The hash chain's `append`
        // recomputes prev_hash/current_hash from its own state; the background
        // writer task is the single writer, so chain state cannot change
        // between here and the append, making the persisted event identical to
        // the one the chain stores.
        let event = builder
            .clone()
            .sequence(sequence)
            .prev_hash(hash_chain.last_hash())
            .timestamp(chrono::Utc::now())
            .build()
            .map_err(AsyncAuditError::EventBuild)?;

        // Durability first: persist to storage BEFORE advancing any in-memory
        // state. If the write fails we return the error without touching the
        // hash chain or Merkle tree, so the in-memory sequence/last_hash do not
        // advance and no persisted gap / refused-restart condition is created.
        storage.write_event(&event)?;

        // Append to hash chain (advances sequence + last_hash) only after the
        // durable write succeeded.
        let hash = hash_chain
            .append(event)
            .map_err(|_| AsyncAuditError::EventBuild("Hash chain append failed"))?;

        // Update Merkle tree
        let merkle_root = {
            let mut tree = merkle_tree.write();
            tree.update(&hash);
            tree.get_root().ok()
        };

        // Persist a signed-root checkpoint committing to this sequence + root,
        // enabling tail-truncation detection on a later restart.
        if let Some(root) = merkle_root {
            let checkpoint = Checkpoint::new(sequence, root, checkpoint_key);
            storage.write_checkpoint(&checkpoint)?;
        }

        Ok(sequence)
    }

    /// Log an audit event asynchronously
    pub async fn log(&self, builder: AuditEventBuilder) -> Result<u64, AsyncAuditError> {
        if !self.config.enabled {
            return Err(AsyncAuditError::Disabled);
        }

        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

        let request = LogRequest {
            builder,
            response: response_tx,
        };

        // Try to send without blocking
        let tx = self.tx.read().clone();
        if let Some(sender) = tx {
            sender
                .send(request)
                .await
                .map_err(|_| AsyncAuditError::ChannelSend)?;
        } else {
            return Err(AsyncAuditError::Shutdown);
        }

        // Wait for response from writer task
        response_rx.await.map_err(|_| AsyncAuditError::Shutdown)?
    }

    /// Log a successful operation
    pub async fn log_success(
        &self,
        event_type: EventType,
        operation: impl Into<String>,
        namespace: impl Into<String>,
        client_id: impl Into<String>,
        key_id: Option<String>,
    ) -> Result<u64, AsyncAuditError> {
        let mut builder = AuditEvent::builder()
            .event_type(event_type)
            .operation(operation)
            .namespace(namespace)
            .client_id(client_id)
            .success();

        if let Some(kid) = key_id {
            builder = builder.key_id(kid);
        }

        self.log(builder).await
    }

    /// Log a failed operation
    pub async fn log_failure(
        &self,
        event_type: EventType,
        operation: impl Into<String>,
        namespace: impl Into<String>,
        client_id: impl Into<String>,
        key_id: Option<String>,
        reason: impl Into<String>,
    ) -> Result<u64, AsyncAuditError> {
        let mut builder = AuditEvent::builder()
            .event_type(event_type)
            .operation(operation)
            .namespace(namespace)
            .client_id(client_id)
            .failure(reason);

        if let Some(kid) = key_id {
            builder = builder.key_id(kid);
        }

        self.log(builder).await
    }

    /// Verify the integrity of the audit chain
    pub fn verify_integrity(&self) -> Result<(), AsyncAuditError> {
        self.hash_chain
            .verify_all()
            .map_err(|_| AsyncAuditError::EventBuild("Verification failed"))
    }

    /// Get the Merkle root hash
    pub fn get_merkle_root(&self) -> Result<String, AsyncAuditError> {
        self.merkle_tree
            .read()
            .get_root()
            .map_err(|_| AsyncAuditError::EventBuild("Merkle tree is empty"))
    }

    /// Get an event by sequence number
    pub fn get_event(&self, sequence: u64) -> Result<AuditEvent, AsyncAuditError> {
        self.hash_chain
            .get_event(sequence)
            .map_err(|_| AsyncAuditError::EventBuild("Event not found"))
    }

    /// Get events in a range
    pub fn get_events_range(&self, from: u64, to: u64) -> Result<Vec<AuditEvent>, AsyncAuditError> {
        self.hash_chain
            .get_events_range(from, to)
            .map_err(|_| AsyncAuditError::EventBuild("Invalid range"))
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
    pub async fn flush(&self) -> Result<(), AsyncAuditError> {
        self.storage.flush()?;
        Ok(())
    }

    /// Force a log rotation
    pub async fn rotate(&self) -> Result<(), AsyncAuditError> {
        self.storage.force_rotation()?;
        Ok(())
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

    /// Shutdown the logger gracefully
    pub async fn shutdown(&self) {
        // Drop the sender to signal shutdown
        let _ = self.tx.write().take();

        // Take the handle first, releasing the lock before awaiting
        let handle = self.writer_handle.write().take();

        // Wait for writer task to complete (outside of lock scope)
        if let Some(handle) = handle {
            let _ = handle.await;
        }

        // Final flush
        let _ = self.storage.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_async_logger_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = AsyncAuditConfig {
            storage: StorageConfig {
                base_dir: temp_dir.path().to_path_buf(),
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: false,
            ..Default::default()
        };

        let logger = AsyncAuditLogger::new(config).unwrap();
        assert_eq!(logger.current_sequence(), 0);
    }

    #[tokio::test]
    async fn test_async_log_success() {
        let temp_dir = TempDir::new().unwrap();
        let config = AsyncAuditConfig {
            storage: StorageConfig {
                base_dir: temp_dir.path().to_path_buf(),
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: false,
            ..Default::default()
        };

        let logger = AsyncAuditLogger::new(config).unwrap();

        let seq = logger
            .log_success(
                EventType::KeyGeneration,
                "generate_key",
                "default",
                "client_1",
                Some("key_123".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(seq, 1);

        // Wait a bit for background task to process
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert_eq!(logger.current_sequence(), 1);
    }

    #[tokio::test]
    async fn test_async_high_throughput() {
        let temp_dir = TempDir::new().unwrap();
        let config = AsyncAuditConfig {
            storage: StorageConfig {
                base_dir: temp_dir.path().to_path_buf(),
                sync_writes: false,
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: false,
            batch_size: 100,
            ..Default::default()
        };

        let logger = AsyncAuditLogger::new(config).unwrap();

        let start = std::time::Instant::now();
        let count = 1000;

        for i in 1..=count {
            logger
                .log_success(
                    EventType::Sign,
                    format!("operation_{}", i),
                    "default",
                    "client_1",
                    None,
                )
                .await
                .unwrap();
        }

        let duration = start.elapsed();
        let ops_per_sec = count as f64 / duration.as_secs_f64();

        println!(
            "Async throughput: {:.2}ms total, {:.0} ops/sec",
            duration.as_millis(),
            ops_per_sec
        );

        // Note: Performance varies by machine, so we just verify it completed
        // Expected: >100 ops/sec on modern hardware, but depends on CPU/disk

        // Wait for background processing
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        assert_eq!(logger.current_sequence(), count);
        assert!(logger.verify_integrity().is_ok());
    }

    #[tokio::test]
    async fn test_async_batch_processing() {
        let temp_dir = TempDir::new().unwrap();
        let config = AsyncAuditConfig {
            storage: StorageConfig {
                base_dir: temp_dir.path().to_path_buf(),
                sync_writes: false,
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: false,
            batch_size: 50,
            batch_timeout_ms: 50,
            ..Default::default()
        };

        let logger = AsyncAuditLogger::new(config).unwrap();

        // Log 100 events (2 batches)
        for i in 1..=100 {
            logger
                .log_success(
                    EventType::Sign,
                    format!("op_{}", i),
                    "default",
                    "client_1",
                    None,
                )
                .await
                .unwrap();
        }

        // Wait for batches to process
        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

        assert_eq!(logger.current_sequence(), 100);
        assert!(logger.verify_integrity().is_ok());
    }

    #[tokio::test]
    async fn test_async_shutdown() {
        let temp_dir = TempDir::new().unwrap();
        let config = AsyncAuditConfig {
            storage: StorageConfig {
                base_dir: temp_dir.path().to_path_buf(),
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: false,
            ..Default::default()
        };

        let logger = AsyncAuditLogger::new(config).unwrap();

        for i in 1..=10 {
            logger
                .log_success(
                    EventType::Sign,
                    format!("op_{}", i),
                    "default",
                    "client_1",
                    None,
                )
                .await
                .unwrap();
        }

        logger.shutdown().await;

        // Verify all events were persisted
        assert_eq!(logger.current_sequence(), 10);
    }
}
