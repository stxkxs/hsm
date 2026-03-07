#![deny(unsafe_code)]
//! Storage Backend Module
//!
//! This module provides a secure, encrypted storage backend for persisting cryptographic keys
//! with atomic operations, journaling, and corruption detection.
//!
//! # Architecture
//!
//! The storage system is built on a layered architecture with multiple components:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │            CachedStorage (LRU Cache)                │
//! │  - Hot key caching (< 100μs reads)                  │
//! │  - Write-through cache invalidation                 │
//! │  - Lock-free metadata cache                         │
//! └────────────────────┬────────────────────────────────┘
//!                      │
//! ┌────────────────────▼────────────────────────────────┐
//! │         EncryptedFileStorage (Core Backend)         │
//! │  - AES-256-GCM encryption at rest                   │
//! │  - Write-ahead journaling for atomicity             │
//! │  - Namespace-based isolation                        │
//! │  - SHA-256 integrity verification                   │
//! └────┬────────────────────────────────────────────┬───┘
//!      │                                            │
//! ┌────▼──────────────┐                   ┌────────▼──────┐
//! │  WriteAheadLog    │                   │   MasterKey   │
//! │  - Journal ops    │                   │  - AES-256-GCM│
//! │  - ACID semantics │                   │  - KEK wrapped│
//! │  - Crash recovery │                   │  - Zeroized   │
//! └───────────────────┘                   └───────────────┘
//! ```
//!
//! ## Storage Hierarchy
//!
//! Data is organized in a hierarchical directory structure:
//!
//! ```text
//! base_path/
//! ├── master_key.enc          # Encrypted master key
//! └── namespaces/
//!     ├── production/
//!     │   ├── keys/
//!     │   │   ├── key-abc123.enc   # Encrypted key data
//!     │   │   ├── key-abc123.meta  # Integrity metadata
//!     │   │   └── ...
//!     │   └── journal/
//!     │       └── wal.log          # Write-ahead log
//!     └── staging/
//!         └── ...
//! ```
//!
//! # Features
//!
//! - **Encryption at Rest**: All keys are encrypted using AES-256-GCM with authenticated encryption
//! - **Atomic Operations**: Write operations are atomic via write-ahead journaling (ACID semantics)
//! - **Crash Recovery**: Automatic recovery from crashes using journal replay
//! - **Corruption Detection**: SHA-256 checksums prevent silent data corruption
//! - **Namespace Isolation**: Keys are organized by namespace for multi-tenancy
//! - **Performance Caching**: LRU cache for hot keys with >90% hit rate target
//! - **Directory Sharding**: Distributes keys across 256 shards to avoid filesystem bottlenecks
//!
//! # Crash Recovery
//!
//! The storage system provides automatic crash recovery through write-ahead logging:
//!
//! 1. **Write Phase**: Before modifying data, operations are written to the journal
//! 2. **Commit Phase**: Journal entries are fsynced to disk for durability
//! 3. **Apply Phase**: The actual file operations are performed
//! 4. **Clear Phase**: Successfully applied operations are removed from the journal
//!
//! On startup after a crash:
//!
//! 1. The system scans all namespace directories for journal files
//! 2. Each journal is replayed in sequence order
//! 3. Operations are re-applied idempotently
//! 4. Corrupted journal entries are skipped (resilient to partial writes)
//! 5. Journals are truncated after successful recovery
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! ```rust,no_run
//! use hsm_storage::{EncryptedFileStorage, StorageBackend, KeyId};
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create storage with a new master key
//! let base_path = PathBuf::from("/secure/storage");
//! let kek = [0u8; 32]; // Key-encryption-key (from config/env)
//! let mut storage = EncryptedFileStorage::create_with_new_key(base_path, &kek)?;
//!
//! // Create a namespace for isolation
//! storage.create_namespace("production")?;
//!
//! // Store a key atomically
//! let key_id = KeyId::new("user-auth-key-001");
//! let key_data = b"secret cryptographic key material";
//! storage.store_key(&key_id, key_data, "production")?;
//!
//! // Load the key
//! let loaded = storage.load_key(&key_id, "production")?;
//! assert_eq!(loaded, key_data);
//!
//! // Ensure durability (fsync journals)
//! storage.sync()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Atomic Operations with Caching
//!
//! ```rust,no_run
//! use hsm_storage::{EncryptedFileStorage, CachedStorage, KeyId, StorageBackend};
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let base_path = PathBuf::from("/secure/storage");
//! let kek = [0u8; 32];
//! let backend = EncryptedFileStorage::create_with_new_key(base_path, &kek)?;
//!
//! // Wrap with cache layer (10,000 key capacity)
//! let cached_storage = CachedStorage::new(backend, 10_000);
//!
//! // Create namespace
//! cached_storage.backend().lock().create_namespace("production")?;
//!
//! // Write-through cache: writes go to both cache and disk
//! let key_id = KeyId::new("hot-key");
//! cached_storage.store_key_cached(&key_id, b"frequently accessed", "production")?;
//!
//! // Subsequent reads hit cache (< 100μs latency)
//! let data = cached_storage.load_key_cached(&key_id, "production")?;
//!
//! // Check cache performance
//! let stats = cached_storage.cache_stats();
//! println!("Cache hit rate: {:.2}%", stats.hit_rate);
//! # Ok(())
//! # }
//! ```
//!
//! ## Recovery from Crash
//!
//! ```rust,no_run
//! use hsm_storage::EncryptedFileStorage;
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // After a crash, open existing storage
//! let base_path = PathBuf::from("/secure/storage");
//! let kek = [0u8; 32];
//!
//! // This automatically replays journals and recovers state
//! let storage = EncryptedFileStorage::open(base_path, &kek)?;
//!
//! // All committed operations are guaranteed to be present
//! // Uncommitted operations are safely discarded
//! # Ok(())
//! # }
//! ```

pub mod backend;
pub mod checksum;
pub mod encrypted_fs;
pub mod journal;
pub mod master_key;

// Phase 2 enhancements
pub mod async_storage;
pub mod cached_storage;
pub mod compression;
pub mod integrity;
pub mod sharding;

// Hardware backend integration
#[cfg(feature = "hardware")]
pub mod hardware_storage;

#[cfg(feature = "hardware")]
pub mod storage_config;

// Re-export primary types
pub use backend::{StorageBackend, StorageError, StorageResult};
pub use encrypted_fs::EncryptedFileStorage;
pub use master_key::MasterKey;

// Re-export Phase 2 types
pub use async_storage::AsyncFileStorage;
pub use cached_storage::{CacheStats, CachedStorage};
pub use compression::{compress, decompress, CompressedData, CompressionStats};
pub use integrity::{IntegrityKeyManager, IntegrityProtectedKey};
pub use sharding::{get_shard_number, get_sharded_path, ShardStats};

// Re-export hardware backend types
#[cfg(feature = "hardware")]
pub use hardware_storage::{HardwareStorageBackend, HardwareStorageStats};

#[cfg(feature = "hardware")]
pub use storage_config::{
    create_storage_backend, HardwareBackendConfig, StorageBackendType, StorageConfig,
};

/// A unique identifier for a cryptographic key
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct KeyId(String);

impl KeyId {
    /// Create a new KeyId from a string
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the string representation of the KeyId
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for KeyId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl From<&str> for KeyId {
    fn from(id: &str) -> Self {
        Self(id.to_string())
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
