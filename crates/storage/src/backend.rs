//! Storage Backend Trait
//!
//! Defines the core interface for key storage operations.

use crate::KeyId;
use std::path::PathBuf;
use thiserror::Error;

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;

/// Errors that can occur during storage operations
#[derive(Error, Debug)]
pub enum StorageError {
    /// Key not found in storage
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Namespace not found
    #[error("Namespace not found: {0}")]
    NamespaceNotFound(String),

    /// IO error occurred
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Encryption/decryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Corruption detected
    #[error("Data corruption detected: {0}")]
    CorruptionDetected(String),

    /// Journal error
    #[error("Journal error: {0}")]
    Journal(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Master key error
    #[error("Master key error: {0}")]
    MasterKey(String),

    /// Invalid path
    #[error("Invalid path: {0}")]
    InvalidPath(PathBuf),

    /// Operation failed
    #[error("Operation failed: {0}")]
    OperationFailed(String),
}

/// Core storage backend trait
///
/// This trait defines the interface for storing, loading, and deleting encrypted keys.
/// Implementations must ensure:
/// - All operations are atomic
/// - Data is encrypted at rest
/// - Corruption is detected via checksums
/// - Write operations are journaled for crash recovery
pub trait StorageBackend: Send + Sync {
    /// Store a key in the specified namespace
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    /// * `data` - Raw key data to store (will be encrypted)
    /// * `namespace` - Namespace for key isolation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The namespace doesn't exist
    /// - Encryption fails
    /// - IO error occurs
    /// - Journal write fails
    fn store_key(&mut self, key_id: &KeyId, data: &[u8], namespace: &str) -> StorageResult<()>;

    /// Load a key from the specified namespace
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    /// * `namespace` - Namespace containing the key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key doesn't exist
    /// - Namespace doesn't exist
    /// - Decryption fails
    /// - Checksum verification fails
    /// - IO error occurs
    fn load_key(&self, key_id: &KeyId, namespace: &str) -> StorageResult<Vec<u8>>;

    /// Delete a key from the specified namespace
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    /// * `namespace` - Namespace containing the key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key doesn't exist
    /// - Namespace doesn't exist
    /// - Journal write fails
    /// - IO error occurs
    fn delete_key(&mut self, key_id: &KeyId, namespace: &str) -> StorageResult<()>;

    /// List all keys in a namespace
    ///
    /// # Arguments
    ///
    /// * `namespace` - Namespace to list keys from
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Namespace doesn't exist
    /// - IO error occurs
    fn list_keys(&self, namespace: &str) -> StorageResult<Vec<KeyId>>;

    /// Check if a key exists in the specified namespace
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    /// * `namespace` - Namespace to check
    fn key_exists(&self, key_id: &KeyId, namespace: &str) -> StorageResult<bool>;

    /// Synchronize all pending operations to disk
    ///
    /// This ensures all writes are persisted and the journal is committed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Journal commit fails
    /// - fsync fails
    /// - IO error occurs
    fn sync(&mut self) -> StorageResult<()>;

    /// Create a new namespace
    ///
    /// # Arguments
    ///
    /// * `namespace` - Name of the namespace to create
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Namespace already exists
    /// - IO error occurs
    fn create_namespace(&mut self, namespace: &str) -> StorageResult<()>;

    /// Delete a namespace and all its keys
    ///
    /// # Arguments
    ///
    /// * `namespace` - Name of the namespace to delete
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Namespace doesn't exist
    /// - IO error occurs
    fn delete_namespace(&mut self, namespace: &str) -> StorageResult<()>;

    /// List all namespaces
    ///
    /// # Errors
    ///
    /// Returns an error if IO error occurs
    fn list_namespaces(&self) -> StorageResult<Vec<String>>;
}
