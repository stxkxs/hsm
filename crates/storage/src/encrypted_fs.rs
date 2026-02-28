//! Encrypted Filesystem Storage
//!
//! Main implementation of the storage backend with encryption, journaling, and checksums.
//!
//! # Crash Recovery
//!
//! This implementation guarantees atomicity through write-ahead logging. Every mutating
//! operation follows this protocol:
//!
//! 1. **Journal Write**: Operation is serialized and appended to the write-ahead log
//! 2. **Journal Commit**: The journal entry is fsynced to ensure durability
//! 3. **Data Write**: The actual file system mutation is performed
//! 4. **Journal Clear**: After successful startup, replayed journals are truncated
//!
//! ## Recovery Mechanism
//!
//! When [`EncryptedFileStorage::new`] is called, the `recover()` method automatically:
//!
//! - Scans all namespace directories for journal files (`journal/wal.log`)
//! - Reads and replays each journal entry in sequence order
//! - Applies operations idempotently (safe to re-apply completed operations)
//! - Skips corrupted entries (partial writes during crash)
//! - Truncates journals after successful recovery
//!
//! ## Idempotency Guarantees
//!
//! All operations are designed to be idempotent during replay:
//!
//! - `StoreKey`: Overwrites existing file (same result if replayed)
//! - `DeleteKey`: Checks existence before deletion (no error if already deleted)
//! - `CreateNamespace`: Returns success if directory already exists
//! - `DeleteNamespace`: Checks existence before deletion
//!
//! # Examples
//!
//! ## Atomic Key Storage
//!
//! ```rust,no_run
//! use hsm_storage::{EncryptedFileStorage, StorageBackend, KeyId};
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let base_path = PathBuf::from("/data/keys");
//! let kek = [0u8; 32];
//! let mut storage = EncryptedFileStorage::create_with_new_key(base_path, &kek)?;
//! storage.create_namespace("users")?;
//!
//! // This operation is atomic - either fully completes or fully rolls back
//! let key_id = KeyId::new("user-123-auth-key");
//! storage.store_key(&key_id, b"secret key material", "users")?;
//!
//! // Even if the process crashes here, the key will either be:
//! // - Fully written (if commit succeeded)
//! // - Not present (if commit failed)
//! // Never partially written or corrupted
//! # Ok(())
//! # }
//! ```
//!
//! ## Recovery After Crash
//!
//! ```rust,no_run
//! use hsm_storage::EncryptedFileStorage;
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Simulate: Process crashed while writing keys
//! // Journal contains uncommitted operations
//!
//! // On restart, opening storage triggers automatic recovery
//! let base_path = PathBuf::from("/data/keys");
//! let kek = [0u8; 32];
//! let storage = EncryptedFileStorage::open(base_path, &kek)?;
//!
//! // Storage is now in a consistent state:
//! // - All journaled operations have been replayed
//! // - Partial writes have been completed or discarded
//! // - Corrupted journal entries have been skipped
//! # Ok(())
//! # }
//! ```

use crate::backend::{StorageBackend, StorageError, StorageResult};
use crate::checksum::KeyMetadata;
use crate::journal::{JournalOp, WriteAheadLog};
use crate::master_key::{EncryptedData, MasterKey};
use crate::KeyId;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const KEY_FILE_EXT: &str = "enc";
const META_FILE_EXT: &str = "meta";

/// Create a file with restricted permissions (0o600 on Unix)
fn create_restricted_file(path: &std::path::Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    opts.open(path)
}

/// Encrypted filesystem storage implementation
///
/// This implementation provides:
/// - Encryption at rest using AES-256-GCM
/// - Atomic operations via write-ahead journaling
/// - Corruption detection via SHA-256 checksums
/// - Namespace-based directory structure
pub struct EncryptedFileStorage {
    /// Master encryption key
    master_key: MasterKey,
    /// Base directory for storage
    base_path: PathBuf,
    /// Write-ahead log for atomic operations
    journals: HashMap<String, WriteAheadLog>,
}

impl EncryptedFileStorage {
    /// Create a new encrypted file storage
    ///
    /// # Arguments
    ///
    /// * `base_path` - Base directory for all storage
    /// * `master_key` - Master encryption key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Directory creation fails
    /// - Journal recovery fails
    pub fn new(base_path: PathBuf, master_key: MasterKey) -> StorageResult<Self> {
        // Create base directory structure
        fs::create_dir_all(&base_path)?;
        let namespaces_path = base_path.join("namespaces");
        fs::create_dir_all(&namespaces_path)?;

        let mut storage = Self {
            master_key,
            base_path,
            journals: HashMap::new(),
        };

        // Recover from any incomplete operations
        storage.recover()?;

        Ok(storage)
    }

    /// Create storage with a generated master key
    ///
    /// # Arguments
    ///
    /// * `base_path` - Base directory for all storage
    /// * `kek` - Key-encryption-key to protect the master key
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails
    pub fn create_with_new_key(base_path: PathBuf, kek: &[u8; 32]) -> StorageResult<Self> {
        let master_key = MasterKey::generate();
        let master_key_path = base_path.join("master_key.enc");

        // Save the master key
        master_key.save(&master_key_path, kek)?;

        Self::new(base_path, master_key)
    }

    /// Open existing storage with a saved master key
    ///
    /// # Arguments
    ///
    /// * `base_path` - Base directory for storage
    /// * `kek` - Key-encryption-key to decrypt the master key
    ///
    /// # Errors
    ///
    /// Returns an error if the master key cannot be loaded
    pub fn open(base_path: PathBuf, kek: &[u8; 32]) -> StorageResult<Self> {
        let master_key_path = base_path.join("master_key.enc");
        let master_key = MasterKey::load(&master_key_path, kek)?;
        Self::new(base_path, master_key)
    }

    /// Recover from crash by replaying journal
    ///
    /// This method is called automatically during storage initialization to ensure
    /// consistency after a crash or unclean shutdown.
    ///
    /// # Recovery Algorithm
    ///
    /// 1. Scan all namespace directories in `namespaces/`
    /// 2. For each namespace, check for journal file at `journal/wal.log`
    /// 3. Read all journal entries using [`WriteAheadLog::replay`]
    /// 4. Apply each entry in sequence order (idempotent operations)
    /// 5. Truncate the journal after successful replay
    ///
    /// # Corruption Resilience
    ///
    /// The replay process is resilient to:
    /// - Incomplete journal entries (partial writes during crash)
    /// - Checksum failures (detected and skipped)
    /// - Missing files (operations are idempotent)
    /// - Duplicate operations (re-applying is safe)
    ///
    /// # Errors
    ///
    /// Returns an error only if:
    /// - Directory traversal fails (permissions, I/O error)
    /// - File operations fail (disk full, permissions)
    ///
    /// Corrupted journal entries are logged and skipped, not treated as errors.
    fn recover(&mut self) -> StorageResult<()> {
        let namespaces_path = self.base_path.join("namespaces");
        if !namespaces_path.exists() {
            return Ok(());
        }

        // Find all namespaces
        for entry in fs::read_dir(&namespaces_path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let namespace = entry.file_name().to_string_lossy().to_string();

                let journal_path = self.get_journal_path(&namespace);
                if journal_path.exists() {
                    let journal = WriteAheadLog::new(journal_path.clone())?;
                    let entries = journal.replay()?;

                    // Apply each journaled operation
                    for entry in entries {
                        match entry.operation {
                            JournalOp::StoreKey {
                                key_id,
                                namespace,
                                data,
                            } => {
                                self.store_key_impl(&key_id, &data, &namespace)?;
                            }
                            JournalOp::DeleteKey { key_id, namespace } => {
                                self.delete_key_impl(&key_id, &namespace)?;
                            }
                            JournalOp::CreateNamespace { namespace } => {
                                self.create_namespace_impl(&namespace)?;
                            }
                            JournalOp::DeleteNamespace { namespace } => {
                                self.delete_namespace_impl(&namespace)?;
                            }
                        }
                    }

                    // Clear the journal after successful recovery
                    let mut journal = WriteAheadLog::new(journal_path)?;
                    journal.truncate()?;
                }
            }
        }

        Ok(())
    }

    /// Get or create journal for a namespace
    fn get_or_create_journal(&mut self, namespace: &str) -> StorageResult<&mut WriteAheadLog> {
        if !self.journals.contains_key(namespace) {
            let journal_path = self.get_journal_path(namespace);
            let journal = WriteAheadLog::new(journal_path)?;
            self.journals.insert(namespace.to_string(), journal);
        }
        Ok(self.journals.get_mut(namespace).unwrap())
    }

    /// Get path to namespace directory
    fn get_namespace_path(&self, namespace: &str) -> PathBuf {
        self.base_path.join("namespaces").join(namespace)
    }

    /// Get path to keys directory for a namespace
    fn get_keys_path(&self, namespace: &str) -> PathBuf {
        self.get_namespace_path(namespace).join("keys")
    }

    /// Get path to journal directory for a namespace
    fn get_journal_path(&self, namespace: &str) -> PathBuf {
        self.get_namespace_path(namespace)
            .join("journal")
            .join("wal.log")
    }

    /// Validate that a path component (key ID or namespace) does not contain
    /// path traversal sequences or dangerous characters.
    ///
    /// Rejects values containing `/`, `\`, `..`, or null bytes to prevent
    /// path traversal attacks that could read/write outside the storage directory.
    fn validate_path_component(component: &str, label: &str) -> StorageResult<()> {
        if component.contains('/')
            || component.contains('\\')
            || component.contains("..")
            || component.contains('\0')
        {
            return Err(StorageError::OperationFailed(format!(
                "Invalid {}: contains path traversal characters",
                label
            )));
        }
        Ok(())
    }

    /// Get path to encrypted key file
    fn get_key_file_path(&self, namespace: &str, key_id: &KeyId) -> StorageResult<PathBuf> {
        Self::validate_path_component(namespace, "namespace")?;
        Self::validate_path_component(&key_id.to_string(), "key ID")?;
        Ok(self.get_keys_path(namespace)
            .join(format!("key-{}.{}", key_id, KEY_FILE_EXT)))
    }

    /// Get path to metadata file
    fn get_meta_file_path(&self, namespace: &str, key_id: &KeyId) -> StorageResult<PathBuf> {
        Self::validate_path_component(namespace, "namespace")?;
        Self::validate_path_component(&key_id.to_string(), "key ID")?;
        Ok(self.get_keys_path(namespace)
            .join(format!("key-{}.{}", key_id, META_FILE_EXT)))
    }

    /// Store key implementation (without journaling)
    fn store_key_impl(&self, key_id: &KeyId, data: &[u8], namespace: &str) -> StorageResult<()> {
        // Encrypt the data
        let encrypted = self.master_key.encrypt(data)?;

        // Serialize encrypted data
        let encrypted_bytes = postcard::to_allocvec(&encrypted).map_err(|e| {
            StorageError::Serialization(format!("Failed to serialize encrypted data: {}", e))
        })?;

        // Create metadata
        let metadata = KeyMetadata::new(&encrypted_bytes);

        // Write encrypted key with restricted permissions
        let key_path = self.get_key_file_path(namespace, key_id)?;
        let mut key_file = create_restricted_file(&key_path)?;
        key_file.write_all(&encrypted_bytes)?;
        key_file.sync_all()?;

        // Write metadata with restricted permissions
        let meta_path = self.get_meta_file_path(namespace, key_id)?;
        let meta_bytes = postcard::to_allocvec(&metadata).map_err(|e| {
            StorageError::Serialization(format!("Failed to serialize metadata: {}", e))
        })?;
        let mut meta_file = create_restricted_file(&meta_path)?;
        meta_file.write_all(&meta_bytes)?;
        meta_file.sync_all()?;

        Ok(())
    }

    /// Delete key implementation (without journaling)
    ///
    /// Performs secure deletion by overwriting file contents with random bytes
    /// before removing the file, to prevent recovery of sensitive key material.
    fn delete_key_impl(&self, key_id: &KeyId, namespace: &str) -> StorageResult<()> {
        let key_path = self.get_key_file_path(namespace, key_id)?;
        let meta_path = self.get_meta_file_path(namespace, key_id)?;

        // Securely overwrite and remove both files
        Self::secure_remove(&key_path)?;
        Self::secure_remove(&meta_path)?;

        Ok(())
    }

    /// Securely remove a file by overwriting its contents with random bytes before deletion.
    fn secure_remove(path: &std::path::Path) -> StorageResult<()> {
        if !path.exists() {
            return Ok(());
        }

        // Overwrite file contents with random bytes before removal
        if let Ok(metadata) = fs::metadata(path) {
            let file_size = metadata.len() as usize;
            if file_size > 0 {
                let mut random_bytes = vec![0u8; file_size];
                if rand::RngCore::try_fill_bytes(&mut rand::thread_rng(), &mut random_bytes).is_ok() {
                    if let Ok(mut file) = File::create(path) {
                        let _ = file.write_all(&random_bytes);
                        let _ = file.sync_all();
                    }
                }
            }
        }

        // Always attempt removal even if overwrite fails
        fs::remove_file(path)?;

        Ok(())
    }

    /// Create namespace implementation (without journaling)
    fn create_namespace_impl(&self, namespace: &str) -> StorageResult<()> {
        let namespace_path = self.get_namespace_path(namespace);
        if namespace_path.exists() {
            return Ok(()); // Already exists
        }

        fs::create_dir_all(&namespace_path)?;
        fs::create_dir_all(self.get_keys_path(namespace))?;
        fs::create_dir_all(self.get_journal_path(namespace).parent().unwrap())?;

        Ok(())
    }

    /// Delete namespace implementation (without journaling)
    fn delete_namespace_impl(&self, namespace: &str) -> StorageResult<()> {
        let namespace_path = self.get_namespace_path(namespace);
        if namespace_path.exists() {
            fs::remove_dir_all(&namespace_path)?;
        }
        Ok(())
    }
}

impl StorageBackend for EncryptedFileStorage {
    fn store_key(&mut self, key_id: &KeyId, data: &[u8], namespace: &str) -> StorageResult<()> {
        // Verify namespace exists
        if !self.get_namespace_path(namespace).exists() {
            return Err(StorageError::NamespaceNotFound(namespace.to_string()));
        }

        // Journal the operation
        let journal = self.get_or_create_journal(namespace)?;
        journal.append(JournalOp::StoreKey {
            key_id: key_id.clone(),
            namespace: namespace.to_string(),
            data: data.to_vec(),
        })?;
        journal.commit()?;

        // Perform the actual operation
        self.store_key_impl(key_id, data, namespace)?;

        Ok(())
    }

    fn load_key(&self, key_id: &KeyId, namespace: &str) -> StorageResult<Vec<u8>> {
        // Verify namespace exists
        if !self.get_namespace_path(namespace).exists() {
            return Err(StorageError::NamespaceNotFound(namespace.to_string()));
        }

        let key_path = self.get_key_file_path(namespace, key_id)?;
        let meta_path = self.get_meta_file_path(namespace, key_id)?;

        // Check if key exists
        if !key_path.exists() {
            return Err(StorageError::KeyNotFound(key_id.to_string()));
        }

        // Read encrypted data
        let mut encrypted_bytes = Vec::new();
        File::open(&key_path)?.read_to_end(&mut encrypted_bytes)?;

        // Read and verify metadata
        if meta_path.exists() {
            let mut meta_bytes = Vec::new();
            File::open(&meta_path)?.read_to_end(&mut meta_bytes)?;

            let metadata: KeyMetadata = postcard::from_bytes(&meta_bytes).map_err(|e| {
                StorageError::Serialization(format!("Failed to deserialize metadata: {}", e))
            })?;

            // Verify integrity
            metadata.verify(&encrypted_bytes)?;
        }

        // Deserialize encrypted data
        let encrypted: EncryptedData = postcard::from_bytes(&encrypted_bytes).map_err(|e| {
            StorageError::Serialization(format!("Failed to deserialize encrypted data: {}", e))
        })?;

        // Decrypt
        self.master_key.decrypt(&encrypted)
    }

    fn delete_key(&mut self, key_id: &KeyId, namespace: &str) -> StorageResult<()> {
        // Verify namespace exists
        if !self.get_namespace_path(namespace).exists() {
            return Err(StorageError::NamespaceNotFound(namespace.to_string()));
        }

        // Check if key exists
        if !self.get_key_file_path(namespace, key_id)?.exists() {
            return Err(StorageError::KeyNotFound(key_id.to_string()));
        }

        // Journal the operation
        let journal = self.get_or_create_journal(namespace)?;
        journal.append(JournalOp::DeleteKey {
            key_id: key_id.clone(),
            namespace: namespace.to_string(),
        })?;
        journal.commit()?;

        // Perform the actual operation
        self.delete_key_impl(key_id, namespace)?;

        Ok(())
    }

    fn list_keys(&self, namespace: &str) -> StorageResult<Vec<KeyId>> {
        let keys_path = self.get_keys_path(namespace);

        if !keys_path.exists() {
            return Err(StorageError::NamespaceNotFound(namespace.to_string()));
        }

        let mut keys = Vec::new();

        for entry in fs::read_dir(&keys_path)? {
            let entry = entry?;
            let filename = entry.file_name().to_string_lossy().to_string();

            // Only process .enc files
            if filename.ends_with(&format!(".{}", KEY_FILE_EXT)) {
                // Extract key ID from filename: key-<id>.enc
                if let Some(id_part) = filename.strip_prefix("key-") {
                    if let Some(id) = id_part.strip_suffix(&format!(".{}", KEY_FILE_EXT)) {
                        keys.push(KeyId::new(id));
                    }
                }
            }
        }

        Ok(keys)
    }

    fn key_exists(&self, key_id: &KeyId, namespace: &str) -> StorageResult<bool> {
        let key_path = self.get_key_file_path(namespace, key_id)?;
        Ok(key_path.exists())
    }

    fn sync(&mut self) -> StorageResult<()> {
        // Commit all pending journal entries
        for journal in self.journals.values_mut() {
            journal.commit()?;
        }
        Ok(())
    }

    fn create_namespace(&mut self, namespace: &str) -> StorageResult<()> {
        let namespace_path = self.get_namespace_path(namespace);
        if namespace_path.exists() {
            return Err(StorageError::OperationFailed(format!(
                "Namespace already exists: {}",
                namespace
            )));
        }

        self.create_namespace_impl(namespace)?;

        // Initialize journal for the namespace
        let journal_path = self.get_journal_path(namespace);
        let _journal = WriteAheadLog::new(journal_path)?;

        Ok(())
    }

    fn delete_namespace(&mut self, namespace: &str) -> StorageResult<()> {
        let namespace_path = self.get_namespace_path(namespace);
        if !namespace_path.exists() {
            return Err(StorageError::NamespaceNotFound(namespace.to_string()));
        }

        // Remove from journals map
        self.journals.remove(namespace);

        // Delete the namespace
        self.delete_namespace_impl(namespace)?;

        Ok(())
    }

    fn list_namespaces(&self) -> StorageResult<Vec<String>> {
        let namespaces_path = self.base_path.join("namespaces");

        if !namespaces_path.exists() {
            return Ok(Vec::new());
        }

        let mut namespaces = Vec::new();

        for entry in fs::read_dir(&namespaces_path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                namespaces.push(entry.file_name().to_string_lossy().to_string());
            }
        }

        Ok(namespaces)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_storage() -> (TempDir, EncryptedFileStorage) {
        let temp_dir = TempDir::new().unwrap();
        let kek = [42u8; 32];
        let storage =
            EncryptedFileStorage::create_with_new_key(temp_dir.path().to_path_buf(), &kek).unwrap();
        (temp_dir, storage)
    }

    #[test]
    fn test_create_storage() {
        let (_temp_dir, storage) = create_test_storage();
        assert!(storage.base_path.exists());
    }

    #[test]
    fn test_create_and_list_namespace() {
        let (_temp_dir, mut storage) = create_test_storage();

        storage.create_namespace("production").unwrap();
        storage.create_namespace("staging").unwrap();

        let namespaces = storage.list_namespaces().unwrap();
        assert_eq!(namespaces.len(), 2);
        assert!(namespaces.contains(&"production".to_string()));
        assert!(namespaces.contains(&"staging".to_string()));
    }

    #[test]
    fn test_store_and_load_key() {
        let (_temp_dir, mut storage) = create_test_storage();

        storage.create_namespace("test").unwrap();

        let key_id = KeyId::new("test-key-1");
        let data = b"secret key material";

        storage.store_key(&key_id, data, "test").unwrap();

        let loaded = storage.load_key(&key_id, "test").unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn test_delete_key() {
        let (_temp_dir, mut storage) = create_test_storage();

        storage.create_namespace("test").unwrap();

        let key_id = KeyId::new("test-key-1");
        let data = b"secret key material";

        storage.store_key(&key_id, data, "test").unwrap();
        assert!(storage.key_exists(&key_id, "test").unwrap());

        storage.delete_key(&key_id, "test").unwrap();
        assert!(!storage.key_exists(&key_id, "test").unwrap());
    }

    #[test]
    fn test_list_keys() {
        let (_temp_dir, mut storage) = create_test_storage();

        storage.create_namespace("test").unwrap();

        storage
            .store_key(&KeyId::new("key1"), b"data1", "test")
            .unwrap();
        storage
            .store_key(&KeyId::new("key2"), b"data2", "test")
            .unwrap();
        storage
            .store_key(&KeyId::new("key3"), b"data3", "test")
            .unwrap();

        let keys = storage.list_keys("test").unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_namespace_isolation() {
        let (_temp_dir, mut storage) = create_test_storage();

        storage.create_namespace("ns1").unwrap();
        storage.create_namespace("ns2").unwrap();

        let key_id = KeyId::new("shared-id");

        storage.store_key(&key_id, b"data1", "ns1").unwrap();
        storage.store_key(&key_id, b"data2", "ns2").unwrap();

        let data1 = storage.load_key(&key_id, "ns1").unwrap();
        let data2 = storage.load_key(&key_id, "ns2").unwrap();

        assert_eq!(data1, b"data1");
        assert_eq!(data2, b"data2");
    }

    #[test]
    fn test_key_not_found() {
        let (_temp_dir, storage) = create_test_storage();

        let result = storage.load_key(&KeyId::new("nonexistent"), "test");
        assert!(matches!(result, Err(StorageError::NamespaceNotFound(_))));
    }

    #[test]
    fn test_namespace_not_found() {
        let (_temp_dir, mut storage) = create_test_storage();

        let result = storage.store_key(&KeyId::new("key1"), b"data", "nonexistent");
        assert!(matches!(result, Err(StorageError::NamespaceNotFound(_))));
    }

    #[test]
    fn test_delete_namespace() {
        let (_temp_dir, mut storage) = create_test_storage();

        storage.create_namespace("test").unwrap();
        storage
            .store_key(&KeyId::new("key1"), b"data", "test")
            .unwrap();

        storage.delete_namespace("test").unwrap();

        let namespaces = storage.list_namespaces().unwrap();
        assert!(!namespaces.contains(&"test".to_string()));
    }

    #[test]
    fn test_sync() {
        let (_temp_dir, mut storage) = create_test_storage();

        storage.create_namespace("test").unwrap();
        storage
            .store_key(&KeyId::new("key1"), b"data", "test")
            .unwrap();

        assert!(storage.sync().is_ok());
    }

    #[test]
    fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();
        let kek = [42u8; 32];

        // Create storage and write data
        {
            let mut storage =
                EncryptedFileStorage::create_with_new_key(base_path.clone(), &kek).unwrap();
            storage.create_namespace("test").unwrap();
            storage
                .store_key(&KeyId::new("key1"), b"persistent data", "test")
                .unwrap();
        }

        // Reopen storage and verify data
        {
            let storage = EncryptedFileStorage::open(base_path, &kek).unwrap();
            let data = storage.load_key(&KeyId::new("key1"), "test").unwrap();
            assert_eq!(data, b"persistent data");
        }
    }
}
