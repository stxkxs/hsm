//! Async Storage Backend
//!
//! Provides async I/O operations using tokio for non-blocking storage operations.

use crate::backend::{StorageError, StorageResult};
use crate::checksum::KeyMetadata;
use crate::master_key::{EncryptedData, MasterKey};
use crate::KeyId;
use std::path::{Path, PathBuf};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

/// File extension for encrypted key files
const KEY_FILE_EXT: &str = "enc";

/// File extension for metadata files
///
/// Retained only to recognize and clean up legacy split-file records written by
/// an earlier two-rename layout. New writes store metadata inline in the `.enc`
/// record (see [`COMBINED_RECORD_MAGIC`]) so a key and its metadata are made
/// durable with a SINGLE atomic rename.
const META_FILE_EXT: &str = "meta";

/// Magic prefix identifying a combined (metadata + ciphertext) key record.
///
/// Finding #29: the original layout wrote the key and its metadata to two
/// separate files with two independent renames. A crash between the renames
/// left a (new-key, old-meta) window with no WAL/recovery. The combined record
/// packs metadata and ciphertext into a single file persisted with ONE rename,
/// so a key is either fully present (with matching metadata) or absent — never
/// torn. The 4-byte magic distinguishes the new format from any legacy
/// raw-`EncryptedData` `.enc` file so `load_key` stays backward compatible.
const COMBINED_RECORD_MAGIC: &[u8; 4] = b"HSK1";

/// Async encrypted file storage implementation
///
/// This implementation provides:
/// - Non-blocking async I/O with tokio::fs
/// - Atomic writes (write-rename)
/// - fsync for durability
/// - Optimized I/O buffer sizes
pub struct AsyncFileStorage {
    /// Master encryption key
    master_key: MasterKey,
    /// Base directory for storage
    base_path: PathBuf,
}

impl AsyncFileStorage {
    /// Create a new async file storage
    ///
    /// # Arguments
    ///
    /// * `base_path` - Base directory for all storage
    /// * `master_key` - Master encryption key
    pub async fn new(base_path: PathBuf, master_key: MasterKey) -> StorageResult<Self> {
        // Create base directory structure
        fs::create_dir_all(&base_path).await?;
        let namespaces_path = base_path.join("namespaces");
        fs::create_dir_all(&namespaces_path).await?;

        Ok(Self {
            master_key,
            base_path,
        })
    }

    /// Create storage with a generated master key
    pub async fn create_with_new_key(base_path: PathBuf, kek: &[u8; 32]) -> StorageResult<Self> {
        let master_key = MasterKey::generate();
        let master_key_path = base_path.join("master_key.enc");

        // Create parent directory
        if let Some(parent) = master_key_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Save the master key (using sync I/O for simplicity)
        master_key.save(&master_key_path, kek)?;

        Self::new(base_path, master_key).await
    }

    /// Open existing storage with a saved master key
    pub async fn open(base_path: PathBuf, kek: &[u8; 32]) -> StorageResult<Self> {
        let master_key_path = base_path.join("master_key.enc");
        let master_key = MasterKey::load(&master_key_path, kek)?;
        Self::new(base_path, master_key).await
    }

    /// Get path to namespace directory
    fn get_namespace_path(&self, namespace: &str) -> PathBuf {
        self.base_path.join("namespaces").join(namespace)
    }

    /// Get path to keys directory for a namespace
    fn get_keys_path(&self, namespace: &str) -> PathBuf {
        self.get_namespace_path(namespace).join("keys")
    }

    /// Get path to encrypted key file
    fn get_key_file_path(&self, namespace: &str, key_id: &KeyId) -> PathBuf {
        self.get_keys_path(namespace)
            .join(format!("key-{}.{}", key_id, KEY_FILE_EXT))
    }

    /// Get path to metadata file
    fn get_meta_file_path(&self, namespace: &str, key_id: &KeyId) -> PathBuf {
        self.get_keys_path(namespace)
            .join(format!("key-{}.{}", key_id, META_FILE_EXT))
    }

    /// Encode a combined key record: magic + framed metadata + ciphertext.
    ///
    /// Layout (all integers little-endian):
    /// ```text
    /// | "HSK1" (4) | meta_len: u32 (4) | metadata (meta_len) | ciphertext |
    /// ```
    /// This single self-describing blob lets a key and its integrity metadata be
    /// made durable with ONE atomic rename (finding #29).
    fn encode_combined_record(meta_bytes: &[u8], encrypted_bytes: &[u8]) -> StorageResult<Vec<u8>> {
        let meta_len: u32 = meta_bytes
            .len()
            .try_into()
            .map_err(|_| StorageError::Serialization("metadata too large to frame".to_string()))?;
        let mut record = Vec::with_capacity(4 + 4 + meta_bytes.len() + encrypted_bytes.len());
        record.extend_from_slice(COMBINED_RECORD_MAGIC);
        record.extend_from_slice(&meta_len.to_le_bytes());
        record.extend_from_slice(meta_bytes);
        record.extend_from_slice(encrypted_bytes);
        Ok(record)
    }

    /// Decode a combined key record produced by [`Self::encode_combined_record`].
    ///
    /// Returns `Some((metadata, ciphertext))` if `bytes` is a well-formed
    /// combined record, or `None` if it does not carry the combined-record magic
    /// (i.e. a legacy raw-`EncryptedData` `.enc` file). A record that carries the
    /// magic but is truncated/garbled is reported as corruption rather than
    /// silently mis-parsed.
    fn decode_combined_record(bytes: &[u8]) -> StorageResult<Option<(KeyMetadata, Vec<u8>)>> {
        if bytes.len() < 4 || &bytes[..4] != COMBINED_RECORD_MAGIC {
            return Ok(None);
        }
        if bytes.len() < 8 {
            return Err(StorageError::CorruptionDetected(
                "combined record truncated before metadata length".to_string(),
            ));
        }
        let meta_len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let meta_start: usize = 8;
        let meta_end = meta_start
            .checked_add(meta_len)
            .filter(|&end| end <= bytes.len())
            .ok_or_else(|| {
                StorageError::CorruptionDetected(
                    "combined record metadata length exceeds file size".to_string(),
                )
            })?;
        let metadata: KeyMetadata =
            postcard::from_bytes(&bytes[meta_start..meta_end]).map_err(|e| {
                StorageError::Serialization(format!("Failed to deserialize metadata: {}", e))
            })?;
        let ciphertext = bytes[meta_end..].to_vec();
        Ok(Some((metadata, ciphertext)))
    }

    /// fsync a directory so a preceding rename/create within it is durable.
    ///
    /// A rename is only crash-atomic once the directory entry change itself is
    /// persisted; without fsyncing the parent, a crash can lose the rename even
    /// though the file contents were `sync_all`'d.
    async fn fsync_dir(path: &Path) -> StorageResult<()> {
        // Opening a directory for read and calling sync_all flushes its entries.
        let dir = File::open(path).await?;
        dir.sync_all().await?;
        Ok(())
    }

    /// Store a key asynchronously with atomic write
    ///
    /// Finding #29: the key's ciphertext AND its integrity metadata are packed
    /// into a SINGLE combined record (see `COMBINED_RECORD_MAGIC`) and made
    /// durable with ONE `fsync` + ONE atomic rename, followed by an `fsync` of
    /// the parent directory. A crash can therefore only leave the key fully
    /// present (with matching inline metadata) or fully absent — never the
    /// torn (new-key, old-meta) state the previous two-rename layout allowed.
    pub async fn store_key(
        &self,
        key_id: &KeyId,
        data: &[u8],
        namespace: &str,
    ) -> StorageResult<()> {
        // Ensure namespace and keys directory exists
        let keys_path = self.get_keys_path(namespace);
        fs::create_dir_all(&keys_path).await?;

        // Encrypt the data
        let encrypted = self.master_key.encrypt(data)?;

        // Serialize encrypted data
        let encrypted_bytes = postcard::to_allocvec(&encrypted).map_err(|e| {
            StorageError::Serialization(format!("Failed to serialize encrypted data: {}", e))
        })?;

        // Create metadata over the ciphertext.
        let metadata = KeyMetadata::new(&encrypted_bytes);
        let meta_bytes = postcard::to_allocvec(&metadata).map_err(|e| {
            StorageError::Serialization(format!("Failed to serialize metadata: {}", e))
        })?;

        // Build the single combined record (metadata framed ahead of ciphertext).
        let record = Self::encode_combined_record(&meta_bytes, &encrypted_bytes)?;

        let key_path = self.get_key_file_path(namespace, key_id);
        let temp_key_path = key_path.with_extension(format!("{KEY_FILE_EXT}.tmp"));

        // Write the combined record to a temp file and fsync its contents.
        let mut key_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_key_path)
            .await?;
        key_file.write_all(&record).await?;
        key_file.sync_all().await?;
        drop(key_file);

        // Single atomic rename publishes key + metadata together.
        fs::rename(&temp_key_path, &key_path).await?;

        // fsync the parent directory so the rename itself is durable across a crash.
        Self::fsync_dir(&keys_path).await?;

        // Remove any stale legacy split-metadata file so a future loader cannot
        // pick up out-of-date metadata. The combined record is authoritative.
        let legacy_meta_path = self.get_meta_file_path(namespace, key_id);
        if fs::try_exists(&legacy_meta_path).await.unwrap_or(false) {
            let _ = fs::remove_file(&legacy_meta_path).await;
        }

        // Set restrictive file permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_path).await?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_path, perms).await?;
        }

        Ok(())
    }

    /// Load a key asynchronously
    ///
    /// Finding #29: new records are combined (inline metadata + ciphertext) and
    /// are read with a single file open. The inline metadata is always present
    /// and verified, so there is no (new-key, old-meta) torn-read window.
    /// Legacy split-file records (raw `EncryptedData` `.enc` plus an optional
    /// separate `.meta`) are still read for backward compatibility; a legacy
    /// record whose `.meta` is missing/partial is treated as consistent
    /// (verification skipped) rather than failing, since such records predate
    /// the inline-metadata format and are recoverable from the ciphertext alone.
    pub async fn load_key(&self, key_id: &KeyId, namespace: &str) -> StorageResult<Vec<u8>> {
        let key_path = self.get_key_file_path(namespace, key_id);

        // Read the on-disk record (combined or legacy).
        let mut file_bytes = Vec::new();
        File::open(&key_path)
            .await?
            .read_to_end(&mut file_bytes)
            .await?;

        // Prefer the combined format: metadata is inline and authoritative.
        if let Some((metadata, encrypted_bytes)) = Self::decode_combined_record(&file_bytes)? {
            // Verify integrity against the inline metadata.
            metadata.verify(&encrypted_bytes)?;

            let encrypted: EncryptedData = postcard::from_bytes(&encrypted_bytes).map_err(|e| {
                StorageError::Serialization(format!("Failed to deserialize encrypted data: {}", e))
            })?;
            return self.master_key.decrypt(&encrypted);
        }

        // Legacy split-file path: the `.enc` is a raw serialized EncryptedData,
        // with integrity metadata (if any) in a separate `.meta` file.
        let encrypted_bytes = file_bytes;
        let meta_path = self.get_meta_file_path(namespace, key_id);
        if fs::try_exists(&meta_path).await.unwrap_or(false) {
            let mut meta_bytes = Vec::new();
            File::open(&meta_path)
                .await?
                .read_to_end(&mut meta_bytes)
                .await?;

            // A missing/partial legacy metadata file is treated as recoverable:
            // only verify when the metadata deserializes cleanly.
            if let Ok(metadata) = postcard::from_bytes::<KeyMetadata>(&meta_bytes) {
                metadata.verify(&encrypted_bytes)?;
            }
        }

        let encrypted: EncryptedData = postcard::from_bytes(&encrypted_bytes).map_err(|e| {
            StorageError::Serialization(format!("Failed to deserialize encrypted data: {}", e))
        })?;

        self.master_key.decrypt(&encrypted)
    }

    /// Securely delete a key with multi-pass overwrite
    ///
    /// Implements DoD 5220.22-M 3-pass wipe:
    /// 1. Random data
    /// 2. Zeros
    /// 3. Ones
    pub async fn secure_delete(&self, key_id: &KeyId, namespace: &str) -> StorageResult<()> {
        let key_path = self.get_key_file_path(namespace, key_id);
        let meta_path = self.get_meta_file_path(namespace, key_id);

        // Secure delete the key file
        if key_path.exists() {
            self.secure_delete_file(&key_path).await?;
        }

        // Secure delete the metadata file
        if meta_path.exists() {
            self.secure_delete_file(&meta_path).await?;
        }

        Ok(())
    }

    /// Securely delete a single file with multi-pass overwrite
    async fn secure_delete_file(&self, path: &Path) -> StorageResult<()> {
        use rand::RngCore;

        // Get file size
        let metadata = fs::metadata(path).await?;
        let file_size = metadata.len() as usize;

        // Open file for overwriting
        let mut file = OpenOptions::new().write(true).open(path).await?;

        // Pass 1: Overwrite with random data
        let mut random_data = vec![0u8; file_size];
        rand::rngs::OsRng.fill_bytes(&mut random_data);
        file.seek(SeekFrom::Start(0)).await?;
        file.write_all(&random_data).await?;
        file.sync_all().await?;

        // Pass 2: Overwrite with zeros
        file.seek(SeekFrom::Start(0)).await?;
        let zeros = vec![0u8; file_size];
        file.write_all(&zeros).await?;
        file.sync_all().await?;

        // Pass 3: Overwrite with ones
        file.seek(SeekFrom::Start(0)).await?;
        let ones = vec![0xFFu8; file_size];
        file.write_all(&ones).await?;
        file.sync_all().await?;

        // Drop file handle and delete
        drop(file);
        fs::remove_file(path).await?;

        Ok(())
    }

    /// Create a namespace
    pub async fn create_namespace(&self, namespace: &str) -> StorageResult<()> {
        let namespace_path = self.get_namespace_path(namespace);

        // Create namespace and keys directories
        fs::create_dir_all(&namespace_path).await?;
        fs::create_dir_all(self.get_keys_path(namespace)).await?;

        // Set restrictive directory permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&namespace_path).await?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&namespace_path, perms).await?;
        }

        Ok(())
    }

    /// Delete a namespace
    pub async fn delete_namespace(&self, namespace: &str) -> StorageResult<()> {
        let namespace_path = self.get_namespace_path(namespace);
        if !namespace_path.exists() {
            return Err(StorageError::NamespaceNotFound(namespace.to_string()));
        }

        fs::remove_dir_all(&namespace_path).await?;
        Ok(())
    }

    /// List all keys in a namespace
    pub async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<KeyId>> {
        let keys_path = self.get_keys_path(namespace);

        if !keys_path.exists() {
            return Err(StorageError::NamespaceNotFound(namespace.to_string()));
        }

        let mut keys = Vec::new();
        let mut entries = fs::read_dir(&keys_path).await?;

        while let Some(entry) = entries.next_entry().await? {
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

    /// Check if a key exists
    pub async fn key_exists(&self, key_id: &KeyId, namespace: &str) -> StorageResult<bool> {
        let key_path = self.get_key_file_path(namespace, key_id);
        Ok(key_path.exists())
    }

    /// List all namespaces
    pub async fn list_namespaces(&self) -> StorageResult<Vec<String>> {
        let namespaces_path = self.base_path.join("namespaces");

        if !namespaces_path.exists() {
            return Ok(Vec::new());
        }

        let mut namespaces = Vec::new();
        let mut entries = fs::read_dir(&namespaces_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                namespaces.push(entry.file_name().to_string_lossy().to_string());
            }
        }

        Ok(namespaces)
    }

    /// Batch read keys in parallel
    pub async fn read_keys_batch(
        &self,
        key_ids: &[KeyId],
        namespace: &str,
    ) -> StorageResult<Vec<Vec<u8>>> {
        use futures::future::try_join_all;

        // Create futures for all reads
        let futures: Vec<_> = key_ids
            .iter()
            .map(|id| self.load_key(id, namespace))
            .collect();

        // Execute all reads in parallel
        try_join_all(futures).await
    }

    /// Batch write keys in parallel
    pub async fn write_keys_batch(
        &self,
        keys: &[(KeyId, Vec<u8>)],
        namespace: &str,
    ) -> StorageResult<()> {
        use futures::future::try_join_all;

        // Create futures for all writes
        let futures: Vec<_> = keys
            .iter()
            .map(|(id, data)| self.store_key(id, data, namespace))
            .collect();

        // Execute all writes in parallel
        try_join_all(futures).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_store_and_load_key() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();
        let kek = [42u8; 32];

        let storage = AsyncFileStorage::create_with_new_key(base_path.clone(), &kek)
            .await
            .unwrap();

        storage.create_namespace("test").await.unwrap();

        let key_id = KeyId::new("test-key-1");
        let data = b"secret key material";

        storage.store_key(&key_id, data, "test").await.unwrap();

        let loaded = storage.load_key(&key_id, "test").await.unwrap();
        assert_eq!(loaded, data);

        // Explicitly keep temp_dir alive
        drop(temp_dir);
    }

    #[tokio::test]
    async fn test_secure_delete() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();
        let kek = [42u8; 32];
        let storage = AsyncFileStorage::create_with_new_key(base_path, &kek)
            .await
            .unwrap();

        storage.create_namespace("test").await.unwrap();

        let key_id = KeyId::new("test-key-1");
        let data = b"secret key material";

        storage.store_key(&key_id, data, "test").await.unwrap();
        assert!(storage.key_exists(&key_id, "test").await.unwrap());

        storage.secure_delete(&key_id, "test").await.unwrap();
        assert!(!storage.key_exists(&key_id, "test").await.unwrap());

        drop(temp_dir);
    }

    #[tokio::test]
    async fn test_batch_operations() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();
        let kek = [42u8; 32];
        let storage = AsyncFileStorage::create_with_new_key(base_path, &kek)
            .await
            .unwrap();

        storage.create_namespace("test").await.unwrap();

        // Batch write
        let keys = vec![
            (KeyId::new("key1"), b"data1".to_vec()),
            (KeyId::new("key2"), b"data2".to_vec()),
            (KeyId::new("key3"), b"data3".to_vec()),
        ];

        storage.write_keys_batch(&keys, "test").await.unwrap();

        // Batch read
        let key_ids = vec![KeyId::new("key1"), KeyId::new("key2"), KeyId::new("key3")];
        let results = storage.read_keys_batch(&key_ids, "test").await.unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0], b"data1");
        assert_eq!(results[1], b"data2");
        assert_eq!(results[2], b"data3");

        drop(temp_dir);
    }

    #[tokio::test]
    async fn test_list_keys() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();
        let kek = [42u8; 32];
        let storage = AsyncFileStorage::create_with_new_key(base_path, &kek)
            .await
            .unwrap();

        storage.create_namespace("test").await.unwrap();

        storage
            .store_key(&KeyId::new("key1"), b"data1", "test")
            .await
            .unwrap();
        storage
            .store_key(&KeyId::new("key2"), b"data2", "test")
            .await
            .unwrap();
        storage
            .store_key(&KeyId::new("key3"), b"data3", "test")
            .await
            .unwrap();

        let keys = storage.list_keys("test").await.unwrap();
        assert_eq!(keys.len(), 3);

        drop(temp_dir);
    }

    #[tokio::test]
    async fn test_atomic_write() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();
        let kek = [42u8; 32];
        let storage = AsyncFileStorage::create_with_new_key(base_path, &kek)
            .await
            .unwrap();

        storage.create_namespace("test").await.unwrap();

        let key_id = KeyId::new("test-key");
        let data = b"initial data";

        // Write initial data
        storage.store_key(&key_id, data, "test").await.unwrap();

        // Overwrite with new data (should be atomic)
        let new_data = b"updated data";
        storage.store_key(&key_id, new_data, "test").await.unwrap();

        // Should read the new data
        let loaded = storage.load_key(&key_id, "test").await.unwrap();
        assert_eq!(loaded, new_data);

        drop(temp_dir);
    }

    // ---- Regression tests for finding #29: single-rename combined record ----

    /// The combined record is persisted as a SINGLE `.enc` file carrying the
    /// magic header, with NO separate `.meta` file. This proves there is no
    /// second rename that could leave a (new-key, old-meta) crash window: the
    /// key and its integrity metadata live in one atomically-renamed file.
    #[tokio::test]
    async fn test_store_writes_single_combined_record_no_separate_meta() {
        let temp_dir = TempDir::new().unwrap();
        let kek = [42u8; 32];
        let storage = AsyncFileStorage::create_with_new_key(temp_dir.path().to_path_buf(), &kek)
            .await
            .unwrap();
        storage.create_namespace("test").await.unwrap();

        let key_id = KeyId::new("combined-key");
        let data = b"secret key material";
        storage.store_key(&key_id, data, "test").await.unwrap();

        // The .enc file exists and begins with the combined-record magic.
        let key_path = storage.get_key_file_path("test", &key_id);
        let bytes = std::fs::read(&key_path).unwrap();
        assert!(
            bytes.starts_with(COMBINED_RECORD_MAGIC),
            "key file must be a combined record (magic prefix)"
        );

        // There is NO separate .meta file — metadata is inline.
        let meta_path = storage.get_meta_file_path("test", &key_id);
        assert!(
            !meta_path.exists(),
            "combined layout must not write a separate .meta file"
        );

        // No leftover temp file.
        let temp_key_path = key_path.with_extension(format!("{KEY_FILE_EXT}.tmp"));
        assert!(!temp_key_path.exists(), "temp file must be renamed away");

        // Round-trips correctly using only the single file.
        let loaded = storage.load_key(&key_id, "test").await.unwrap();
        assert_eq!(loaded, data);
    }

    /// Loading must NOT depend on any external metadata file: deleting the
    /// (nonexistent) legacy `.meta` is irrelevant because the metadata is inline.
    /// This is the crux of finding #29 — there is no window where the key exists
    /// but its metadata is stale/absent. We assert the key loads from the `.enc`
    /// file alone.
    #[tokio::test]
    async fn test_load_succeeds_from_combined_record_alone() {
        let temp_dir = TempDir::new().unwrap();
        let kek = [42u8; 32];
        let storage = AsyncFileStorage::create_with_new_key(temp_dir.path().to_path_buf(), &kek)
            .await
            .unwrap();
        storage.create_namespace("test").await.unwrap();

        let key_id = KeyId::new("k");
        let data = b"payload bytes that round-trip";
        storage.store_key(&key_id, data, "test").await.unwrap();

        // Even after explicitly ensuring no .meta exists, load works.
        let meta_path = storage.get_meta_file_path("test", &key_id);
        let _ = std::fs::remove_file(&meta_path);
        assert!(!meta_path.exists());

        let loaded = storage.load_key(&key_id, "test").await.unwrap();
        assert_eq!(loaded, data);
    }

    /// Negative test: tampering with the ciphertext portion of a combined record
    /// is detected by the inline metadata's checksum and rejected — proving the
    /// inline metadata is actually verified (not shape-only).
    #[tokio::test]
    async fn test_tampered_combined_record_is_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let kek = [42u8; 32];
        let storage = AsyncFileStorage::create_with_new_key(temp_dir.path().to_path_buf(), &kek)
            .await
            .unwrap();
        storage.create_namespace("test").await.unwrap();

        let key_id = KeyId::new("victim");
        storage
            .store_key(&key_id, b"original secret", "test")
            .await
            .unwrap();

        let key_path = storage.get_key_file_path("test", &key_id);
        let mut bytes = std::fs::read(&key_path).unwrap();
        // Flip a byte in the trailing ciphertext (last byte) without touching the
        // framed metadata, so the checksum over the ciphertext no longer matches.
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&key_path, &bytes).unwrap();

        let result = storage.load_key(&key_id, "test").await;
        assert!(
            matches!(result, Err(StorageError::CorruptionDetected(_))),
            "tampered combined record must be rejected as corruption, got {result:?}"
        );
    }

    /// A combined record whose framed metadata length is impossible (exceeds the
    /// file) is reported as corruption, not silently mis-parsed.
    #[test]
    fn test_decode_combined_record_rejects_bogus_length() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(COMBINED_RECORD_MAGIC);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // absurd meta_len
        bytes.extend_from_slice(b"short");
        let result = AsyncFileStorage::decode_combined_record(&bytes);
        assert!(matches!(result, Err(StorageError::CorruptionDetected(_))));
    }

    /// A non-combined (legacy-style) buffer is recognized as such (returns None),
    /// so the loader falls through to the legacy path rather than erroring.
    #[test]
    fn test_decode_combined_record_passes_through_legacy() {
        let legacy = b"\x00\x01\x02\x03 not a combined record";
        let result = AsyncFileStorage::decode_combined_record(legacy).unwrap();
        assert!(result.is_none());
    }
}
