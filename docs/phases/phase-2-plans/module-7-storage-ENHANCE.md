# Module 7: Storage Backend - Phase 2 Enhancements

## Current Status
- ✅ 1,888 lines of code
- ✅ Compiles successfully
- ✅ Basic encrypted file storage
- ✅ Key serialization/deserialization

## Performance Enhancements

### 1. Read Caching (Priority: CRITICAL)
**Goal**: < 100μs for cached reads, < 5ms for cold reads

**Tasks**:
- [ ] Implement LRU cache for hot keys
- [ ] Add write-through caching
- [ ] Cache key metadata separately
- [ ] Profile cache hit rates
- [ ] Benchmark read performance

**Caching architecture**:
```rust
use lru::LruCache;
use std::sync::Arc;
use dashmap::DashMap;

pub struct CachedStorage {
    // Hot key cache (LRU)
    key_cache: Arc<Mutex<LruCache<KeyId, Arc<EncryptedKey>>>>,

    // Metadata cache (lock-free)
    metadata_cache: Arc<DashMap<KeyId, KeyMetadata>>,

    // Backend storage
    backend: Box<dyn StorageBackend>,

    // Cache stats
    hits: AtomicU64,
    misses: AtomicU64,
}

impl CachedStorage {
    pub async fn read_key(&self, key_id: &KeyId) -> Result<Arc<EncryptedKey>> {
        // Check cache first
        if let Some(cached) = self.key_cache.lock().get(key_id) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(cached.clone());
        }

        // Cache miss - read from backend
        self.misses.fetch_add(1, Ordering::Relaxed);
        let key = self.backend.read(key_id).await?;
        let key_arc = Arc::new(key);

        // Update cache
        self.key_cache.lock().put(key_id.clone(), key_arc.clone());

        Ok(key_arc)
    }

    pub async fn write_key(&self, key: &EncryptedKey) -> Result<()> {
        // Write through to backend
        self.backend.write(key).await?;

        // Update cache
        let key_arc = Arc::new(key.clone());
        self.key_cache.lock().put(key.id.clone(), key_arc);

        Ok(())
    }
}
```

**Target**: 90%+ cache hit rate for typical workloads

### 2. Batch Operations (Priority: HIGH)
**Goal**: 10x improvement for bulk operations

**Tasks**:
- [ ] Implement batch read/write
- [ ] Use async/await for parallel I/O
- [ ] Optimize serialization for batches
- [ ] Profile batch performance
- [ ] Benchmark batch vs individual

**Batch operations**:
```rust
impl Storage {
    pub async fn read_keys_batch(&self, key_ids: &[KeyId]) -> Result<Vec<EncryptedKey>> {
        // Parallel reads
        let futures: Vec<_> = key_ids
            .iter()
            .map(|id| self.read_key(id))
            .collect();

        // Wait for all reads
        let results = futures::future::try_join_all(futures).await?;

        Ok(results)
    }

    pub async fn write_keys_batch(&self, keys: &[EncryptedKey]) -> Result<()> {
        // Parallel writes
        let futures: Vec<_> = keys
            .iter()
            .map(|key| self.write_key(key))
            .collect();

        futures::future::try_join_all(futures).await?;

        Ok(())
    }
}
```

**Expected gain**: 5-10x improvement for batch operations

### 3. Async I/O (Priority: HIGH)
**Goal**: Non-blocking storage operations

**Tasks**:
- [ ] Use tokio::fs for async file I/O
- [ ] Implement async read/write throughout
- [ ] Optimize I/O buffer sizes
- [ ] Profile I/O performance
- [ ] Benchmark sync vs async

**Async storage**:
```rust
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct AsyncFileStorage {
    data_dir: PathBuf,
}

impl AsyncFileStorage {
    pub async fn write_key(&self, key: &EncryptedKey) -> Result<()> {
        let path = self.key_path(&key.id);

        // Open file asynchronously
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await?;

        // Serialize key
        let bytes = bincode::serialize(key)?;

        // Write asynchronously
        file.write_all(&bytes).await?;

        // Ensure durability
        file.sync_all().await?;

        Ok(())
    }

    pub async fn read_key(&self, key_id: &KeyId) -> Result<EncryptedKey> {
        let path = self.key_path(key_id);

        // Read file asynchronously
        let mut file = File::open(&path).await?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await?;

        // Deserialize
        let key = bincode::deserialize(&bytes)?;

        Ok(key)
    }
}
```

### 4. Compression (Priority: MEDIUM)
**Goal**: Reduce storage footprint

**Tasks**:
- [ ] Add optional key compression (zstd)
- [ ] Benchmark compression ratios
- [ ] Measure compression overhead
- [ ] Add compression configuration
- [ ] Test decompression performance

**Compression**:
```rust
use zstd::stream::{encode_all, decode_all};

impl Storage {
    pub fn compress_key(&self, key: &EncryptedKey) -> Result<Vec<u8>> {
        let bytes = bincode::serialize(key)?;

        // Compress with zstd (fast compression, good ratio)
        let compressed = encode_all(&bytes[..], 3)?; // Level 3

        Ok(compressed)
    }

    pub fn decompress_key(&self, compressed: &[u8]) -> Result<EncryptedKey> {
        // Decompress
        let bytes = decode_all(compressed)?;

        // Deserialize
        let key = bincode::deserialize(&bytes)?;

        Ok(key)
    }
}
```

**Expected gain**: 30-50% storage reduction

### 5. Directory Sharding (Priority: MEDIUM)
**Goal**: Avoid filesystem bottlenecks

**Tasks**:
- [ ] Shard keys across multiple directories
- [ ] Use consistent hashing for sharding
- [ ] Optimize directory lookup
- [ ] Test with large key counts (1M+ keys)
- [ ] Benchmark sharding effectiveness

**Sharding**:
```rust
impl Storage {
    fn key_path(&self, key_id: &KeyId) -> PathBuf {
        // Hash key ID
        let hash = seahash::hash(key_id.as_bytes());

        // Shard into 256 directories (00-ff)
        let shard = (hash % 256) as u8;
        let shard_dir = format!("{:02x}", shard);

        // Path: data_dir/shard/key_id
        self.data_dir
            .join(shard_dir)
            .join(key_id.to_string())
    }
}
```

## Security Enhancements

### 1. Envelope Encryption Hardening (Priority: CRITICAL)
**Goal**: Secure key encryption at rest

**Tasks**:
- [ ] Verify DEK (Data Encryption Key) uniqueness per key
- [ ] Add KEK (Key Encryption Key) rotation
- [ ] Use AEAD for envelope encryption
- [ ] Add key wrapping tests
- [ ] Audit encryption implementation

**Envelope encryption**:
```rust
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use rand::rngs::OsRng;

pub struct EnvelopeEncryption {
    // Key Encryption Key (KEK) - master key
    kek: Key,
    cipher: Aes256Gcm,
}

impl EnvelopeEncryption {
    pub fn encrypt_key(&self, plaintext_key: &[u8]) -> Result<EncryptedKey> {
        // Generate unique DEK (Data Encryption Key)
        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);

        // Encrypt plaintext key with DEK
        let nonce_data = Nonce::from_slice(&[0u8; 12]); // Unique nonce
        let dek_cipher = Aes256Gcm::new(Key::from_slice(&dek));
        let encrypted_data = dek_cipher.encrypt(nonce_data, plaintext_key)
            .map_err(|_| StorageError::EncryptionFailed)?;

        // Wrap DEK with KEK
        let nonce_kek = Nonce::from_slice(&[0u8; 12]);
        let wrapped_dek = self.cipher.encrypt(nonce_kek, &dek[..])
            .map_err(|_| StorageError::EncryptionFailed)?;

        Ok(EncryptedKey {
            encrypted_data,
            wrapped_dek,
            nonce_data: nonce_data.to_vec(),
            nonce_kek: nonce_kek.to_vec(),
        })
    }

    pub fn decrypt_key(&self, encrypted: &EncryptedKey) -> Result<Vec<u8>> {
        // Unwrap DEK using KEK
        let nonce_kek = Nonce::from_slice(&encrypted.nonce_kek);
        let dek = self.cipher.decrypt(nonce_kek, &encrypted.wrapped_dek[..])
            .map_err(|_| StorageError::DecryptionFailed)?;

        // Decrypt data using DEK
        let nonce_data = Nonce::from_slice(&encrypted.nonce_data);
        let dek_cipher = Aes256Gcm::new(Key::from_slice(&dek));
        let plaintext = dek_cipher.decrypt(nonce_data, &encrypted.encrypted_data[..])
            .map_err(|_| StorageError::DecryptionFailed)?;

        Ok(plaintext)
    }
}
```

### 2. Secure Deletion (Priority: HIGH)
**Goal**: Cryptographically erase deleted keys

**Tasks**:
- [ ] Implement secure file deletion
- [ ] Overwrite key files before deletion
- [ ] Add multi-pass wiping (DoD 5220.22-M)
- [ ] Verify deletion with filesystem tools
- [ ] Test deletion effectiveness

**Secure deletion**:
```rust
use rand::RngCore;

impl Storage {
    pub async fn secure_delete(&self, key_id: &KeyId) -> Result<()> {
        let path = self.key_path(key_id);

        // Get file size
        let metadata = tokio::fs::metadata(&path).await?;
        let file_size = metadata.len() as usize;

        // Open file for overwriting
        let mut file = OpenOptions::new()
            .write(true)
            .open(&path)
            .await?;

        // Pass 1: Overwrite with random data
        let mut random_data = vec![0u8; file_size];
        OsRng.fill_bytes(&mut random_data);
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
        tokio::fs::remove_file(&path).await?;

        // Remove from cache
        self.key_cache.lock().pop(key_id);

        Ok(())
    }
}
```

### 3. File Permissions (Priority: HIGH)
**Goal**: Restrict file access

**Tasks**:
- [ ] Set restrictive file permissions (0600)
- [ ] Verify directory permissions (0700)
- [ ] Add permission checks
- [ ] Test permission enforcement
- [ ] Document permission model

**Permission enforcement**:
```rust
use std::os::unix::fs::PermissionsExt;

impl Storage {
    pub async fn write_key_secure(&self, key: &EncryptedKey) -> Result<()> {
        let path = self.key_path(&key.id);

        // Write key
        self.write_key_internal(&path, key).await?;

        // Set restrictive permissions (owner read/write only)
        let mut perms = tokio::fs::metadata(&path).await?.permissions();
        perms.set_mode(0o600);
        tokio::fs::set_permissions(&path, perms).await?;

        Ok(())
    }

    pub async fn init_storage_directory(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.data_dir).await?;

        // Set directory permissions (owner access only)
        let mut perms = tokio::fs::metadata(&self.data_dir).await?.permissions();
        perms.set_mode(0o700);
        tokio::fs::set_permissions(&self.data_dir, perms).await?;

        Ok(())
    }
}
```

### 4. Integrity Verification (Priority: HIGH)
**Goal**: Detect storage corruption

**Tasks**:
- [ ] Add checksums/HMAC to stored keys
- [ ] Verify integrity on read
- [ ] Add periodic integrity scans
- [ ] Test corruption detection
- [ ] Add corruption recovery

**Integrity protection**:
```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
pub struct IntegrityProtectedKey {
    encrypted_key: EncryptedKey,
    hmac: Vec<u8>,
}

impl Storage {
    pub fn add_integrity_protection(&self, key: &EncryptedKey) -> Result<IntegrityProtectedKey> {
        // Serialize encrypted key
        let bytes = bincode::serialize(key)?;

        // Compute HMAC
        let mut mac = HmacSha256::new_from_slice(&self.integrity_key)?;
        mac.update(&bytes);
        let hmac = mac.finalize().into_bytes().to_vec();

        Ok(IntegrityProtectedKey {
            encrypted_key: key.clone(),
            hmac,
        })
    }

    pub fn verify_integrity(&self, protected: &IntegrityProtectedKey) -> Result<()> {
        // Serialize encrypted key
        let bytes = bincode::serialize(&protected.encrypted_key)?;

        // Compute expected HMAC
        let mut mac = HmacSha256::new_from_slice(&self.integrity_key)?;
        mac.update(&bytes);

        // Verify HMAC
        mac.verify_slice(&protected.hmac)
            .map_err(|_| StorageError::IntegrityCheckFailed)?;

        Ok(())
    }
}
```

### 5. Backup Encryption (Priority: MEDIUM)
**Goal**: Encrypted backups

**Tasks**:
- [ ] Encrypt backup files
- [ ] Add backup integrity checks
- [ ] Implement backup versioning
- [ ] Test backup/restore
- [ ] Document backup procedures

## Reliability Enhancements

### 1. Write Durability (Priority: CRITICAL)
**Goal**: Never lose data on crash

**Tasks**:
- [ ] Use fsync after writes
- [ ] Implement write-ahead logging (WAL)
- [ ] Add atomic writes (write-rename)
- [ ] Test crash recovery
- [ ] Verify durability guarantees

**Atomic writes**:
```rust
impl Storage {
    pub async fn write_key_atomic(&self, key: &EncryptedKey) -> Result<()> {
        let final_path = self.key_path(&key.id);
        let temp_path = final_path.with_extension("tmp");

        // Write to temporary file
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .await?;

        let bytes = bincode::serialize(key)?;
        file.write_all(&bytes).await?;

        // Force to disk (CRITICAL for durability)
        file.sync_all().await?;
        drop(file);

        // Atomic rename
        tokio::fs::rename(&temp_path, &final_path).await?;

        Ok(())
    }
}
```

### 2. Error Recovery (Priority: HIGH)
**Goal**: Graceful error handling

**Tasks**:
- [ ] Add retry logic for transient errors
- [ ] Implement corruption recovery
- [ ] Add storage health checks
- [ ] Test error scenarios
- [ ] Document recovery procedures

### 3. Storage Quotas (Priority: MEDIUM)
**Goal**: Prevent storage exhaustion

**Tasks**:
- [ ] Implement per-namespace quotas
- [ ] Add storage usage tracking
- [ ] Enforce quota limits
- [ ] Add quota alerts
- [ ] Test quota enforcement

### 4. Monitoring (Priority: MEDIUM)
**Goal**: Observable storage

**Tasks**:
- [ ] Add metrics for read/write latency
- [ ] Track cache hit rates
- [ ] Monitor storage usage
- [ ] Add error rate metrics
- [ ] Alert on storage issues

## Testing Enhancements

### 1. Performance Tests (Priority: HIGH)
**Goal**: Meet performance targets

**Tasks**:
- [ ] Benchmark read/write latency
- [ ] Test cache effectiveness
- [ ] Benchmark batch operations
- [ ] Profile I/O performance
- [ ] Test with large datasets (1M+ keys)

### 2. Durability Tests (Priority: CRITICAL)
**Goal**: Verify no data loss

**Tasks**:
- [ ] Test crash recovery
- [ ] Verify fsync behavior
- [ ] Test atomic write correctness
- [ ] Test corruption detection
- [ ] Verify backup/restore

### 3. Security Tests (Priority: HIGH)
**Goal**: Verify encryption and deletion

**Tasks**:
- [ ] Test envelope encryption
- [ ] Verify secure deletion
- [ ] Test integrity protection
- [ ] Verify file permissions
- [ ] Audit encryption implementation

## Success Metrics

**Performance**:
- ✅ Read latency: < 100μs (cached), < 5ms (cold)
- ✅ Write latency: < 10ms p99
- ✅ Cache hit rate: > 90%
- ✅ Batch speedup: 5-10x

**Security**:
- ✅ All keys encrypted at rest
- ✅ Secure deletion verified
- ✅ Integrity checks pass
- ✅ File permissions enforced (0600)

**Reliability**:
- ✅ Zero data loss (durable writes)
- ✅ Crash recovery works
- ✅ Corruption detection works
- ✅ > 95% test coverage

## Claude Agent Instructions

1. Read this enhancement plan
2. Run existing tests to verify baseline
3. Implement LRU caching with high hit rates
4. Add async I/O throughout
5. Implement secure deletion
6. Add integrity protection
7. Verify performance targets
8. Test durability and crash recovery
9. Achieve all success metrics
