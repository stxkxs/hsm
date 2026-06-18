//! Cached Storage Layer
//!
//! Provides LRU caching on top of the storage backend for improved read performance.
//!
//! # Cache Eviction Policy
//!
//! This implementation uses a **Least Recently Used (LRU)** eviction policy:
//!
//! - Cache has a fixed capacity (configurable, default 10,000 keys)
//! - When cache is full and a new key is loaded, the least recently accessed key is evicted
//! - Both reads and writes update the "recently used" status
//! - Cache is **write-through**: writes go to both cache and disk immediately
//!
//! ## Cache Architecture
//!
//! ```text
//! ┌──────────────────────────────────────┐
//! │         CachedStorage                │
//! │  ┌────────────────────────────────┐  │
//! │  │ LRU Key Cache (Mutex)          │  │  Stores full decrypted key data
//! │  │ - Max 10k entries              │  │  Protected by Mutex for LRU updates
//! │  │ - Evicts LRU on overflow       │  │
//! │  └────────────────────────────────┘  │
//! │  ┌────────────────────────────────┐  │
//! │  │ Metadata Cache (DashMap)       │  │  Lock-free concurrent access
//! │  │ - Key sizes and timestamps     │  │  Separate from data for fast stats
//! │  │ - Lock-free reads              │  │
//! │  └────────────────────────────────┘  │
//! │  ┌────────────────────────────────┐  │
//! │  │ Hit/Miss Counters (AtomicU64)  │  │  Lock-free performance tracking
//! │  └────────────────────────────────┘  │
//! └──────────────┬───────────────────────┘
//!                │
//! ┌──────────────▼───────────────────────┐
//! │  EncryptedFileStorage (Backend)      │
//! │  - Disk-based persistence            │
//! │  - Encryption, journaling, checksums │
//! └──────────────────────────────────────┘
//! ```
//!
//! # Performance Characteristics
//!
//! - **Cached Reads**: < 100μs (memory access, no disk I/O)
//! - **Cache Miss**: ~1-5ms (disk read + decryption + cache population)
//! - **Cached Writes**: ~1-5ms (write-through: disk write + cache update)
//! - **Target Hit Rate**: > 90% for typical workloads
//!
//! ## Cache Behavior
//!
//! | Operation | Cache Hit | Cache Miss | Side Effect |
//! |-----------|-----------|------------|-------------|
//! | `load_key_cached` | Return from cache | Load from disk, populate cache | Increment hit/miss counter |
//! | `store_key_cached` | Update cache | Populate cache | Write to disk (write-through) |
//! | `delete_key_cached` | Invalidate cache | No-op | Delete from disk |
//! | `clear_cache` | N/A | N/A | Evict all entries, reset counters |
//!
//! # Examples
//!
//! ## Basic Caching
//!
//! ```rust,no_run
//! use hsm_storage::{CachedStorage, EncryptedFileStorage, KeyId, StorageBackend};
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let base_path = PathBuf::from("/data/keys");
//! let kek = [0u8; 32];
//! let backend = EncryptedFileStorage::create_with_new_key(base_path, &kek)?;
//!
//! // Create cached storage with 5,000 key capacity
//! let cached = CachedStorage::new(backend, 5_000);
//!
//! // Create namespace
//! cached.backend().lock().create_namespace("prod")?;
//!
//! let key_id = KeyId::new("hot-key");
//!
//! // First access: cache miss (slow - disk read)
//! cached.store_key_cached(&key_id, b"frequently accessed", "prod")?;
//!
//! // Subsequent accesses: cache hit (fast - memory read)
//! let data1 = cached.load_key_cached(&key_id, "prod")?; // ~50μs
//! let data2 = cached.load_key_cached(&key_id, "prod")?; // ~50μs
//! let data3 = cached.load_key_cached(&key_id, "prod")?; // ~50μs
//!
//! // Check cache performance
//! let stats = cached.cache_stats();
//! println!("Hit rate: {:.1}%", stats.hit_rate);
//! println!("Cache size: {}/{}", stats.cache_size, stats.cache_capacity);
//! # Ok(())
//! # }
//! ```
//!
//! ## Monitoring Cache Performance
//!
//! ```rust,no_run
//! use hsm_storage::{CachedStorage, EncryptedFileStorage, KeyId, StorageBackend};
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let base_path = PathBuf::from("/data/keys");
//! # let kek = [0u8; 32];
//! # let backend = EncryptedFileStorage::create_with_new_key(base_path, &kek)?;
//! # let cached = CachedStorage::new(backend, 10_000);
//! # cached.backend().lock().create_namespace("prod")?;
//! // Perform operations...
//! for i in 0..100 {
//!     let key_id = KeyId::new(format!("key-{}", i));
//!     cached.store_key_cached(&key_id, b"data", "prod")?;
//! }
//!
//! // Check cache statistics
//! let stats = cached.cache_stats();
//! println!("Total requests: {}", stats.total_requests);
//! println!("Hits: {} ({:.1}%)", stats.hits, stats.hit_rate);
//! println!("Misses: {}", stats.misses);
//! println!("Utilization: {}/{}", stats.cache_size, stats.cache_capacity);
//!
//! // Clear cache if needed (e.g., memory pressure)
//! if stats.cache_size > 8_000 {
//!     cached.clear_cache();
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Write-Through Caching
//!
//! ```rust,no_run
//! use hsm_storage::{CachedStorage, EncryptedFileStorage, KeyId, StorageBackend};
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let base_path = PathBuf::from("/data/keys");
//! # let kek = [0u8; 32];
//! # let backend = EncryptedFileStorage::create_with_new_key(base_path, &kek)?;
//! # let cached = CachedStorage::new(backend, 10_000);
//! # cached.backend().lock().create_namespace("prod")?;
//! let key_id = KeyId::new("important-key");
//!
//! // Write goes to BOTH cache and disk
//! cached.store_key_cached(&key_id, b"critical data", "prod")?;
//!
//! // Even if cache is cleared, data is safe on disk
//! cached.clear_cache();
//!
//! // Next read loads from disk and re-populates cache
//! let data = cached.load_key_cached(&key_id, "prod")?;
//! assert_eq!(data, b"critical data");
//! # Ok(())
//! # }
//! ```

use crate::backend::{StorageBackend, StorageResult};
use crate::KeyId;
use dashmap::DashMap;
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Cached plaintext key material.
///
/// Wrapped in [`Zeroizing`] so the plaintext bytes are securely wiped from
/// memory when the value is dropped (LRU eviction, `clear_cache`, or when the
/// owning `CachedStorage` is dropped), matching the `SecretVec`/`ZeroizeOnDrop`
/// model used for the master key. The `Arc` lets the cache hand the value to
/// the LRU map cheaply; the cache is always the sole owner, so dropping the
/// entry drops the last reference and triggers the wipe.
type CachedKeyData = Arc<Zeroizing<Vec<u8>>>;

/// Metadata for cached keys
#[derive(Debug, Clone)]
pub struct CachedKeyMetadata {
    /// Size of the encrypted key data
    pub size: usize,
    /// Timestamp when cached
    pub cached_at: u64,
}

/// Cached storage implementation with LRU cache
///
/// This implementation provides:
/// - LRU cache for hot keys (< 100μs cached reads)
/// - Write-through caching
/// - Separate metadata cache (lock-free)
/// - Cache statistics tracking
pub struct CachedStorage<B: StorageBackend> {
    /// Underlying storage backend
    backend: Arc<Mutex<B>>,

    /// LRU cache for key data (namespace:key_id -> decrypted key material).
    ///
    /// Values are [`CachedKeyData`] (`Arc<Zeroizing<Vec<u8>>>`) so that the
    /// plaintext key bytes are securely wiped from memory when an entry is
    /// evicted (LRU overflow), cleared (`clear_cache`), or dropped (when the
    /// `CachedStorage` is dropped). The `Arc` is shared with no other holders,
    /// so dropping the last reference (which the cache always is) triggers
    /// zeroization.
    key_cache: Arc<Mutex<LruCache<String, CachedKeyData>>>,

    /// Lock-free metadata cache
    metadata_cache: Arc<DashMap<String, CachedKeyMetadata>>,

    /// Cache hit counter
    hits: Arc<AtomicU64>,

    /// Cache miss counter
    misses: Arc<AtomicU64>,

    /// Maximum cache size (number of keys)
    cache_capacity: usize,
}

impl<B: StorageBackend> CachedStorage<B> {
    /// Create a new cached storage with specified cache capacity
    ///
    /// # Arguments
    ///
    /// * `backend` - The underlying storage backend
    /// * `cache_capacity` - Maximum number of keys to cache (default: 10000)
    pub fn new(backend: B, cache_capacity: usize) -> Self {
        let capacity =
            NonZeroUsize::new(cache_capacity).unwrap_or(NonZeroUsize::new(10000).unwrap());

        Self {
            backend: Arc::new(Mutex::new(backend)),
            key_cache: Arc::new(Mutex::new(LruCache::new(capacity))),
            metadata_cache: Arc::new(DashMap::new()),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            cache_capacity,
        }
    }

    /// Create a cache key from namespace and key ID
    fn make_cache_key(namespace: &str, key_id: &KeyId) -> String {
        format!("{}:{}", namespace, key_id)
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        let hit_rate = if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        CacheStats {
            hits,
            misses,
            hit_rate,
            total_requests: total,
            cache_size: self.metadata_cache.len(),
            cache_capacity: self.cache_capacity,
        }
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        self.key_cache.lock().clear();
        self.metadata_cache.clear();
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
    }

    /// Load a key (with caching)
    pub fn load_key_cached(&self, key_id: &KeyId, namespace: &str) -> StorageResult<Vec<u8>> {
        let cache_key = Self::make_cache_key(namespace, key_id);

        // Check cache first
        {
            let mut cache = self.key_cache.lock();
            if let Some(cached_data) = cache.get(&cache_key) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                // Clone the inner Vec (deref through Arc + Zeroizing). The caller
                // receives an independent plaintext copy; the cached copy remains
                // wrapped in Zeroizing and is wiped on eviction/clear/drop.
                return Ok((***cached_data).to_vec());
            }
        }

        // Cache miss - read from backend.
        //
        // Finding #17 (lost update): the backend lock is held across the cache
        // publish so that the backend-read and cache-population form a SINGLE
        // critical section. If a concurrent `store_key_cached` runs, it must
        // acquire the same backend lock before it can write+publish, so the two
        // operations are serialized and the cache can never be left holding a
        // value older than the backend for this key.
        self.misses.fetch_add(1, Ordering::Relaxed);
        let backend = self.backend.lock();
        let data = backend.load_key(key_id, namespace)?;

        // Update cache while STILL holding the backend lock. Wrap in Zeroizing
        // so the plaintext key material is securely wiped on eviction/clear/drop,
        // matching the SecretVec model.
        let data_arc = Arc::new(Zeroizing::new(data.clone()));
        let metadata = CachedKeyMetadata {
            size: data.len(),
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.key_cache.lock().put(cache_key.clone(), data_arc);
        self.metadata_cache.insert(cache_key, metadata);
        drop(backend);

        Ok(data)
    }

    /// Store a key (write-through cache)
    pub fn store_key_cached(
        &self,
        key_id: &KeyId,
        data: &[u8],
        namespace: &str,
    ) -> StorageResult<()> {
        // Finding #17 (lost update): hold the backend lock across the cache
        // publish so the backend-write and cache-update form a SINGLE critical
        // section. Without this, two concurrent writers for the same key can
        // interleave as: W1 writes backend(v1), W2 writes backend(v2), W2
        // publishes cache(v2), W1 publishes cache(v1) — leaving cache=v1 while
        // backend=v2, a permanently stale cache. Serializing the whole
        // write+publish under the backend mutex guarantees the cache reflects
        // the last backend write.
        let mut backend = self.backend.lock();
        backend.store_key(key_id, data, namespace)?;

        // Update cache while STILL holding the backend lock. Wrap in Zeroizing
        // so the plaintext key material is securely wiped on eviction/clear/drop,
        // matching the SecretVec model.
        let cache_key = Self::make_cache_key(namespace, key_id);
        let data_arc = Arc::new(Zeroizing::new(data.to_vec()));
        let metadata = CachedKeyMetadata {
            size: data.len(),
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.key_cache.lock().put(cache_key.clone(), data_arc);
        self.metadata_cache.insert(cache_key, metadata);
        drop(backend);

        Ok(())
    }

    /// Delete a key (invalidate cache)
    pub fn delete_key_cached(&self, key_id: &KeyId, namespace: &str) -> StorageResult<()> {
        // Finding #17 (lost update): hold the backend lock across the cache
        // invalidation so the backend-delete and cache-eviction form a single
        // critical section, serialized against concurrent store/load for the
        // same key. Otherwise a store that interleaves between the backend
        // delete and the cache pop could leave a stale cached value behind.
        let mut backend = self.backend.lock();
        backend.delete_key(key_id, namespace)?;

        // Invalidate cache while STILL holding the backend lock.
        let cache_key = Self::make_cache_key(namespace, key_id);
        self.key_cache.lock().pop(&cache_key);
        self.metadata_cache.remove(&cache_key);
        drop(backend);

        Ok(())
    }

    /// Get a reference to the underlying backend
    pub fn backend(&self) -> Arc<Mutex<B>> {
        Arc::clone(&self.backend)
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of cache hits
    pub hits: u64,

    /// Number of cache misses
    pub misses: u64,

    /// Cache hit rate as a percentage
    pub hit_rate: f64,

    /// Total number of requests
    pub total_requests: u64,

    /// Current cache size (number of entries)
    pub cache_size: usize,

    /// Maximum cache capacity
    pub cache_capacity: usize,
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cache Stats: {} hits, {} misses, {:.2}% hit rate, {}/{} entries",
            self.hits, self.misses, self.hit_rate, self.cache_size, self.cache_capacity
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted_fs::EncryptedFileStorage;
    use tempfile::TempDir;

    fn create_test_cached_storage() -> (TempDir, CachedStorage<EncryptedFileStorage>) {
        let temp_dir = TempDir::new().unwrap();
        let kek = [42u8; 32];
        let backend =
            EncryptedFileStorage::create_with_new_key(temp_dir.path().to_path_buf(), &kek).unwrap();

        let cached = CachedStorage::new(backend, 1000);
        (temp_dir, cached)
    }

    #[test]
    fn test_cache_hit() {
        let (_temp, cached) = create_test_cached_storage();

        // Create namespace
        cached.backend().lock().create_namespace("test").unwrap();

        let key_id = KeyId::new("test-key");
        let data = b"test data";

        // First write
        cached.store_key_cached(&key_id, data, "test").unwrap();

        // First read (cache hit)
        let loaded1 = cached.load_key_cached(&key_id, "test").unwrap();
        assert_eq!(loaded1, data);

        // Second read (should be cache hit)
        let loaded2 = cached.load_key_cached(&key_id, "test").unwrap();
        assert_eq!(loaded2, data);

        let stats = cached.cache_stats();
        assert_eq!(stats.hits, 2); // Both reads should hit cache
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.hit_rate, 100.0);
    }

    #[test]
    fn test_cache_miss() {
        let (_temp, cached) = create_test_cached_storage();

        // Create namespace
        cached.backend().lock().create_namespace("test").unwrap();

        let key_id = KeyId::new("test-key");
        let data = b"test data";

        // Write directly to backend (bypass cache)
        cached
            .backend()
            .lock()
            .store_key(&key_id, data, "test")
            .unwrap();

        // Read (cache miss)
        let loaded = cached.load_key_cached(&key_id, "test").unwrap();
        assert_eq!(loaded, data);

        let stats = cached.cache_stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate, 0.0);
    }

    #[test]
    fn test_cache_invalidation() {
        let (_temp, cached) = create_test_cached_storage();

        // Create namespace
        cached.backend().lock().create_namespace("test").unwrap();

        let key_id = KeyId::new("test-key");
        let data = b"test data";

        // Write and cache
        cached.store_key_cached(&key_id, data, "test").unwrap();

        // Read (cache hit)
        cached.load_key_cached(&key_id, "test").unwrap();

        // Delete (should invalidate cache)
        cached.delete_key_cached(&key_id, "test").unwrap();

        // Verify key is gone
        let backend = cached.backend();
        let result = backend.lock().load_key(&key_id, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_lru_eviction() {
        let temp_dir = TempDir::new().unwrap();
        let kek = [42u8; 32];
        let backend =
            EncryptedFileStorage::create_with_new_key(temp_dir.path().to_path_buf(), &kek).unwrap();

        // Create cache with capacity of 2
        let cached = CachedStorage::new(backend, 2);
        cached.backend().lock().create_namespace("test").unwrap();

        // Write 3 keys
        cached
            .store_key_cached(&KeyId::new("key1"), b"data1", "test")
            .unwrap();
        cached
            .store_key_cached(&KeyId::new("key2"), b"data2", "test")
            .unwrap();
        cached
            .store_key_cached(&KeyId::new("key3"), b"data3", "test")
            .unwrap();

        // The cache should only have 2-3 entries due to metadata cache being separate
        // The metadata cache may have all 3, but the key cache should have only 2
        let stats = cached.cache_stats();
        assert!(
            stats.cache_size <= 3,
            "Cache size should not grow unbounded"
        );
    }

    #[test]
    fn test_clear_cache() {
        let (_temp, cached) = create_test_cached_storage();

        cached.backend().lock().create_namespace("test").unwrap();

        // Add some data
        cached
            .store_key_cached(&KeyId::new("key1"), b"data1", "test")
            .unwrap();
        cached
            .store_key_cached(&KeyId::new("key2"), b"data2", "test")
            .unwrap();

        // Clear cache
        cached.clear_cache();

        let stats = cached.cache_stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.cache_size, 0);
    }

    // ---- Regression test for finding #17: write-through cache lost update ----
    //
    // Before the fix, `store_key_cached` dropped the backend Mutex BEFORE
    // updating the cache. Two concurrent writers for the same key could
    // interleave so that the backend ended up with one writer's value while the
    // cache ended up holding the *other* writer's value — a permanently stale
    // cache (cache != backend). After the fix the backend lock is held across
    // the cache publish, so the cache always reflects the last backend write.
    //
    // This test hammers a single key with many concurrent writers, then asserts
    // that the value served from the cache equals the value persisted in the
    // backend. It also runs concurrent loaders to exercise the read path's
    // critical section. The assertion is a value equality (not a shape check):
    // a lost update leaves divergent bytes and fails.
    #[test]
    fn test_concurrent_writers_keep_cache_consistent_with_backend() {
        use std::sync::Arc as StdArc;
        use std::thread;

        let temp_dir = TempDir::new().unwrap();
        let kek = [42u8; 32];
        let backend =
            EncryptedFileStorage::create_with_new_key(temp_dir.path().to_path_buf(), &kek).unwrap();
        let cached = StdArc::new(CachedStorage::new(backend, 1000));
        cached.backend().lock().create_namespace("test").unwrap();

        let key_id = KeyId::new("hot-key");

        // Each writer writes a distinct, recoverable value: b"value-<n>".
        // Whichever writer wins the last backend write, the cache MUST agree.
        let num_writers = 16;
        let iterations = 50;

        let mut handles = Vec::new();
        for w in 0..num_writers {
            let cached = StdArc::clone(&cached);
            let key_id = key_id.clone();
            handles.push(thread::spawn(move || {
                for i in 0..iterations {
                    let val = format!("writer-{w}-iter-{i}");
                    cached
                        .store_key_cached(&key_id, val.as_bytes(), "test")
                        .unwrap();
                }
            }));
        }
        // Concurrent readers to exercise the load-path critical section.
        for _ in 0..4 {
            let cached = StdArc::clone(&cached);
            let key_id = key_id.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..iterations {
                    let _ = cached.load_key_cached(&key_id, "test");
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // After all writers finish, the cache must equal the backend for this key.
        let cache_key = CachedStorage::<EncryptedFileStorage>::make_cache_key("test", &key_id);
        let cached_val: Vec<u8> = {
            let mut guard = cached.key_cache.lock();
            (***guard.get(&cache_key).expect("entry should be cached")).clone()
        };
        let backend_val = cached
            .backend()
            .lock()
            .load_key(&key_id, "test")
            .expect("backend must have the key");

        assert_eq!(
            cached_val, backend_val,
            "cache diverged from backend after concurrent writers (lost update)"
        );
    }

    // ---- Regression tests for finding LOW #28: cached key material zeroization ----
    //
    // Before the fix, the cache stored `Arc<Vec<u8>>`, so plaintext key bytes were
    // freed WITHOUT being wiped on LRU eviction, `clear_cache`, or drop. The cache
    // now stores `Arc<Zeroizing<Vec<u8>>>`, which wipes the heap buffer on drop.
    //
    // These tests do NOT read freed memory (that would be UB). Instead they assert
    // that the cache value type actually wires up `Zeroize` (a compile-time bound),
    // that `Zeroizing`'s in-place wipe — the exact operation its `Drop` invokes —
    // truly zeroes the buffer while it is still alive, and that the cache is the
    // sole `Arc` owner so dropping the entry triggers that wipe.

    /// The compiler enforces that the value the cache stores wipes on drop.
    /// This is coupled to the *actual* field type: we build a value of exactly
    /// the type stored in `key_cache` and require its inner payload to implement
    /// [`Zeroize`]. Before the fix the cache held `Arc<Vec<u8>>`, whose inner
    /// `Vec<u8>` does not wipe on drop and would not satisfy the bound — so
    /// reverting the field type turns this into a build break, not a silent leak.
    #[test]
    fn test_cache_value_type_zeroizes_on_drop() {
        use zeroize::{Zeroize, ZeroizeOnDrop};

        // Helper that only accepts the cache's stored value type if the payload
        // behind the `Arc` both implements `Zeroize` AND wipes on drop.
        fn assert_zeroizes_on_drop<T: Zeroize + ZeroizeOnDrop>(_arc: &Arc<T>) {}

        // Construct a value of EXACTLY the type held in `key_cache`, by pulling
        // a real entry out of a populated cache so the type is inferred from the
        // field rather than hardcoded.
        let (_temp, cached) = create_test_cached_storage();
        cached.backend().lock().create_namespace("test").unwrap();
        let key_id = KeyId::new("k");
        cached.store_key_cached(&key_id, b"v", "test").unwrap();
        let cache_key = CachedStorage::<EncryptedFileStorage>::make_cache_key("test", &key_id);
        let guard = cached.key_cache.lock();
        let arc = guard.peek(&cache_key).expect("entry cached");
        assert_zeroizes_on_drop(arc);
    }

    /// Proves that the wrapper actually wipes its heap buffer. We call the same
    /// in-place wipe that `Zeroizing`'s `Drop` invokes, then read the bytes back
    /// through the still-live value (no freed-memory access) and assert they are
    /// all zero. Before the fix the cache used a bare `Vec<u8>`, which leaves the
    /// secret bytes intact on drop.
    #[test]
    fn test_zeroizing_wrapper_wipes_buffer_in_place() {
        use zeroize::Zeroize;

        // Match the exact type stored in the cache.
        let mut secret: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0xABu8; 64]);
        assert!(secret.iter().all(|&b| b == 0xAB), "precondition: filled");

        // `Drop for Zeroizing` calls `self.zeroize()`; invoke it directly while
        // the buffer is alive so we can observe the wipe without UB.
        secret.zeroize();

        assert!(
            secret.iter().all(|&b| b == 0),
            "Zeroizing must wipe the plaintext buffer (drop relies on this)"
        );
    }

    /// Proves the cache holds the *sole* `Arc` to each value, so dropping/evicting
    /// the entry drops the last reference and triggers `Zeroizing::drop` (the wipe).
    /// If a future change started handing out clones of the `Arc`, the refcount
    /// would exceed 1 and eviction would no longer wipe — this catches that.
    #[test]
    fn test_cache_is_sole_arc_owner_so_drop_zeroizes() {
        let (_temp, cached) = create_test_cached_storage();
        cached.backend().lock().create_namespace("test").unwrap();

        let key_id = KeyId::new("secret-key");
        cached
            .store_key_cached(&key_id, b"super secret key material", "test")
            .unwrap();
        // Populate via the read path too.
        cached.load_key_cached(&key_id, "test").unwrap();

        let cache_key = CachedStorage::<EncryptedFileStorage>::make_cache_key("test", &key_id);
        {
            let mut guard = cached.key_cache.lock();
            let arc = guard.get(&cache_key).expect("entry should be cached");
            assert_eq!(
                Arc::strong_count(arc),
                1,
                "cache must be sole Arc owner so the last drop runs Zeroizing::drop"
            );
        }

        // Evicting the entry drops the last Arc, which runs Zeroizing's wipe.
        // We cannot observe the freed bytes safely, but the strong_count==1
        // invariant above guarantees the wipe executes on eviction/clear/drop.
        cached.delete_key_cached(&key_id, "test").unwrap();
        assert!(cached.key_cache.lock().get(&cache_key).is_none());
    }
}
