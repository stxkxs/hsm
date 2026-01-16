use lru::LruCache;
use parking_lot::RwLock;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cache entry with TTL
#[derive(Clone, Debug)]
struct CacheEntry<V> {
    value: V,
    expires_at: Instant,
}

impl<V> CacheEntry<V> {
    fn new(value: V, ttl: Duration) -> Self {
        Self {
            value,
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Thread-safe LRU cache with TTL support
pub struct TtlCache<K, V> {
    cache: Arc<RwLock<LruCache<K, CacheEntry<V>>>>,
    default_ttl: Duration,
}

impl<K: Hash + Eq, V: Clone> TtlCache<K, V> {
    /// Create a new TTL cache with specified capacity and default TTL
    pub fn new(capacity: usize, default_ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("Capacity must be non-zero"),
            ))),
            default_ttl,
        }
    }

    /// Insert a value with default TTL
    pub fn insert(&self, key: K, value: V) {
        self.insert_with_ttl(key, value, self.default_ttl);
    }

    /// Insert a value with custom TTL
    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        let entry = CacheEntry::new(value, ttl);
        self.cache.write().put(key, entry);
    }

    /// Get a value from cache if it exists and hasn't expired
    pub fn get(&self, key: &K) -> Option<V> {
        let mut cache = self.cache.write();

        // Get the entry
        let entry = cache.get(key)?;

        // Check if expired
        if entry.is_expired() {
            // Remove expired entry
            cache.pop(key);
            return None;
        }

        Some(entry.value.clone())
    }

    /// Remove a value from cache
    pub fn invalidate(&self, key: &K) {
        self.cache.write().pop(key);
    }

    /// Clear all entries from cache
    pub fn clear(&self) {
        self.cache.write().clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.read();
        CacheStats {
            size: cache.len(),
            capacity: cache.cap().get(),
        }
    }

    /// Remove expired entries (for background cleanup)
    pub fn cleanup_expired(&self)
    where
        K: Clone,
    {
        let mut cache = self.cache.write();
        let now = Instant::now();

        // Collect expired keys
        let expired_keys: Vec<K> = cache
            .iter()
            .filter(|(_, entry)| now >= entry.expires_at)
            .map(|(k, _)| (*k).clone())
            .collect();

        // Remove expired entries
        for key in expired_keys {
            cache.pop(&key);
        }
    }
}

impl<K: Hash + Eq, V: Clone> Clone for TtlCache<K, V> {
    fn clone(&self) -> Self {
        Self {
            cache: Arc::clone(&self.cache),
            default_ttl: self.default_ttl,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub size: usize,
    pub capacity: usize,
}

/// Cache key for read operations
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum CacheKey {
    GetKey {
        key_id: Vec<u8>,
        namespace: String,
    },
    VerifySignature {
        key_id: Vec<u8>,
        data_hash: [u8; 32],
        signature: Vec<u8>,
    },
}

/// Response cache for idempotent operations
pub struct ResponseCache {
    pub get_key_cache: TtlCache<CacheKey, Vec<u8>>,
    pub verify_cache: TtlCache<CacheKey, bool>,
}

impl ResponseCache {
    pub fn new() -> Self {
        Self {
            // Cache GetKey responses for 5 minutes (keys don't change frequently)
            get_key_cache: TtlCache::new(10000, Duration::from_secs(300)),
            // Cache verification results for 1 minute (signatures are deterministic)
            verify_cache: TtlCache::new(50000, Duration::from_secs(60)),
        }
    }

    /// Invalidate caches for a specific key (called on key updates/deletes)
    pub fn invalidate_key(&self, key_id: &[u8], namespace: &str) {
        // Invalidate get_key cache
        let key = CacheKey::GetKey {
            key_id: key_id.to_vec(),
            namespace: namespace.to_string(),
        };
        self.get_key_cache.invalidate(&key);

        // Note: We don't invalidate verify cache as signatures remain valid
        // even after key updates (public key doesn't change)
    }

    /// Cleanup expired entries from all caches
    pub fn cleanup_expired(&self) {
        self.get_key_cache.cleanup_expired();
        self.verify_cache.cleanup_expired();
    }

    /// Clear all caches
    pub fn clear_all(&self) {
        self.get_key_cache.clear();
        self.verify_cache.clear();
    }

    /// Get statistics for all caches
    pub fn stats(&self) -> ResponseCacheStats {
        ResponseCacheStats {
            get_key: self.get_key_cache.stats(),
            verify: self.verify_cache.stats(),
        }
    }
}

impl Default for ResponseCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ResponseCache {
    fn clone(&self) -> Self {
        Self {
            get_key_cache: self.get_key_cache.clone(),
            verify_cache: self.verify_cache.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResponseCacheStats {
    pub get_key: CacheStats,
    pub verify: CacheStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_cache_insert_and_get() {
        let cache = TtlCache::new(10, Duration::from_secs(60));
        cache.insert("key1", "value1");

        assert_eq!(cache.get(&"key1"), Some("value1"));
        assert_eq!(cache.get(&"nonexistent"), None);
    }

    #[test]
    fn test_ttl_cache_expiration() {
        let cache = TtlCache::new(10, Duration::from_secs(60));
        cache.insert_with_ttl("key1", "value1", Duration::from_millis(10));

        assert_eq!(cache.get(&"key1"), Some("value1"));

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        assert_eq!(cache.get(&"key1"), None);
    }

    #[test]
    fn test_ttl_cache_invalidate() {
        let cache = TtlCache::new(10, Duration::from_secs(60));
        cache.insert("key1", "value1");

        assert_eq!(cache.get(&"key1"), Some("value1"));

        cache.invalidate(&"key1");
        assert_eq!(cache.get(&"key1"), None);
    }

    #[test]
    fn test_ttl_cache_clear() {
        let cache = TtlCache::new(10, Duration::from_secs(60));
        cache.insert("key1", "value1");
        cache.insert("key2", "value2");

        cache.clear();

        assert_eq!(cache.get(&"key1"), None);
        assert_eq!(cache.get(&"key2"), None);
    }

    #[test]
    fn test_ttl_cache_lru_eviction() {
        let cache = TtlCache::new(2, Duration::from_secs(60));
        cache.insert("key1", "value1");
        cache.insert("key2", "value2");
        cache.insert("key3", "value3"); // Should evict key1

        assert_eq!(cache.get(&"key1"), None);
        assert_eq!(cache.get(&"key2"), Some("value2"));
        assert_eq!(cache.get(&"key3"), Some("value3"));
    }

    #[test]
    fn test_response_cache_invalidate_key() {
        let cache = ResponseCache::new();

        let key_id = b"test-key".to_vec();
        let namespace = "test";

        let cache_key = CacheKey::GetKey {
            key_id: key_id.clone(),
            namespace: namespace.to_string(),
        };

        cache.get_key_cache.insert(cache_key.clone(), vec![1, 2, 3]);
        assert!(cache.get_key_cache.get(&cache_key).is_some());

        cache.invalidate_key(&key_id, namespace);
        assert!(cache.get_key_cache.get(&cache_key).is_none());
    }

    #[test]
    fn test_cache_stats() {
        let cache = TtlCache::new(100, Duration::from_secs(60));
        cache.insert("key1", "value1");
        cache.insert("key2", "value2");

        let stats = cache.stats();
        assert_eq!(stats.size, 2);
        assert_eq!(stats.capacity, 100);
    }

    #[test]
    fn test_cleanup_expired() {
        let cache = TtlCache::new(10, Duration::from_secs(60));
        cache.insert_with_ttl("key1", "value1", Duration::from_millis(10));
        cache.insert_with_ttl("key2", "value2", Duration::from_secs(60));

        // Wait for key1 to expire
        std::thread::sleep(Duration::from_millis(20));

        cache.cleanup_expired();

        assert_eq!(cache.get(&"key1"), None);
        assert_eq!(cache.get(&"key2"), Some("value2"));
    }
}
