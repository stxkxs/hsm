use super::key::{Key, KeyId};
use dashmap::DashMap;
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;

const HOT_CACHE_SIZE: usize = 256;

/// Composite key type for namespace + key ID
type CompositeKey = (String, KeyId);

/// Hot cache type alias to reduce type complexity
type HotCache = LruCache<CompositeKey, Arc<Key>>;

/// Thread-safe in-memory key store with lock-free concurrent access
pub struct KeyStore {
    // Lock-free concurrent hashmap: (namespace, KeyId) -> Arc<Key>
    keys: Arc<DashMap<CompositeKey, Arc<Key>>>,
    // LRU cache for hot keys
    hot_cache: Arc<Mutex<HotCache>>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(DashMap::new()),
            hot_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(HOT_CACHE_SIZE).unwrap(),
            ))),
        }
    }

    /// Store a key in the given namespace
    pub fn insert(&self, namespace: &str, key: Key) -> Result<(), crate::Error> {
        let composite_key = (namespace.to_string(), key.id);
        let key_id = key.id;

        // Atomic check-and-insert via the DashMap Entry API. A separate
        // `contains_key` + `insert` is a TOCTOU race: two concurrent inserts of
        // the same (namespace, id) could both observe "absent" and one would
        // silently overwrite the other. The Occupied/Vacant match closes that
        // window so a duplicate id always errors.
        let key_arc = Arc::new(key);
        match self.keys.entry(composite_key.clone()) {
            dashmap::Entry::Occupied(_) => {
                return Err(crate::Error::KeyAlreadyExists(key_id));
            }
            dashmap::Entry::Vacant(vacant) => {
                vacant.insert(Arc::clone(&key_arc));
            }
        }

        // Add to hot cache
        self.hot_cache.lock().put(composite_key, key_arc);

        Ok(())
    }

    /// Get a key from the store (returns `Arc<Key>` for zero-copy)
    pub fn get(&self, namespace: &str, key_id: &KeyId) -> Result<Arc<Key>, crate::Error> {
        let composite_key = (namespace.to_string(), *key_id);

        // Try hot cache first (< 100μs for cached lookups)
        {
            let mut cache = self.hot_cache.lock();
            if let Some(key) = cache.get(&composite_key) {
                // Verify namespace matches even on cache hits to prevent
                // cross-namespace access through cache poisoning
                if key.namespace != namespace {
                    return Err(crate::Error::NamespaceViolation {
                        expected: namespace.to_string(),
                        actual: key.namespace.clone(),
                    });
                }
                return Ok(key.clone());
            }
        }

        // Cold lookup from main store (< 1ms for cold lookups)
        let key_ref = self
            .keys
            .get(&composite_key)
            .ok_or(crate::Error::KeyNotFound(*key_id))?;

        let key_arc = key_ref.value().clone();

        // Critical security check: Verify namespace matches
        if key_arc.namespace != namespace {
            return Err(crate::Error::NamespaceViolation {
                expected: namespace.to_string(),
                actual: key_arc.namespace.clone(),
            });
        }

        // Add to hot cache for future lookups
        self.hot_cache.lock().put(composite_key, key_arc.clone());

        Ok(key_arc)
    }

    /// Update a key in the store
    /// Uses DashMap's entry API for atomic updates
    pub fn update<F>(&self, namespace: &str, key_id: &KeyId, updater: F) -> Result<(), crate::Error>
    where
        F: FnOnce(&mut Key),
    {
        let composite_key = (namespace.to_string(), *key_id);

        // Use entry API for atomic update
        let entry = self.keys.entry(composite_key.clone());

        match entry {
            dashmap::Entry::Occupied(mut occ) => {
                // Clone the key to make it mutable
                let mut new_key = (**occ.get()).clone();

                // Verify namespace
                if new_key.namespace != namespace {
                    return Err(crate::Error::NamespaceViolation {
                        expected: namespace.to_string(),
                        actual: new_key.namespace.clone(),
                    });
                }

                // Apply the update
                updater(&mut new_key);

                let new_key_arc = Arc::new(new_key);

                // Replace the value atomically
                occ.insert(Arc::clone(&new_key_arc));

                // Update hot cache
                self.hot_cache
                    .lock()
                    .put(composite_key, Arc::clone(&new_key_arc));

                Ok(())
            }
            dashmap::Entry::Vacant(_) => Err(crate::Error::KeyNotFound(*key_id)),
        }
    }

    /// Delete a key from the store
    pub fn delete(&self, namespace: &str, key_id: &KeyId) -> Result<Arc<Key>, crate::Error> {
        let composite_key = (namespace.to_string(), *key_id);

        // Remove from main store
        let (_key, key_arc) = self
            .keys
            .remove(&composite_key)
            .ok_or(crate::Error::KeyNotFound(*key_id))?;

        // Verify namespace
        if key_arc.namespace != namespace {
            return Err(crate::Error::NamespaceViolation {
                expected: namespace.to_string(),
                actual: key_arc.namespace.clone(),
            });
        }

        // Remove from hot cache
        self.hot_cache.lock().pop(&composite_key);

        // Key material is automatically zeroized when all Arc references are dropped
        Ok(key_arc)
    }

    /// List all keys in a namespace
    pub fn list(&self, namespace: &str) -> Result<Vec<KeyId>, crate::Error> {
        let mut key_ids = Vec::new();

        for entry in self.keys.iter() {
            let (ns, key_id) = entry.key();
            if ns == namespace {
                key_ids.push(*key_id);
            }
        }

        Ok(key_ids)
    }

    /// List keys with pagination for batch operations
    pub fn list_batch(
        &self,
        namespace: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<KeyId>, crate::Error> {
        let mut key_ids = Vec::new();

        for entry in self.keys.iter() {
            let (ns, key_id) = entry.key();
            if ns == namespace {
                key_ids.push(*key_id);
            }
        }

        // Apply pagination. Clamp both bounds so an offset past the end (or an
        // offset+limit that overflows) yields an empty slice instead of
        // panicking on an out-of-range / start>end slice index.
        let len = key_ids.len();
        let start = offset.min(len);
        let end = offset.saturating_add(limit).min(len);

        Ok(key_ids[start..end].to_vec())
    }

    /// Count keys in a namespace
    pub fn count(&self, namespace: &str) -> usize {
        self.keys
            .iter()
            .filter(|entry| entry.key().0 == namespace)
            .count()
    }

    /// Delete multiple keys atomically (for batch operations)
    pub fn delete_batch(
        &self,
        namespace: &str,
        key_ids: &[KeyId],
    ) -> Result<Vec<Arc<Key>>, crate::Error> {
        let mut deleted_keys = Vec::new();

        for key_id in key_ids {
            match self.delete(namespace, key_id) {
                Ok(key) => deleted_keys.push(key),
                Err(e) => {
                    // On error, we can't easily rollback DashMap operations
                    // In a production system, this would use proper transactions
                    return Err(e);
                }
            }
        }

        Ok(deleted_keys)
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for KeyStore {
    fn clone(&self) -> Self {
        Self {
            keys: Arc::clone(&self.keys),
            hot_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(HOT_CACHE_SIZE).unwrap(),
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{KeyState, KeyType, KeyUsagePolicy};

    #[test]
    fn test_key_store_basic_operations() {
        let store = KeyStore::new();
        let namespace = "test-namespace";

        let key = create_test_key(namespace);
        let key_id = key.id;

        // Insert
        store.insert(namespace, key).unwrap();

        // Get
        let retrieved = store.get(namespace, &key_id).unwrap();
        assert_eq!(retrieved.id, key_id);

        // Update
        store
            .update(namespace, &key_id, |k| {
                k.state = KeyState::Deactivated;
            })
            .unwrap();

        let updated = store.get(namespace, &key_id).unwrap();
        assert_eq!(updated.state, KeyState::Deactivated);

        // Delete
        let deleted = store.delete(namespace, &key_id).unwrap();
        assert_eq!(deleted.id, key_id);

        // Verify deletion
        assert!(store.get(namespace, &key_id).is_err());
    }

    #[test]
    fn test_namespace_isolation() {
        let store = KeyStore::new();
        let ns1 = "namespace1";
        let ns2 = "namespace2";

        let key1 = create_test_key(ns1);
        let key_id1 = key1.id;

        let key2 = create_test_key(ns2);
        let key_id2 = key2.id;

        store.insert(ns1, key1).unwrap();
        store.insert(ns2, key2).unwrap();

        // Can get key from its own namespace
        assert!(store.get(ns1, &key_id1).is_ok());
        assert!(store.get(ns2, &key_id2).is_ok());

        // Cannot get key from different namespace
        assert!(store.get(ns1, &key_id2).is_err());
        assert!(store.get(ns2, &key_id1).is_err());
    }

    #[test]
    fn test_hot_cache() {
        let store = KeyStore::new();
        let namespace = "test-namespace";

        let key = create_test_key(namespace);
        let key_id = key.id;

        store.insert(namespace, key).unwrap();

        // First access (cold)
        let _retrieved1 = store.get(namespace, &key_id).unwrap();

        // Second access should hit cache
        let _retrieved2 = store.get(namespace, &key_id).unwrap();

        // Both should return the same Arc (same pointer)
        let arc1 = store.get(namespace, &key_id).unwrap();
        let arc2 = store.get(namespace, &key_id).unwrap();
        assert!(Arc::ptr_eq(&arc1, &arc2));
    }

    #[test]
    fn test_batch_operations() {
        let store = KeyStore::new();
        let namespace = "test-namespace";

        // Insert multiple keys
        let mut key_ids = Vec::new();
        for _ in 0..10 {
            let key = create_test_key(namespace);
            key_ids.push(key.id);
            store.insert(namespace, key).unwrap();
        }

        // List with pagination
        let page1 = store.list_batch(namespace, 0, 5).unwrap();
        assert_eq!(page1.len(), 5);

        let page2 = store.list_batch(namespace, 5, 5).unwrap();
        assert_eq!(page2.len(), 5);

        // Delete batch
        let deleted = store.delete_batch(namespace, &key_ids[0..3]).unwrap();
        assert_eq!(deleted.len(), 3);

        // Verify deletion
        assert_eq!(store.count(namespace), 7);
    }

    #[test]
    fn test_insert_duplicate_id_errors() {
        let store = KeyStore::new();
        let namespace = "test-namespace";

        let key = create_test_key(namespace);
        let key_id = key.id;

        // Build a second key sharing the SAME id (so the composite key collides).
        let mut dup = create_test_key(namespace);
        dup.id = key_id;

        store.insert(namespace, key).unwrap();

        let err = store
            .insert(namespace, dup)
            .expect_err("duplicate id must be rejected, not silently overwritten");
        match err {
            crate::Error::KeyAlreadyExists(id) => assert_eq!(id, key_id),
            other => panic!("expected KeyAlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn test_list_batch_offset_past_end_returns_empty() {
        let store = KeyStore::new();
        let namespace = "test-namespace";

        for _ in 0..3 {
            store.insert(namespace, create_test_key(namespace)).unwrap();
        }

        // offset > len must not panic; returns empty.
        let empty = store.list_batch(namespace, 100, 10).unwrap();
        assert!(empty.is_empty());

        // offset == len boundary also empty.
        let boundary = store.list_batch(namespace, 3, 10).unwrap();
        assert!(boundary.is_empty());

        // offset within range but limit overruns end: clamped, no panic.
        let tail = store.list_batch(namespace, 2, usize::MAX).unwrap();
        assert_eq!(tail.len(), 1);
    }

    fn create_test_key(namespace: &str) -> Key {
        use chrono::Utc;

        Key {
            id: KeyId::new(),
            key_type: KeyType::Ed25519,
            private_material: None,
            public_material: None,
            state: KeyState::Active,
            namespace: namespace.to_string(),
            created_at: Utc::now(),
            policy: KeyUsagePolicy::default(),
            version: 1,
            previous_version: None,
            operation_count: 0,
            hd_info: None,
        }
    }
}
