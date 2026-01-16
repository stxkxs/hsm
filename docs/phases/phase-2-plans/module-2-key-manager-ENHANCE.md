# Module 2: Key Manager - Phase 2 Enhancements

## Current Status
- ✅ 723 lines of code
- ✅ Compiles successfully
- ✅ Basic key lifecycle management

## Performance Enhancements

### 1. Fast Key Lookup (Priority: CRITICAL)
**Goal**: < 1ms p99 for key retrieval

**Tasks**:
- [ ] Benchmark current key lookup performance
- [ ] Implement lock-free reads with Arc<RwLock>
- [ ] Add key caching layer (LRU cache for hot keys)
- [ ] Use DashMap for concurrent access
- [ ] Profile lock contention

**Optimization**:
```rust
use dashmap::DashMap;

pub struct KeyStore {
    // Lock-free concurrent hashmap
    keys: Arc<DashMap<(String, KeyId), Arc<Key>>>,
    // LRU cache for hot keys
    hot_cache: Arc<Mutex<LruCache<KeyId, Arc<Key>>>>,
}
```

**Target**: < 100μs for cached lookups, < 1ms for cold lookups

### 2. Reduce Cloning Overhead (Priority: HIGH)
**Goal**: Eliminate unnecessary key material copies

**Tasks**:
- [ ] Use Arc<Key> instead of cloning keys
- [ ] Return references where possible
- [ ] Implement Copy-on-Write for metadata
- [ ] Profile memory allocations
- [ ] Measure clone reduction

**Pattern**:
```rust
// BEFORE (lots of cloning)
pub fn get_key(&self, key_id: &KeyId) -> Result<Key> {
    self.store.get(key_id).cloned()
}

// AFTER (zero-copy with Arc)
pub fn get_key(&self, key_id: &KeyId) -> Result<Arc<Key>> {
    self.store.get(key_id).map(|k| k.clone())
}
```

### 3. Concurrent Operations (Priority: HIGH)
**Goal**: Support 1000+ concurrent key operations

**Tasks**:
- [ ] Replace parking_lot::RwLock with DashMap
- [ ] Shard locks by namespace
- [ ] Use lock-free data structures where possible
- [ ] Add concurrent stress tests
- [ ] Benchmark under load

**Expected gain**: 5-10x improvement in concurrent throughput

### 4. Batch Operations (Priority: MEDIUM)
**Goal**: Support bulk key operations

**Tasks**:
- [ ] Add `list_keys_batch()` with pagination
- [ ] Implement `generate_keys_batch()`
- [ ] Add `delete_keys_batch()` with transaction safety
- [ ] Optimize metadata queries
- [ ] Add batch benchmarks

## Security Enhancements

### 1. Namespace Isolation Hardening (Priority: CRITICAL)
**Goal**: Zero cross-namespace leakage

**Tasks**:
- [ ] Add comprehensive namespace isolation tests
- [ ] Verify all operations check namespace
- [ ] Add fuzz testing for namespace bypasses
- [ ] Audit every get/list operation
- [ ] Add security test suite

**Critical check**:
```rust
pub fn get_key(&self, key_id: &KeyId, namespace: &str) -> Result<Arc<Key>> {
    let key = self.store.get(namespace, key_id)?;

    // CRITICAL: Verify namespace matches
    if key.namespace != namespace {
        return Err(Error::NamespaceViolation {
            expected: namespace.to_string(),
            actual: key.namespace.clone(),
        });
    }

    Ok(key)
}
```

### 2. Key Material Protection (Priority: CRITICAL)
**Goal**: Keys never exposed in plaintext

**Tasks**:
- [ ] Audit all key access points
- [ ] Ensure KeyMaterial is always encrypted at rest
- [ ] Verify no key logging in errors/debug
- [ ] Add memory zeroization tests
- [ ] Use SecretVec for all key material

**Add protection**:
```rust
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("id", &self.id)
            .field("key_type", &self.key_type)
            .field("namespace", &self.namespace)
            .field("state", &self.state)
            .field("private_material", &"<redacted>")  // NEVER log keys
            .finish()
    }
}
```

### 3. Access Control (Priority: HIGH)
**Goal**: Per-key ACLs enforced

**Tasks**:
- [ ] Implement per-key access control lists
- [ ] Verify ACLs on every operation
- [ ] Add ACL audit logging
- [ ] Test ACL enforcement
- [ ] Document ACL model

### 4. Key Rotation Safety (Priority: HIGH)
**Goal**: Atomic key rotation

**Tasks**:
- [ ] Implement transactional key rotation
- [ ] Verify old key deactivation is atomic
- [ ] Add rollback on failure
- [ ] Test concurrent rotation scenarios
- [ ] Add rotation audit trail

**Atomic rotation**:
```rust
pub fn rotate_key(&self, key_id: &KeyId, namespace: &str) -> Result<KeyId> {
    // Begin transaction
    let mut txn = self.begin_transaction();

    // Generate new key
    let new_key_id = self.generate_key_in_txn(&mut txn, spec)?;

    // Link to old key
    txn.set_previous_version(new_key_id, key_id)?;

    // Deactivate old key
    txn.update_state(key_id, KeyState::Deactivated)?;

    // Commit atomically
    txn.commit()?;

    Ok(new_key_id)
}
```

### 5. Key Deletion Security (Priority: HIGH)
**Goal**: Secure key wiping

**Tasks**:
- [ ] Implement secure deletion with overwrites
- [ ] Verify memory zeroization on delete
- [ ] Add multi-pass wiping for paranoid mode
- [ ] Test with valgrind/miri
- [ ] Document deletion guarantees

## Reliability Enhancements

### 1. Error Recovery (Priority: HIGH)
**Goal**: Graceful error handling

**Tasks**:
- [ ] Add retry logic for transient failures
- [ ] Implement circuit breakers
- [ ] Add health checks
- [ ] Log all errors with context
- [ ] Add error recovery tests

### 2. Audit Trail (Priority: HIGH)
**Goal**: Complete key lifecycle logging

**Tasks**:
- [ ] Log every key operation (create, read, update, delete)
- [ ] Include caller identity in logs
- [ ] Add operation timestamps
- [ ] Integrate with audit module
- [ ] Test audit completeness

**Logging**:
```rust
pub fn generate_key(&self, spec: KeySpec) -> Result<KeyId> {
    let start = Instant::now();

    let key_id = self.generate_key_internal(spec.clone())?;

    // Log successful creation
    audit::log(AuditEvent::KeyGenerated {
        key_id,
        key_type: spec.key_type,
        namespace: spec.namespace,
        created_by: current_identity(),
        duration: start.elapsed(),
    });

    Ok(key_id)
}
```

### 3. Metrics (Priority: MEDIUM)
**Goal**: Observable performance

**Tasks**:
- [ ] Add operation counters
- [ ] Add latency histograms
- [ ] Track key count by namespace
- [ ] Monitor lock contention
- [ ] Export Prometheus metrics

## Testing Enhancements

### 1. Concurrent Access Tests (Priority: HIGH)
**Goal**: Verify thread safety

**Tasks**:
- [ ] Add stress tests with 1000+ concurrent operations
- [ ] Test concurrent reads and writes
- [ ] Verify no deadlocks
- [ ] Add race condition tests with loom
- [ ] Test under high contention

### 2. Namespace Isolation Tests (Priority: CRITICAL)
**Goal**: Prove zero cross-namespace leakage

**Tasks**:
- [ ] Add fuzzing for namespace bypasses
- [ ] Test all operations across namespaces
- [ ] Verify list operations don't leak
- [ ] Add property-based tests
- [ ] Security audit

### 3. Memory Leak Tests (Priority: HIGH)
**Goal**: Zero memory leaks

**Tasks**:
- [ ] Run valgrind on all tests
- [ ] Check for leaked keys in memory
- [ ] Profile long-running operations
- [ ] Test key deletion thoroughly
- [ ] Add continuous memory monitoring

## Success Metrics

**Performance**:
- ✅ Key lookup: < 1ms p99
- ✅ Key generation: < 50ms p99
- ✅ Concurrent ops: > 1000/sec
- ✅ Lock contention: < 1% of time

**Security**:
- ✅ Zero namespace leakage in tests
- ✅ All keys zeroized on delete
- ✅ ACLs enforced 100% of time
- ✅ Complete audit trail

**Reliability**:
- ✅ Zero memory leaks
- ✅ Atomic operations
- ✅ Graceful error handling
- ✅ > 95% test coverage

## Claude Agent Instructions

1. Read this enhancement plan
2. Run existing tests to verify baseline
3. Implement DashMap for concurrent access
4. Add comprehensive namespace isolation tests
5. Implement key caching layer
6. Add audit logging for all operations
7. Verify all security properties
8. Achieve performance targets
9. Run stress tests and verify no issues
