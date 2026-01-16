# Module 5: Audit & Logging System - Phase 2 Enhancements

## Current Status
- ✅ 2,876 lines of code
- ✅ Compiles successfully
- ✅ Basic audit logging
- ✅ Hash chain implementation
- ✅ Merkle tree for tamper evidence

## Performance Enhancements

### 1. Asynchronous Logging (Priority: CRITICAL)
**Goal**: < 5ms p99 for audit log writes (don't block operations)

**Tasks**:
- [ ] Implement async audit log channel
- [ ] Use bounded channel with backpressure
- [ ] Add background writer task
- [ ] Batch writes to storage
- [ ] Profile logging overhead

**Async architecture**:
```rust
use tokio::sync::mpsc;

pub struct AuditLogger {
    // Bounded channel for audit events
    tx: mpsc::Sender<AuditEvent>,
    // Background task handle
    writer_task: JoinHandle<()>,
}

impl AuditLogger {
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);

        let writer_task = tokio::spawn(async move {
            Self::writer_loop(rx).await;
        });

        Self { tx, writer_task }
    }

    // Non-blocking log
    pub async fn log(&self, event: AuditEvent) -> Result<()> {
        // Try to send, fail fast if channel full
        self.tx.try_send(event)
            .map_err(|_| AuditError::QueueFull)?;
        Ok(())
    }

    async fn writer_loop(mut rx: mpsc::Receiver<AuditEvent>) {
        let mut batch = Vec::with_capacity(100);

        loop {
            // Batch events for efficiency
            batch.clear();

            // Get first event (blocking)
            if let Some(event) = rx.recv().await {
                batch.push(event);
            } else {
                break; // Channel closed
            }

            // Get more events without blocking
            while batch.len() < 100 {
                match rx.try_recv() {
                    Ok(event) => batch.push(event),
                    Err(_) => break,
                }
            }

            // Write batch to storage
            if let Err(e) = Self::write_batch(&batch).await {
                error!("Failed to write audit batch: {:?}", e);
            }
        }
    }
}
```

**Target**: < 1ms for log call (async), < 5ms for batch flush

### 2. Batch Writes (Priority: HIGH)
**Goal**: 10x throughput improvement

**Tasks**:
- [ ] Batch multiple events before writing
- [ ] Optimize hash chain computation
- [ ] Batch Merkle tree updates
- [ ] Add configurable batch size/timeout
- [ ] Benchmark batching effectiveness

**Expected gain**: 10-20x improvement in write throughput

### 3. Merkle Tree Optimization (Priority: HIGH)
**Goal**: Fast tamper evidence proofs

**Tasks**:
- [ ] Use in-memory Merkle tree cache
- [ ] Optimize tree updates (incremental)
- [ ] Add efficient proof generation
- [ ] Cache intermediate nodes
- [ ] Benchmark proof verification

**Optimized Merkle tree**:
```rust
use rs_merkle::{MerkleTree, Hasher, MerkleProof};
use sha2::Sha256;

pub struct TamperEvidenceLog {
    // In-memory Merkle tree
    tree: MerkleTree<Sha256Hasher>,
    // Leaf cache for fast lookups
    leaves: Vec<[u8; 32]>,
}

impl TamperEvidenceLog {
    pub fn append(&mut self, event: &AuditEvent) -> Result<()> {
        let hash = self.hash_event(event);
        self.leaves.push(hash);

        // Incremental tree update (O(log n))
        self.tree.append(hash);

        Ok(())
    }

    pub fn generate_proof(&self, index: usize) -> Result<MerkleProof> {
        // Fast proof generation from cached tree
        self.tree.proof(&[index])
            .ok_or(AuditError::InvalidIndex)
    }

    pub fn verify_proof(&self, event: &AuditEvent, proof: &MerkleProof) -> bool {
        let hash = self.hash_event(event);
        proof.verify(self.tree.root(), &[hash], &[event.index])
    }
}
```

### 4. Query Optimization (Priority: MEDIUM)
**Goal**: Fast log queries

**Tasks**:
- [ ] Add indexes on timestamp, event type, identity
- [ ] Implement query result caching
- [ ] Optimize range queries
- [ ] Add pagination with cursors
- [ ] Benchmark query performance

### 5. Storage Optimization (Priority: HIGH)
**Goal**: Efficient log storage

**Tasks**:
- [ ] Use append-only file format
- [ ] Add log compression (zstd)
- [ ] Implement log rotation
- [ ] Add archival to cold storage
- [ ] Benchmark storage efficiency

**Compressed storage**:
```rust
use zstd::stream::Encoder;

pub struct AuditStorage {
    current_file: File,
    compressor: Encoder<'static, File>,
}

impl AuditStorage {
    pub fn write_batch(&mut self, events: &[AuditEvent]) -> Result<()> {
        for event in events {
            // Serialize and compress
            let bytes = bincode::serialize(event)?;
            self.compressor.write_all(&bytes)?;
        }

        // Flush periodically
        self.compressor.flush()?;
        Ok(())
    }
}
```

## Security Enhancements

### 1. Tamper Evidence Hardening (Priority: CRITICAL)
**Goal**: Detect any tampering immediately

**Tasks**:
- [ ] Add periodic hash chain verification
- [ ] Verify Merkle tree consistency
- [ ] Add cross-chain verification
- [ ] Implement external anchoring (optional)
- [ ] Test tamper detection

**Verification**:
```rust
impl AuditLog {
    pub fn verify_integrity(&self) -> Result<IntegrityReport> {
        let mut report = IntegrityReport::new();

        // 1. Verify hash chain continuity
        let mut prev_hash = [0u8; 32];
        for event in self.events.iter() {
            let computed_hash = self.compute_chain_hash(&event, &prev_hash);
            if computed_hash != event.chain_hash {
                report.add_violation(Violation::HashChainBroken {
                    event_id: event.id,
                    expected: computed_hash,
                    actual: event.chain_hash,
                });
            }
            prev_hash = event.chain_hash;
        }

        // 2. Verify Merkle tree consistency
        let recomputed_root = self.recompute_merkle_root();
        if recomputed_root != self.merkle_root {
            report.add_violation(Violation::MerkleTreeInconsistent {
                expected: recomputed_root,
                actual: self.merkle_root,
            });
        }

        // 3. Check for gaps in sequence numbers
        for window in self.events.windows(2) {
            if window[1].sequence_number != window[0].sequence_number + 1 {
                report.add_violation(Violation::SequenceGap {
                    prev: window[0].sequence_number,
                    next: window[1].sequence_number,
                });
            }
        }

        Ok(report)
    }
}
```

### 2. Audit Log Signing (Priority: HIGH)
**Goal**: Cryptographic proof of authenticity

**Tasks**:
- [ ] Sign each audit batch with HSM key
- [ ] Add signature verification
- [ ] Implement log rotation with signatures
- [ ] Add timestamp authority integration (optional)
- [ ] Test signature verification

**Signed logs**:
```rust
pub struct SignedAuditBatch {
    events: Vec<AuditEvent>,
    merkle_root: [u8; 32],
    signature: Vec<u8>,  // Signed with HSM key
    timestamp: i64,
}

impl AuditLogger {
    pub async fn finalize_batch(&self, batch: Vec<AuditEvent>) -> Result<SignedAuditBatch> {
        // Compute Merkle root
        let merkle_root = self.compute_merkle_root(&batch);

        // Sign the root
        let signature = self.crypto_engine.sign(
            &self.audit_signing_key,
            &merkle_root,
            SignAlgorithm::Ed25519,
        ).await?;

        Ok(SignedAuditBatch {
            events: batch,
            merkle_root,
            signature,
            timestamp: Utc::now().timestamp(),
        })
    }
}
```

### 3. Write-Once Log (Priority: CRITICAL)
**Goal**: Prevent log modification

**Tasks**:
- [ ] Implement write-once file system semantics
- [ ] Add file immutability flags
- [ ] Verify no log modifications
- [ ] Test append-only enforcement
- [ ] Document immutability guarantees

### 4. Log Encryption (Priority: HIGH)
**Goal**: Protect log confidentiality

**Tasks**:
- [ ] Encrypt logs at rest
- [ ] Use authenticated encryption (AES-GCM)
- [ ] Implement key rotation for log encryption
- [ ] Add decryption for queries
- [ - Test encryption performance

**Encrypted storage**:
```rust
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};

pub struct EncryptedAuditStorage {
    cipher: Aes256Gcm,
    storage: File,
}

impl EncryptedAuditStorage {
    pub fn write_event(&mut self, event: &AuditEvent) -> Result<()> {
        // Serialize event
        let plaintext = bincode::serialize(event)?;

        // Generate unique nonce (event sequence number as nonce)
        let nonce = Self::event_nonce(event.sequence_number);

        // Encrypt with authenticated encryption
        let ciphertext = self.cipher.encrypt(&nonce, plaintext.as_ref())
            .map_err(|_| AuditError::EncryptionFailed)?;

        // Write nonce + ciphertext
        self.storage.write_all(&nonce)?;
        self.storage.write_all(&ciphertext)?;

        Ok(())
    }
}
```

### 5. Access Control (Priority: HIGH)
**Goal**: Restrict log access

**Tasks**:
- [ ] Implement log read permissions
- [ ] Add audit trail for log access
- [ ] Restrict log modification (append-only)
- [ ] Add compliance reporting
- [ ] Test access control enforcement

## Reliability Enhancements

### 1. Log Durability (Priority: CRITICAL)
**Goal**: Never lose audit events

**Tasks**:
- [ ] Implement fsync after batch writes
- [ ] Add write-ahead logging (WAL)
- [ ] Test crash recovery
- [ ] Add replication (optional)
- [ ] Document durability guarantees

**Durable writes**:
```rust
impl AuditStorage {
    pub async fn write_batch_durable(&mut self, batch: &[AuditEvent]) -> Result<()> {
        // Write to file
        for event in batch {
            self.write_event(event)?;
        }

        // Force to disk (CRITICAL for durability)
        self.file.sync_all()?;

        Ok(())
    }
}
```

### 2. Log Rotation (Priority: HIGH)
**Goal**: Manage log growth

**Tasks**:
- [ ] Implement automatic log rotation
- [ ] Add size-based and time-based rotation
- [ ] Maintain hash chain across rotations
- [ ] Archive old logs
- [ ] Test rotation behavior

### 3. Error Recovery (Priority: HIGH)
**Goal**: Graceful error handling

**Tasks**:
- [ ] Add retry logic for transient failures
- [ ] Implement dead letter queue for failed events
- [ ] Add alerting on audit failures
- [ ] Test failure scenarios
- [ ] Document recovery procedures

### 4. Monitoring (Priority: MEDIUM)
**Goal**: Observable audit system

**Tasks**:
- [ ] Add metrics for write latency
- [ ] Track queue depth
- [ ] Monitor log size and growth rate
- [ ] Alert on tamper detection
- [ ] Add health checks

## Testing Enhancements

### 1. Tamper Detection Tests (Priority: CRITICAL)
**Goal**: Prove tamper evidence works

**Tasks**:
- [ ] Test hash chain modification detection
- [ ] Test Merkle tree tampering detection
- [ ] Test sequence number gap detection
- [ ] Add randomized tampering tests
- [ ] Verify all tampering is detected

### 2. Performance Tests (Priority: HIGH)
**Goal**: Meet performance targets

**Tasks**:
- [ ] Benchmark write throughput
- [ ] Test under high load (10,000+ events/sec)
- [ ] Measure query performance
- [ ] Test batch effectiveness
- [ ] Profile bottlenecks

### 3. Durability Tests (Priority: HIGH)
**Goal**: Verify no data loss

**Tasks**:
- [ ] Test crash recovery
- [ ] Verify fsync behavior
- [ ] Test power failure scenarios (optional)
- [ ] Verify log integrity after crashes
- [ ] Test backup/restore

### 4. Compliance Tests (Priority: MEDIUM)
**Goal**: Meet audit requirements

**Tasks**:
- [ ] Verify all operations are logged
- [ ] Test log completeness
- [ ] Verify tamper evidence
- [ ] Test log retention
- [ ] Generate compliance reports

## Success Metrics

**Performance**:
- ✅ Audit write latency: < 5ms p99 (async)
- ✅ Write throughput: > 10,000 events/sec
- ✅ Query latency: < 100ms p99
- ✅ Storage efficiency: > 50% compression ratio

**Security**:
- ✅ 100% tamper detection in tests
- ✅ All logs cryptographically signed
- ✅ Logs encrypted at rest
- ✅ Write-once enforcement
- ✅ Complete audit trail

**Reliability**:
- ✅ Zero data loss (durable writes)
- ✅ Automatic log rotation
- ✅ Crash recovery works
- ✅ > 95% test coverage

## Claude Agent Instructions

1. Read this enhancement plan
2. Run existing tests to verify baseline
3. Implement asynchronous logging with batching
4. Add comprehensive tamper detection tests
5. Implement log signing and encryption
6. Add durability guarantees (fsync)
7. Verify performance targets
8. Test tamper detection thoroughly
9. Achieve all success metrics
