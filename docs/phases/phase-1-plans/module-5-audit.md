# Module 5: Audit & Logging System - Implementation Plan

## Agent Mission
Build a tamper-evident audit logging system using hash chains and Merkle trees to ensure complete auditability of all HSM operations.

## Critical Success Factors
1. Every operation must be logged
2. Logs must be tamper-evident (hash chain + Merkle tree)
3. Log integrity must be verifiable
4. High-throughput logging (10,000+ ops/sec)
5. Structured JSON format for easy parsing
6. Log rotation and retention

## File Structure
```
crates/audit/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── logger.rs              # Main audit logger
│   ├── event.rs               # Audit event types
│   ├── hash_chain.rs          # Hash chain implementation
│   ├── merkle_tree.rs         # Merkle tree for verification
│   ├── storage.rs             # Log persistence
│   └── verifier.rs            # Log integrity verification
└── tests/
    ├── integrity_tests.rs
    └── performance_tests.rs
```

## Key Components
```rust
// Audit event structure
#[derive(Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub sequence: u64,
    pub event_type: EventType,
    pub operation: String,
    pub namespace: String,
    pub client_id: String,
    pub key_id: Option<String>,
    pub result: OperationResult,
    pub prev_hash: String,
    pub current_hash: String,
}

// Hash chain for tamper evidence
pub struct HashChain {
    pub fn append(&mut self, event: AuditEvent) -> String;
    pub fn verify(&self, from: u64, to: u64) -> bool;
}

// Merkle tree for efficient verification
pub struct MerkleTree {
    pub fn update(&mut self, hash: &str);
    pub fn get_root(&self) -> String;
    pub fn verify_inclusion(&self, hash: &str) -> bool;
}
```

## Timeline
- Day 1: Event types + hash chain
- Day 2: Merkle tree implementation
- Day 3: Storage + rotation
- Day 4: Verification + testing
