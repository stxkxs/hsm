# Module 7: Storage Backend - Implementation Plan

## Agent Mission
Build a secure, encrypted storage backend for persisting keys with atomic operations, journaling, and corruption detection.

## Critical Success Factors
1. All keys encrypted at rest (AES-256-GCM)
2. Atomic write operations
3. Journaling for crash recovery
4. Corruption detection via checksums
5. Namespace-based directory structure
6. Performance: 1000+ writes/sec

## File Structure
```
crates/storage/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── backend.rs             # Storage trait
│   ├── encrypted_fs.rs        # Encrypted filesystem
│   ├── journal.rs             # Write-ahead journal
│   ├── master_key.rs          # Master key management
│   └── checksum.rs            # Corruption detection
└── tests/
    ├── storage_tests.rs
    ├── corruption_tests.rs
    └── performance_tests.rs
```

## Storage Layout
```
/data/hsm/
├── master_key.enc
├── namespaces/
│   ├── production/
│   │   ├── keys/
│   │   │   ├── key-abc123.enc
│   │   │   └── key-abc123.meta
│   │   └── journal/
│   └── staging/
└── audit/
```

## Key Components
```rust
pub trait StorageBackend {
    fn store_key(&mut self, key_id: &KeyId, data: &[u8], namespace: &str) -> Result<()>;
    fn load_key(&self, key_id: &KeyId, namespace: &str) -> Result<Vec<u8>>;
    fn delete_key(&mut self, key_id: &KeyId, namespace: &str) -> Result<()>;
    fn sync(&mut self) -> Result<()>;
}

pub struct EncryptedFileStorage {
    master_key: SecretVec<u8>,
    base_path: PathBuf,
    journal: WriteAheadLog,
}
```

## Timeline
- Day 1: Storage trait + master key
- Day 2: Encrypted FS implementation
- Day 3: Journaling + checksums
- Day 4: Testing + recovery scenarios
