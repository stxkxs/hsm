# Module 8: Backup & Recovery - Phase 2 Enhancements

## Current Status
- ✅ 1,587 lines of code
- ✅ Compiles successfully
- ✅ Basic backup/restore
- ✅ Shamir's Secret Sharing

## Performance Enhancements

### 1. Incremental Backups (Priority: CRITICAL)
**Goal**: Fast incremental backups (< 1min for typical changes)

**Tasks**:
- [ ] Implement change tracking for keys
- [ ] Add incremental backup generation
- [ ] Optimize diff computation
- [ ] Add backup chaining
- [ ] Benchmark backup speed

**Incremental backup**:
```rust
use std::collections::HashSet;

pub struct IncrementalBackup {
    // Track changed keys since last backup
    changed_keys: HashSet<KeyId>,
    last_backup_timestamp: i64,
}

impl BackupManager {
    pub async fn create_incremental_backup(&self) -> Result<Backup> {
        let last_backup = self.get_last_backup()?;

        // Find keys changed since last backup
        let changed_keys = self.storage
            .list_keys_modified_since(last_backup.timestamp)?;

        // Create backup with only changed keys
        let mut backup = Backup::new(BackupType::Incremental);
        backup.set_parent(last_backup.id);

        for key_id in changed_keys {
            let key = self.storage.read_key(&key_id).await?;
            backup.add_key(key);
        }

        Ok(backup)
    }

    pub async fn restore_incremental(&self, backup_chain: Vec<Backup>) -> Result<()> {
        // Restore full backup first
        let full_backup = backup_chain.first()
            .ok_or(BackupError::NoFullBackup)?;
        self.restore_full(full_backup).await?;

        // Apply incremental backups in order
        for incremental in &backup_chain[1..] {
            for key in &incremental.keys {
                self.storage.write_key(key).await?;
            }
        }

        Ok(())
    }
}
```

**Expected gain**: 10-50x faster backups for typical workloads

### 2. Parallel Backup (Priority: HIGH)
**Goal**: Utilize multiple cores for backup

**Tasks**:
- [ ] Parallelize key encryption
- [ ] Use concurrent I/O
- [ ] Optimize chunk processing
- [ ] Profile parallelization
- [ ] Benchmark parallel vs sequential

**Parallel backup**:
```rust
use rayon::prelude::*;
use tokio::task;

impl BackupManager {
    pub async fn create_backup_parallel(&self) -> Result<Backup> {
        let keys = self.storage.list_all_keys().await?;

        // Process keys in parallel
        let encrypted_keys: Vec<_> = keys
            .par_iter()
            .map(|key_id| {
                // Encrypt each key in parallel
                self.encrypt_key_for_backup(key_id)
            })
            .collect::<Result<Vec<_>>>()?;

        // Create backup
        let mut backup = Backup::new(BackupType::Full);
        for encrypted_key in encrypted_keys {
            backup.add_key(encrypted_key);
        }

        Ok(backup)
    }
}
```

**Expected speedup**: 4-8x on multi-core systems

### 3. Compression (Priority: HIGH)
**Goal**: Reduce backup size

**Tasks**:
- [ ] Add zstd compression for backups
- [ ] Optimize compression level
- [ ] Add deduplication
- [ ] Benchmark compression ratios
- [ ] Test decompression speed

**Compressed backups**:
```rust
use zstd::stream::{Encoder, Decoder};

impl BackupManager {
    pub async fn write_compressed_backup(&self, backup: &Backup, path: &Path) -> Result<()> {
        // Serialize backup
        let bytes = bincode::serialize(backup)?;

        // Compress with zstd (level 6 = good balance)
        let compressed = zstd::encode_all(&bytes[..], 6)?;

        // Write to file
        tokio::fs::write(path, compressed).await?;

        info!(
            "Backup compressed: {} -> {} bytes ({:.1}% reduction)",
            bytes.len(),
            compressed.len(),
            100.0 * (1.0 - compressed.len() as f64 / bytes.len() as f64)
        );

        Ok(())
    }

    pub async fn read_compressed_backup(&self, path: &Path) -> Result<Backup> {
        // Read compressed data
        let compressed = tokio::fs::read(path).await?;

        // Decompress
        let bytes = zstd::decode_all(&compressed[..])?;

        // Deserialize
        let backup = bincode::deserialize(&bytes)?;

        Ok(backup)
    }
}
```

**Expected gain**: 50-70% size reduction

### 4. Streaming Backups (Priority: MEDIUM)
**Goal**: Support large backups (> RAM size)

**Tasks**:
- [ ] Implement streaming backup writer
- [ ] Add streaming restore
- [ ] Use chunked processing
- [ ] Test with large datasets
- [ ] Optimize memory usage

**Streaming**:
```rust
use tokio::io::{AsyncWriteExt, AsyncReadExt};

impl BackupManager {
    pub async fn create_streaming_backup(&self, mut writer: impl AsyncWrite + Unpin) -> Result<()> {
        let keys = self.storage.list_all_keys().await?;

        // Write backup header
        let header = BackupHeader::new();
        let header_bytes = bincode::serialize(&header)?;
        writer.write_all(&header_bytes).await?;

        // Stream keys one at a time
        for key_id in keys {
            let key = self.storage.read_key(&key_id).await?;
            let encrypted = self.encrypt_key_for_backup(&key)?;

            // Write key length + data
            let key_bytes = bincode::serialize(&encrypted)?;
            writer.write_u64(key_bytes.len() as u64).await?;
            writer.write_all(&key_bytes).await?;
        }

        writer.flush().await?;
        Ok(())
    }
}
```

## Security Enhancements

### 1. Shamir's Secret Sharing Hardening (Priority: CRITICAL)
**Goal**: Secure threshold cryptography

**Tasks**:
- [ ] Audit SSS implementation for correctness
- [ ] Add share validation
- [ ] Implement share refresh (proactive security)
- [ ] Add share distribution tracking
- [ ] Test reconstruction with various thresholds

**SSS hardening**:
```rust
use sharks::{Sharks, Share};

pub struct SecretSharingManager {
    threshold: u8,
    total_shares: u8,
}

impl SecretSharingManager {
    pub fn split_master_key(&self, master_key: &[u8]) -> Result<Vec<Share>> {
        if master_key.len() != 32 {
            return Err(BackupError::InvalidKeySize);
        }

        let sharks = Sharks(self.threshold);
        let dealer = sharks.dealer(master_key);

        // Generate shares
        let shares: Vec<Share> = dealer.take(self.total_shares as usize).collect();

        // Validate shares (CRITICAL)
        self.validate_shares(&shares, master_key)?;

        Ok(shares)
    }

    fn validate_shares(&self, shares: &[Share], original: &[u8]) -> Result<()> {
        // Test reconstruction with minimum threshold
        let sharks = Sharks(self.threshold);
        let reconstructed = sharks.recover(&shares[..self.threshold as usize])
            .map_err(|_| BackupError::ShareRecoveryFailed)?;

        // Verify reconstruction matches original
        if reconstructed != original {
            return Err(BackupError::ShareValidationFailed);
        }

        Ok(())
    }

    pub fn reconstruct_master_key(&self, shares: &[Share]) -> Result<Vec<u8>> {
        if shares.len() < self.threshold as usize {
            return Err(BackupError::InsufficientShares {
                provided: shares.len(),
                required: self.threshold as usize,
            });
        }

        let sharks = Sharks(self.threshold);
        let recovered = sharks.recover(shares)
            .map_err(|_| BackupError::ShareRecoveryFailed)?;

        Ok(recovered)
    }
}
```

### 2. Backup Encryption (Priority: CRITICAL)
**Goal**: Encrypted backups at rest

**Tasks**:
- [ ] Use AES-256-GCM for backup encryption
- [ ] Add per-backup encryption keys
- [ ] Implement key derivation from passphrase
- [ ] Add backup integrity verification
- [ ] Test encryption/decryption

**Encrypted backups**:
```rust
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Argon2, PasswordHasher};

pub struct EncryptedBackup {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    salt: Vec<u8>,
    tag: Vec<u8>,
}

impl BackupManager {
    pub fn encrypt_backup(&self, backup: &Backup, passphrase: &str) -> Result<EncryptedBackup> {
        // Derive encryption key from passphrase using Argon2
        let salt = self.generate_salt();
        let key = self.derive_key_from_passphrase(passphrase, &salt)?;

        // Generate random nonce
        let nonce = self.generate_nonce();

        // Serialize backup
        let plaintext = bincode::serialize(backup)?;

        // Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new(Key::from_slice(&key));
        let nonce_obj = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce_obj, plaintext.as_ref())
            .map_err(|_| BackupError::EncryptionFailed)?;

        Ok(EncryptedBackup {
            ciphertext,
            nonce,
            salt,
            tag: vec![], // Tag is included in ciphertext by AEAD
        })
    }

    fn derive_key_from_passphrase(&self, passphrase: &str, salt: &[u8]) -> Result<Vec<u8>> {
        let argon2 = Argon2::default();

        // Use Argon2id for key derivation (secure against side-channels)
        let mut key = [0u8; 32];
        argon2.hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|_| BackupError::KeyDerivationFailed)?;

        Ok(key.to_vec())
    }
}
```

### 3. Backup Integrity Verification (Priority: HIGH)
**Goal**: Detect backup corruption

**Tasks**:
- [ ] Add HMAC to backups
- [ ] Implement backup verification
- [ ] Add periodic backup validation
- [ ] Test corruption detection
- [ ] Add backup repair (from redundancy)

**Integrity verification**:
```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct VerifiedBackup {
    backup: Backup,
    hmac: Vec<u8>,
    timestamp: i64,
}

impl BackupManager {
    pub fn create_verified_backup(&self, backup: Backup) -> Result<VerifiedBackup> {
        let backup_bytes = bincode::serialize(&backup)?;

        // Compute HMAC
        let mut mac = HmacSha256::new_from_slice(&self.integrity_key)?;
        mac.update(&backup_bytes);
        let hmac = mac.finalize().into_bytes().to_vec();

        Ok(VerifiedBackup {
            backup,
            hmac,
            timestamp: Utc::now().timestamp(),
        })
    }

    pub fn verify_backup(&self, verified: &VerifiedBackup) -> Result<()> {
        let backup_bytes = bincode::serialize(&verified.backup)?;

        // Recompute HMAC
        let mut mac = HmacSha256::new_from_slice(&self.integrity_key)?;
        mac.update(&backup_bytes);

        // Verify
        mac.verify_slice(&verified.hmac)
            .map_err(|_| BackupError::IntegrityCheckFailed)?;

        Ok(())
    }
}
```

### 4. Secure Share Distribution (Priority: HIGH)
**Goal**: Safe share handling

**Tasks**:
- [ ] Add share encryption
- [ ] Implement share tracking
- [ ] Add share revocation
- [ ] Document share distribution procedures
- [ ] Test share security

### 5. Backup Access Control (Priority: MEDIUM)
**Goal**: Restrict backup access

**Tasks**:
- [ ] Add role-based backup permissions
- [ ] Audit backup operations
- [ ] Implement backup encryption key management
- [ ] Test access control
- [ ] Document backup security model

## Reliability Enhancements

### 1. Backup Verification (Priority: CRITICAL)
**Goal**: Ensure backups are restorable

**Tasks**:
- [ ] Verify backup after creation
- [ ] Add periodic restore tests
- [ ] Implement backup health checks
- [ ] Test restore reliability
- [ ] Document verification procedures

**Verification**:
```rust
impl BackupManager {
    pub async fn verify_backup_restorable(&self, backup_path: &Path) -> Result<BackupHealth> {
        let mut health = BackupHealth::new();

        // 1. Read backup
        let backup = match self.read_backup(backup_path).await {
            Ok(b) => b,
            Err(e) => {
                health.add_error(format!("Failed to read backup: {}", e));
                return Ok(health);
            }
        };

        // 2. Verify integrity
        if let Err(e) = self.verify_backup(&backup) {
            health.add_error(format!("Integrity check failed: {}", e));
        }

        // 3. Verify all keys can be decrypted
        for key in &backup.keys {
            if let Err(e) = self.decrypt_backup_key(key) {
                health.add_error(format!("Key decryption failed: {}", e));
            }
        }

        // 4. Test sample restore
        if let Err(e) = self.test_restore_sample(&backup).await {
            health.add_error(format!("Sample restore failed: {}", e));
        }

        Ok(health)
    }

    async fn test_restore_sample(&self, backup: &Backup) -> Result<()> {
        // Create temporary storage
        let temp_storage = TempStorage::new()?;

        // Restore to temporary location
        for key in backup.keys.iter().take(10) {  // Test first 10 keys
            temp_storage.write_key(key).await?;
        }

        // Verify keys can be read back
        for key in backup.keys.iter().take(10) {
            let restored = temp_storage.read_key(&key.id).await?;
            if restored.id != key.id {
                return Err(BackupError::RestoreVerificationFailed);
            }
        }

        Ok(())
    }
}
```

### 2. Backup Retention (Priority: HIGH)
**Goal**: Manage backup lifecycle

**Tasks**:
- [ ] Implement retention policies
- [ ] Add automatic backup rotation
- [ ] Implement backup archival
- [ ] Add backup expiration
- [ ] Test retention enforcement

### 3. Disaster Recovery (Priority: HIGH)
**Goal**: Fast recovery from failures

**Tasks**:
- [ ] Document disaster recovery procedures
- [ ] Add automated recovery workflows
- [ ] Test recovery scenarios
- [ ] Add recovery time optimization
- [ ] Measure RTO/RPO

**Recovery metrics**:
- RTO (Recovery Time Objective): < 1 hour
- RPO (Recovery Point Objective): < 15 minutes

### 4. Backup Monitoring (Priority: MEDIUM)
**Goal**: Observable backup system

**Tasks**:
- [ ] Add metrics for backup operations
- [ ] Track backup success/failure rates
- [ ] Monitor backup sizes
- [ ] Alert on backup failures
- [ ] Add backup health dashboard

## Testing Enhancements

### 1. Restore Tests (Priority: CRITICAL)
**Goal**: Verify backups are restorable

**Tasks**:
- [ ] Test full backup/restore
- [ ] Test incremental restore
- [ ] Test partial restore
- [ ] Test cross-version restore
- [ ] Test disaster recovery scenarios

### 2. Shamir's Secret Sharing Tests (Priority: CRITICAL)
**Goal**: Verify SSS correctness

**Tasks**:
- [ ] Test with various thresholds
- [ ] Test with minimum shares
- [ ] Test with extra shares
- [ ] Test share validation
- [ ] Test reconstruction accuracy

**SSS tests**:
```rust
#[test]
fn test_shamir_secret_sharing() {
    let manager = SecretSharingManager {
        threshold: 3,
        total_shares: 5,
    };

    let secret = b"this is a secret master key!!!!!";

    // Split secret
    let shares = manager.split_master_key(secret).unwrap();
    assert_eq!(shares.len(), 5);

    // Test reconstruction with minimum threshold (3 shares)
    let subset = &shares[0..3];
    let recovered = manager.reconstruct_master_key(subset).unwrap();
    assert_eq!(&recovered[..], secret);

    // Test with different subset
    let subset2 = &shares[2..5];
    let recovered2 = manager.reconstruct_master_key(subset2).unwrap();
    assert_eq!(&recovered2[..], secret);

    // Test insufficient shares fails
    let subset3 = &shares[0..2];
    assert!(manager.reconstruct_master_key(subset3).is_err());
}
```

### 3. Performance Tests (Priority: HIGH)
**Goal**: Meet performance targets

**Tasks**:
- [ ] Benchmark backup speed
- [ ] Test compression ratios
- [ ] Benchmark restore speed
- [ ] Profile parallelization
- [ ] Test with large datasets

### 4. Security Tests (Priority: HIGH)
**Goal**: Verify backup security

**Tasks**:
- [ ] Test backup encryption
- [ ] Test share security
- [ ] Verify integrity protection
- [ ] Test access control
- [ ] Audit backup security

## Success Metrics

**Performance**:
- ✅ Full backup: < 5min for 100k keys
- ✅ Incremental backup: < 1min
- ✅ Compression ratio: > 50%
- ✅ Restore speed: < 10min for 100k keys

**Security**:
- ✅ All backups encrypted
- ✅ SSS tested with multiple thresholds
- ✅ Integrity verification works
- ✅ Share validation passes

**Reliability**:
- ✅ 100% restore success rate
- ✅ Backup verification passes
- ✅ RTO < 1 hour, RPO < 15 minutes
- ✅ > 95% test coverage

## Claude Agent Instructions

1. Read this enhancement plan
2. Run existing tests to verify baseline
3. Implement incremental backups
4. Add parallel backup processing
5. Harden Shamir's Secret Sharing
6. Add backup verification
7. Verify performance targets
8. Test restore reliability thoroughly
9. Achieve all success metrics
