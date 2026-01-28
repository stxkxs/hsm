//! # Backup and Recovery Module for HSM
//!
//! This module provides comprehensive backup and disaster recovery capabilities
//! for the HSM, including encrypted key export, Shamir's Secret Sharing for
//! master key protection, and integrity verification.
//!
//! ## Features
//!
//! - **Encrypted Backups**: AES-256-GCM encrypted key export with Argon2id key derivation
//! - **Shamir's Secret Sharing**: Split master keys into `n` shares with `k` threshold recovery
//! - **Integrity Verification**: HMAC-SHA256 checksums prevent tampering
//! - **Incremental Backups**: Only backup changed keys for efficiency
//! - **Compression**: Zstd compression reduces storage requirements
//! - **Parallel Processing**: Multi-threaded backup operations for performance
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    Backup & Recovery Architecture                    │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                       │
//! │  ┌──────────────┐                      ┌──────────────────────────┐  │
//! │  │  Key Store   │─────────────────────▶│    Backup Pipeline       │  │
//! │  │  (HSM Keys)  │                      │                          │  │
//! │  └──────────────┘                      │  1. Serialize (JSON)     │  │
//! │                                        │  2. Compress (Zstd)      │  │
//! │  ┌──────────────┐                      │  3. Encrypt (AES-GCM)    │  │
//! │  │ Master Key   │──┐                   │  4. HMAC Sign            │  │
//! │  └──────────────┘  │                   └──────────────────────────┘  │
//! │                    │                              │                   │
//! │                    ▼                              ▼                   │
//! │         ┌─────────────────┐           ┌──────────────────────┐       │
//! │         │ Shamir's Secret │           │   Encrypted Backup   │       │
//! │         │    Sharing      │           │   (.hsm-backup)      │       │
//! │         └─────────────────┘           └──────────────────────┘       │
//! │                    │                                                  │
//! │         ┌──────────┴──────────┐                                      │
//! │         ▼          ▼          ▼                                      │
//! │     [Share 1] [Share 2] [Share 3] ... [Share N]                     │
//! │                                                                       │
//! │  Recovery requires K of N shares (threshold scheme)                  │
//! │                                                                       │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ### Create and Restore a Backup
//!
//! ```rust
//! use backup::{SimpleBackupManager, BackupManager};
//!
//! // Create a backup manager and add keys
//! let mut manager = SimpleBackupManager::new();
//! manager.add_key("production", "signing-key-1", b"secret_key_data".to_vec());
//! manager.add_key("production", "encryption-key-1", b"another_secret".to_vec());
//!
//! // Export keys with password encryption
//! let password = b"strong-backup-password-123!";
//! let backup = manager.export_keys("production", password).unwrap();
//!
//! // Later: restore from backup
//! let mut new_manager = SimpleBackupManager::new();
//! let key_count = new_manager.import_keys(&backup, password).unwrap();
//! println!("Restored {} keys", key_count);
//! ```
//!
//! ### Shamir's Secret Sharing for Master Key
//!
//! Split the master key into 5 shares, requiring any 3 to recover:
//!
//! ```rust
//! use backup::{SimpleBackupManager, BackupManager};
//!
//! let mut manager = SimpleBackupManager::new();
//!
//! // Set the master key (typically 32 bytes for AES-256)
//! let master_key = b"master_key_32_bytes_long_here!!!";
//! manager.set_master_key(master_key.to_vec());
//!
//! // Split into 5 shares with threshold of 3
//! let shares = manager.split_master_key(3, 5).unwrap();
//! assert_eq!(shares.len(), 5);
//!
//! // Distribute shares to different custodians/locations
//! // Share 1 -> Custodian A (secure vault)
//! // Share 2 -> Custodian B (bank safe deposit)
//! // Share 3 -> Custodian C (offline storage)
//! // Share 4 -> Custodian D (disaster recovery site)
//! // Share 5 -> Custodian E (escrow service)
//!
//! // Recovery: collect any 3 shares
//! let mut recovery_manager = SimpleBackupManager::new();
//! let recovery_shares = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
//! recovery_manager.recover_master_key(&recovery_shares).unwrap();
//!
//! // Verify recovery was successful
//! assert_eq!(recovery_manager.get_master_key(), Some(master_key.as_slice()));
//! ```
//!
//! ## Incremental Backups
//!
//! For large key stores, use incremental backups to only export changed keys:
//!
//! ```rust,ignore
//! use hsm_backup::incremental::{IncrementalBackup, BackupState};
//!
//! // Initialize incremental backup tracking
//! let mut backup_state = BackupState::new();
//!
//! // First backup: full backup
//! let full_backup = IncrementalBackup::create_full(&key_store, password)?;
//!
//! // Later: incremental backup (only changed keys)
//! let incremental = IncrementalBackup::create_incremental(
//!     &key_store,
//!     &backup_state,
//!     password,
//! )?;
//!
//! // Restore: apply full + incremental
//! let restored = IncrementalBackup::restore(&full_backup, &[incremental], password)?;
//! ```
//!
//! ## Backup Verification
//!
//! Always verify backups before relying on them for disaster recovery:
//!
//! ```rust,ignore
//! use hsm_backup::{BackupVerifier, VerificationResult};
//!
//! let verifier = BackupVerifier::new();
//!
//! // Verify backup integrity without decrypting
//! let result = verifier.verify_integrity(&backup_data)?;
//! assert!(result.is_valid());
//!
//! // Full verification (decrypt and validate contents)
//! let result = verifier.verify_full(&backup_data, password)?;
//! match result {
//!     VerificationResult::Valid { key_count, .. } => {
//!         println!("Backup valid: {} keys", key_count);
//!     }
//!     VerificationResult::Corrupted { reason } => {
//!         eprintln!("Backup corrupted: {}", reason);
//!     }
//! }
//! ```
//!
//! ## Security Considerations
//!
//! - **Password Strength**: Use strong passwords (16+ characters, high entropy)
//! - **Share Distribution**: Store Shamir shares in geographically separate locations
//! - **Never Store Together**: Never store all shares or share + password together
//! - **Threshold Selection**: Choose threshold based on availability vs security trade-off
//!   - Higher threshold (4-of-5): More secure, harder to recover
//!   - Lower threshold (2-of-5): Easier recovery, higher collusion risk
//! - **Regular Testing**: Periodically verify backups can be restored
//! - **Secure Deletion**: Securely delete temporary files and memory after operations
//!
//! ## Performance Characteristics
//!
//! - **Full Backup**: <5 minutes for 100,000 keys
//! - **Incremental Backup**: <1 minute for typical daily changes
//! - **Compression Ratio**: ~60-70% reduction in backup size
//! - **Parallel Processing**: Scales with available CPU cores

pub mod compression;
pub mod error;
pub mod export;
pub mod health;
pub mod import;
pub mod incremental;
pub mod integrity;
pub mod parallel;
pub mod shamir;
pub mod streaming;
pub mod verification;

pub use error::{BackupError, Result};
pub use export::{EncryptedBackup, KeyExporter};
pub use import::{ImportedKeys, KeyImporter};
pub use shamir::{
    recover_master_key, split_master_key, SerializableShare, ShamirConfig, ShamirSecretSharing,
};
pub use verification::{BackupVerifier, VerificationResult};

use std::collections::HashMap;

/// Trait for managing backup and recovery operations
pub trait BackupManager {
    /// Export keys from a namespace with password encryption
    fn export_keys(&self, namespace: &str, password: &[u8]) -> Result<Vec<u8>>;

    /// Import keys from an encrypted backup
    fn import_keys(&mut self, backup: &[u8], password: &[u8]) -> Result<usize>;

    /// Split master key into Shamir shares
    fn split_master_key(&self, threshold: u8, shares: u8) -> Result<Vec<Vec<u8>>>;

    /// Recover master key from Shamir shares
    fn recover_master_key(&mut self, shares: &[Vec<u8>]) -> Result<()>;
}

/// Simple in-memory implementation of BackupManager for testing and demonstration
#[derive(Default)]
pub struct SimpleBackupManager {
    keys: HashMap<String, Vec<u8>>,
    master_key: Option<Vec<u8>>,
    exporter: KeyExporter,
    importer: KeyImporter,
}

impl SimpleBackupManager {
    /// Create a new simple backup manager
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            master_key: None,
            exporter: KeyExporter::new(),
            importer: KeyImporter::new(),
        }
    }

    /// Add a key to a namespace
    pub fn add_key(&mut self, namespace: &str, key_id: &str, key_data: Vec<u8>) {
        let key = format!("{}:{}", namespace, key_id);
        self.keys.insert(key, key_data);
    }

    /// Set the master key
    pub fn set_master_key(&mut self, master_key: Vec<u8>) {
        self.master_key = Some(master_key);
    }

    /// Get the master key
    pub fn get_master_key(&self) -> Option<&[u8]> {
        self.master_key.as_deref()
    }

    /// Get keys in a namespace
    pub fn get_namespace_keys(&self, namespace: &str) -> Vec<(String, Vec<u8>)> {
        let prefix = format!("{}:", namespace);
        self.keys
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl BackupManager for SimpleBackupManager {
    fn export_keys(&self, namespace: &str, password: &[u8]) -> Result<Vec<u8>> {
        // Collect all keys from the namespace
        let keys = self.get_namespace_keys(namespace);

        if keys.is_empty() {
            return Err(BackupError::EmptyData);
        }

        // Serialize keys to JSON
        let keys_json =
            serde_json::to_vec(&keys).map_err(|e| BackupError::Serialization(e.to_string()))?;

        // Export with encryption
        self.exporter
            .export_to_json(&keys_json, password, Some(namespace.to_string()))
    }

    fn import_keys(&mut self, backup: &[u8], password: &[u8]) -> Result<usize> {
        // Import and decrypt
        let imported = self.importer.import_from_json(backup, password)?;

        // Deserialize the keys
        let keys: Vec<(String, Vec<u8>)> = serde_json::from_slice(&imported.data)
            .map_err(|e| BackupError::Deserialization(e.to_string()))?;

        let count = keys.len();

        // Add keys to storage
        for (key_id, key_data) in keys {
            self.keys.insert(key_id, key_data);
        }

        Ok(count)
    }

    fn split_master_key(&self, threshold: u8, shares: u8) -> Result<Vec<Vec<u8>>> {
        let master_key = self.master_key.as_ref().ok_or(BackupError::EmptyData)?;

        let serializable_shares = split_master_key(master_key, threshold, shares)?;

        // Convert to raw bytes for output
        Ok(serializable_shares
            .into_iter()
            .map(|share| serde_json::to_vec(&share).unwrap_or_default())
            .collect())
    }

    fn recover_master_key(&mut self, shares: &[Vec<u8>]) -> Result<()> {
        // Deserialize shares
        let serializable_shares: Result<Vec<SerializableShare>> = shares
            .iter()
            .map(|s| {
                serde_json::from_slice(s).map_err(|e| BackupError::Deserialization(e.to_string()))
            })
            .collect();

        let serializable_shares = serializable_shares?;

        // Recover the master key
        let recovered_key = recover_master_key(&serializable_shares)?;

        self.master_key = Some(recovered_key);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_backup_manager_export_import() {
        let mut manager = SimpleBackupManager::new();

        // Add some keys
        manager.add_key("test", "key1", b"secret_data_1".to_vec());
        manager.add_key("test", "key2", b"secret_data_2".to_vec());

        let password = b"strong_password_123";

        // Export keys
        let backup = manager.export_keys("test", password).unwrap();

        // Create a new manager and import
        let mut new_manager = SimpleBackupManager::new();
        let count = new_manager.import_keys(&backup, password).unwrap();

        assert_eq!(count, 2);
    }

    #[test]
    fn test_simple_backup_manager_master_key() {
        let mut manager = SimpleBackupManager::new();

        let master_key = b"master_key_32_bytes_long_here!!!";
        manager.set_master_key(master_key.to_vec());

        // Split master key
        let shares = manager.split_master_key(3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Create new manager and recover
        let mut new_manager = SimpleBackupManager::new();
        new_manager.recover_master_key(&shares[0..3]).unwrap();

        assert_eq!(new_manager.get_master_key(), Some(master_key.as_slice()));
    }

    #[test]
    fn test_backup_manager_trait() {
        let mut manager = SimpleBackupManager::new();
        manager.add_key("prod", "api_key", b"secret".to_vec());

        let password = b"password";
        let backup = manager.export_keys("prod", password).unwrap();

        let mut new_manager = SimpleBackupManager::new();
        let count = new_manager.import_keys(&backup, password).unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn test_export_empty_namespace() {
        let manager = SimpleBackupManager::new();
        let result = manager.export_keys("empty", b"password");

        assert!(matches!(result, Err(BackupError::EmptyData)));
    }

    #[test]
    fn test_split_without_master_key() {
        let manager = SimpleBackupManager::new();
        let result = manager.split_master_key(3, 5);

        assert!(matches!(result, Err(BackupError::EmptyData)));
    }
}
