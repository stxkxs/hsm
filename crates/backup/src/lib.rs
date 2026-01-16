//! Backup and recovery module for HSM.
//!
//! This module provides functionality for:
//! - Encrypted key export and import
//! - Shamir's Secret Sharing for master key protection
//! - Backup verification and integrity checking
//! - Incremental backups for efficiency
//! - Parallel processing for performance
//! - Compression for reduced storage
//! - HMAC-based integrity verification

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
