//! Incremental backup support for efficient backup operations.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::error::{BackupError, Result};

/// Backup type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupType {
    /// Full backup containing all keys
    Full,
    /// Incremental backup containing only changed keys
    Incremental,
}

/// Key identifier
pub type KeyId = String;

/// Represents a key with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Unique identifier for the key
    pub id: KeyId,
    /// Encrypted key data
    pub data: Vec<u8>,
    /// Last modification timestamp
    pub modified_at: i64,
}

/// Incremental backup metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalBackupMetadata {
    /// Type of backup
    pub backup_type: BackupType,
    /// Backup ID
    pub id: String,
    /// Parent backup ID (for incremental backups)
    pub parent_id: Option<String>,
    /// Timestamp of backup creation
    pub timestamp: i64,
    /// List of key IDs in this backup
    pub key_ids: Vec<KeyId>,
    /// Total number of keys
    pub key_count: usize,
}

/// Incremental backup structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalBackup {
    /// Metadata
    pub metadata: IncrementalBackupMetadata,
    /// Keys in this backup
    pub keys: Vec<KeyEntry>,
}

impl IncrementalBackup {
    /// Create a new full backup
    pub fn new_full(id: String) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            metadata: IncrementalBackupMetadata {
                backup_type: BackupType::Full,
                id,
                parent_id: None,
                timestamp,
                key_ids: Vec::new(),
                key_count: 0,
            },
            keys: Vec::new(),
        }
    }

    /// Create a new incremental backup
    pub fn new_incremental(id: String, parent_id: String) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            metadata: IncrementalBackupMetadata {
                backup_type: BackupType::Incremental,
                id,
                parent_id: Some(parent_id),
                timestamp,
                key_ids: Vec::new(),
                key_count: 0,
            },
            keys: Vec::new(),
        }
    }

    /// Add a key to the backup
    pub fn add_key(&mut self, key: KeyEntry) {
        self.metadata.key_ids.push(key.id.clone());
        self.keys.push(key);
        self.metadata.key_count = self.keys.len();
    }

    /// Get backup type
    pub fn backup_type(&self) -> BackupType {
        self.metadata.backup_type
    }

    /// Get parent backup ID (for incremental backups)
    pub fn parent_id(&self) -> Option<&str> {
        self.metadata.parent_id.as_deref()
    }
}

/// Manages incremental backups
pub struct IncrementalBackupManager {
    /// Track last backup timestamp
    last_backup_timestamp: Option<i64>,
    /// Track changed keys
    changed_keys: HashSet<KeyId>,
}

impl Default for IncrementalBackupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalBackupManager {
    /// Create a new incremental backup manager
    pub fn new() -> Self {
        Self {
            last_backup_timestamp: None,
            changed_keys: HashSet::new(),
        }
    }

    /// Mark a key as changed
    pub fn mark_changed(&mut self, key_id: KeyId) {
        self.changed_keys.insert(key_id);
    }

    /// Get keys modified since last backup
    pub fn get_changed_keys(&self) -> Vec<KeyId> {
        self.changed_keys.iter().cloned().collect()
    }

    /// Filter keys modified since a given timestamp
    pub fn filter_keys_by_timestamp(
        &self,
        all_keys: &[KeyEntry],
        since_timestamp: i64,
    ) -> Vec<KeyEntry> {
        all_keys
            .iter()
            .filter(|k| k.modified_at > since_timestamp)
            .cloned()
            .collect()
    }

    /// Create a full backup
    pub fn create_full_backup(
        &mut self,
        backup_id: String,
        keys: Vec<KeyEntry>,
    ) -> IncrementalBackup {
        let mut backup = IncrementalBackup::new_full(backup_id);
        for key in keys {
            backup.add_key(key);
        }
        self.last_backup_timestamp = Some(backup.metadata.timestamp);
        self.changed_keys.clear();
        backup
    }

    /// Create an incremental backup
    pub fn create_incremental_backup(
        &mut self,
        backup_id: String,
        parent_id: String,
        keys: Vec<KeyEntry>,
    ) -> IncrementalBackup {
        let mut backup = IncrementalBackup::new_incremental(backup_id, parent_id);
        for key in keys {
            backup.add_key(key);
        }
        self.last_backup_timestamp = Some(backup.metadata.timestamp);
        self.changed_keys.clear();
        backup
    }

    /// Restore from a chain of backups (full + incrementals)
    pub fn restore_from_chain(
        &self,
        backups: &[IncrementalBackup],
    ) -> Result<HashMap<KeyId, KeyEntry>> {
        if backups.is_empty() {
            return Err(BackupError::EmptyData);
        }

        // Verify the first backup is a full backup
        if backups[0].backup_type() != BackupType::Full {
            return Err(BackupError::NoFullBackup);
        }

        let mut restored_keys: HashMap<KeyId, KeyEntry> = HashMap::new();

        // Restore full backup first
        for key in &backups[0].keys {
            restored_keys.insert(key.id.clone(), key.clone());
        }

        // Apply incremental backups in order
        for backup in &backups[1..] {
            for key in &backup.keys {
                restored_keys.insert(key.id.clone(), key.clone());
            }
        }

        Ok(restored_keys)
    }

    /// Validate a backup chain
    pub fn validate_chain(&self, backups: &[IncrementalBackup]) -> Result<()> {
        if backups.is_empty() {
            return Err(BackupError::EmptyData);
        }

        // First backup must be full
        if backups[0].backup_type() != BackupType::Full {
            return Err(BackupError::NoFullBackup);
        }

        // Validate chain continuity
        for i in 1..backups.len() {
            let backup = &backups[i];
            let expected_parent = &backups[i - 1].metadata.id;

            if backup.backup_type() != BackupType::Incremental {
                return Err(BackupError::InvalidFormat(
                    "Non-incremental backup in chain".to_string(),
                ));
            }

            match &backup.parent_id() {
                Some(parent) if parent == expected_parent => {}
                _ => {
                    return Err(BackupError::InvalidFormat(
                        "Broken backup chain".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key(id: &str, timestamp: i64) -> KeyEntry {
        KeyEntry {
            id: id.to_string(),
            data: format!("data_{}", id).into_bytes(),
            modified_at: timestamp,
        }
    }

    #[test]
    fn test_full_backup_creation() {
        let mut manager = IncrementalBackupManager::new();
        let keys = vec![create_test_key("key1", 100), create_test_key("key2", 200)];

        let backup = manager.create_full_backup("backup1".to_string(), keys);

        assert_eq!(backup.backup_type(), BackupType::Full);
        assert_eq!(backup.metadata.key_count, 2);
        assert_eq!(backup.parent_id(), None);
    }

    #[test]
    fn test_incremental_backup_creation() {
        let mut manager = IncrementalBackupManager::new();
        let keys = vec![create_test_key("key3", 300)];

        let backup =
            manager.create_incremental_backup("backup2".to_string(), "backup1".to_string(), keys);

        assert_eq!(backup.backup_type(), BackupType::Incremental);
        assert_eq!(backup.metadata.key_count, 1);
        assert_eq!(backup.parent_id(), Some("backup1"));
    }

    #[test]
    fn test_restore_from_chain() {
        let manager = IncrementalBackupManager::new();

        // Create backup chain
        let mut full_backup = IncrementalBackup::new_full("backup1".to_string());
        full_backup.add_key(create_test_key("key1", 100));
        full_backup.add_key(create_test_key("key2", 200));

        let mut inc_backup =
            IncrementalBackup::new_incremental("backup2".to_string(), "backup1".to_string());
        inc_backup.add_key(create_test_key("key2", 300)); // Updated key
        inc_backup.add_key(create_test_key("key3", 300)); // New key

        let chain = vec![full_backup, inc_backup];
        let restored = manager.restore_from_chain(&chain).unwrap();

        assert_eq!(restored.len(), 3);
        assert!(restored.contains_key("key1"));
        assert!(restored.contains_key("key2"));
        assert!(restored.contains_key("key3"));

        // Verify key2 has the updated timestamp
        assert_eq!(restored.get("key2").unwrap().modified_at, 300);
    }

    #[test]
    fn test_validate_chain() {
        let manager = IncrementalBackupManager::new();

        let full_backup = IncrementalBackup::new_full("backup1".to_string());
        let inc_backup =
            IncrementalBackup::new_incremental("backup2".to_string(), "backup1".to_string());

        let chain = vec![full_backup, inc_backup];
        assert!(manager.validate_chain(&chain).is_ok());
    }

    #[test]
    fn test_validate_broken_chain() {
        let manager = IncrementalBackupManager::new();

        let full_backup = IncrementalBackup::new_full("backup1".to_string());
        let inc_backup =
            IncrementalBackup::new_incremental("backup2".to_string(), "wrong_parent".to_string());

        let chain = vec![full_backup, inc_backup];
        assert!(manager.validate_chain(&chain).is_err());
    }

    #[test]
    fn test_no_full_backup_in_chain() {
        let manager = IncrementalBackupManager::new();

        let inc_backup =
            IncrementalBackup::new_incremental("backup1".to_string(), "backup0".to_string());

        let chain = vec![inc_backup];
        assert!(matches!(
            manager.validate_chain(&chain),
            Err(BackupError::NoFullBackup)
        ));
    }

    #[test]
    fn test_filter_keys_by_timestamp() {
        let manager = IncrementalBackupManager::new();
        let all_keys = vec![
            create_test_key("key1", 100),
            create_test_key("key2", 200),
            create_test_key("key3", 300),
        ];

        let filtered = manager.filter_keys_by_timestamp(&all_keys, 150);

        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].id, "key2");
        assert_eq!(filtered[1].id, "key3");
    }

    #[test]
    fn test_mark_changed() {
        let mut manager = IncrementalBackupManager::new();
        manager.mark_changed("key1".to_string());
        manager.mark_changed("key2".to_string());
        manager.mark_changed("key1".to_string()); // Duplicate

        let changed = manager.get_changed_keys();
        assert_eq!(changed.len(), 2);
    }
}
