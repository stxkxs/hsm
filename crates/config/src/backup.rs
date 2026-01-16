//! Configuration backup and restore functionality.
//!
//! This module provides automatic backup of configuration files before changes
//! and restoration capabilities.

use crate::schema::HsmConfig;
use chrono::{DateTime, Utc};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors that can occur during backup/restore operations.
#[derive(Error, Debug)]
pub enum BackupError {
    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Backup not found
    #[error("Backup not found: {0}")]
    BackupNotFound(String),

    /// Invalid backup directory
    #[error("Invalid backup directory")]
    InvalidBackupDir,
}

pub type Result<T> = std::result::Result<T, BackupError>;

/// Configuration backup manager.
///
/// Provides automatic backup of configuration files with timestamped versions
/// and restoration capabilities.
///
/// # Examples
///
/// ```rust,no_run
/// use hsm_config::backup::BackupManager;
/// use hsm_config::HsmConfig;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let manager = BackupManager::new("backups")?;
///
/// // Create a backup
/// let config = HsmConfig::default();
/// let backup_path = manager.create_backup(&config, "config.toml")?;
/// println!("Backup created at: {:?}", backup_path);
///
/// // List all backups
/// let backups = manager.list_backups("config.toml")?;
/// for backup in backups {
///     println!("Backup: {:?}", backup);
/// }
///
/// // Restore from latest backup
/// let restored = manager.restore_latest("config.toml")?;
/// # Ok(())
/// # }
/// ```
pub struct BackupManager {
    backup_dir: PathBuf,
}

/// Information about a backup file.
#[derive(Debug, Clone)]
pub struct BackupInfo {
    /// Path to the backup file
    pub path: PathBuf,
    /// Original config file name
    pub original_name: String,
    /// Timestamp when backup was created
    pub timestamp: DateTime<Utc>,
    /// Size of the backup file in bytes
    pub size: u64,
}

impl BackupManager {
    /// Create a new backup manager.
    ///
    /// # Arguments
    ///
    /// * `backup_dir` - Directory where backups will be stored
    ///
    /// # Errors
    ///
    /// Returns an error if the backup directory cannot be created.
    pub fn new<P: AsRef<Path>>(backup_dir: P) -> Result<Self> {
        let backup_dir = backup_dir.as_ref().to_path_buf();

        // Create backup directory if it doesn't exist
        if !backup_dir.exists() {
            fs::create_dir_all(&backup_dir)?;
        }

        Ok(Self { backup_dir })
    }

    /// Create a backup of a configuration.
    ///
    /// The backup file will be named with a timestamp:
    /// `<original_name>.backup.<timestamp>.toml`
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration to backup
    /// * `original_name` - Original configuration file name (for reference)
    ///
    /// # Returns
    ///
    /// Returns the path to the created backup file.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or file writing fails.
    pub fn create_backup(&self, config: &HsmConfig, original_name: &str) -> Result<PathBuf> {
        let timestamp = Utc::now();
        let timestamp_str = timestamp.format("%Y%m%d_%H%M%S_%3f").to_string();

        let backup_name = format!(
            "{}.backup.{}.toml",
            original_name
                .trim_end_matches(".toml")
                .trim_end_matches(".yaml"),
            timestamp_str
        );

        let backup_path = self.backup_dir.join(&backup_name);

        // Serialize config
        let content = toml::to_string_pretty(config)
            .map_err(|e| BackupError::SerializationError(e.to_string()))?;

        // Write to file
        fs::write(&backup_path, content)?;

        Ok(backup_path)
    }

    /// Create a backup from an existing file.
    ///
    /// This is useful for backing up before making changes to a file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the configuration file to backup
    ///
    /// # Returns
    ///
    /// Returns the path to the created backup file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or copied.
    pub fn create_backup_from_file<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf> {
        let path = path.as_ref();
        let timestamp = Utc::now();
        let timestamp_str = timestamp.format("%Y%m%d_%H%M%S_%3f").to_string();

        let original_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(BackupError::InvalidBackupDir)?;

        let backup_name = format!(
            "{}.backup.{}.toml",
            original_name
                .trim_end_matches(".toml")
                .trim_end_matches(".yaml"),
            timestamp_str
        );

        let backup_path = self.backup_dir.join(&backup_name);

        // Copy file
        fs::copy(path, &backup_path)?;

        Ok(backup_path)
    }

    /// List all backups for a given configuration file.
    ///
    /// # Arguments
    ///
    /// * `original_name` - Original configuration file name
    ///
    /// # Returns
    ///
    /// Returns a list of backup information, sorted by timestamp (newest first).
    ///
    /// # Errors
    ///
    /// Returns an error if the backup directory cannot be read.
    pub fn list_backups(&self, original_name: &str) -> Result<Vec<BackupInfo>> {
        let base_name = original_name
            .trim_end_matches(".toml")
            .trim_end_matches(".yaml");
        let prefix = format!("{}.backup.", base_name);

        let mut backups = Vec::new();

        for entry in fs::read_dir(&self.backup_dir)? {
            let entry = entry?;
            let path = entry.path();

            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.starts_with(&prefix) && file_name.ends_with(".toml") {
                    // Extract timestamp from filename
                    if let Some(timestamp_str) = file_name
                        .strip_prefix(&prefix)
                        .and_then(|s| s.strip_suffix(".toml"))
                    {
                        // Parse timestamp (format: YYYYMMDD_HHMMSS_mmm)
                        // Try to parse, if it fails, skip this file
                        if let Ok(naive_dt) = chrono::NaiveDateTime::parse_from_str(
                            timestamp_str,
                            "%Y%m%d_%H%M%S_%3f",
                        ) {
                            let timestamp =
                                DateTime::<Utc>::from_naive_utc_and_offset(naive_dt, Utc);
                            let metadata = fs::metadata(&path)?;

                            backups.push(BackupInfo {
                                path: path.clone(),
                                original_name: original_name.to_string(),
                                timestamp: timestamp.with_timezone(&Utc),
                                size: metadata.len(),
                            });
                        }
                    }
                }
            }
        }

        // Sort by timestamp (newest first)
        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(backups)
    }

    /// Restore configuration from a specific backup.
    ///
    /// # Arguments
    ///
    /// * `backup_path` - Path to the backup file
    ///
    /// # Returns
    ///
    /// Returns the restored configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or deserialized.
    pub fn restore_from_backup<P: AsRef<Path>>(&self, backup_path: P) -> Result<HsmConfig> {
        let content = fs::read_to_string(backup_path.as_ref())?;

        let config: HsmConfig = toml::from_str(&content)
            .map_err(|e| BackupError::DeserializationError(e.to_string()))?;

        Ok(config)
    }

    /// Restore configuration from the latest backup.
    ///
    /// # Arguments
    ///
    /// * `original_name` - Original configuration file name
    ///
    /// # Returns
    ///
    /// Returns the restored configuration from the most recent backup.
    ///
    /// # Errors
    ///
    /// Returns an error if no backups exist or restoration fails.
    pub fn restore_latest(&self, original_name: &str) -> Result<HsmConfig> {
        let backups = self.list_backups(original_name)?;

        let latest = backups
            .first()
            .ok_or_else(|| BackupError::BackupNotFound(original_name.to_string()))?;

        self.restore_from_backup(&latest.path)
    }

    /// Clean up old backups, keeping only the most recent N backups.
    ///
    /// # Arguments
    ///
    /// * `original_name` - Original configuration file name
    /// * `keep_count` - Number of recent backups to keep
    ///
    /// # Returns
    ///
    /// Returns the number of backups deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if backup listing or deletion fails.
    pub fn cleanup_old_backups(&self, original_name: &str, keep_count: usize) -> Result<usize> {
        let backups = self.list_backups(original_name)?;

        let mut deleted = 0;
        for backup in backups.iter().skip(keep_count) {
            fs::remove_file(&backup.path)?;
            deleted += 1;
        }

        Ok(deleted)
    }

    /// Get the total size of all backups for a configuration file.
    ///
    /// # Arguments
    ///
    /// * `original_name` - Original configuration file name
    ///
    /// # Returns
    ///
    /// Returns the total size in bytes.
    pub fn get_total_backup_size(&self, original_name: &str) -> Result<u64> {
        let backups = self.list_backups(original_name)?;
        Ok(backups.iter().map(|b| b.size).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_and_restore_backup() {
        let temp_dir = TempDir::new().unwrap();
        let manager = BackupManager::new(temp_dir.path()).unwrap();

        let config = HsmConfig::default();
        let backup_path = manager.create_backup(&config, "config.toml").unwrap();

        assert!(backup_path.exists());

        let restored = manager.restore_from_backup(&backup_path).unwrap();
        assert_eq!(config, restored);
    }

    #[test]
    fn test_list_backups() {
        let temp_dir = TempDir::new().unwrap();
        let manager = BackupManager::new(temp_dir.path()).unwrap();

        let config = HsmConfig::default();

        // Create multiple backups
        manager.create_backup(&config, "config.toml").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        manager.create_backup(&config, "config.toml").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        manager.create_backup(&config, "config.toml").unwrap();

        let backups = manager.list_backups("config.toml").unwrap();
        assert_eq!(backups.len(), 3);

        // Should be sorted by timestamp (newest first)
        assert!(backups[0].timestamp >= backups[1].timestamp);
        assert!(backups[1].timestamp >= backups[2].timestamp);
    }

    #[test]
    fn test_restore_latest() {
        let temp_dir = TempDir::new().unwrap();
        let manager = BackupManager::new(temp_dir.path()).unwrap();

        let mut config = HsmConfig::default();
        manager.create_backup(&config, "config.toml").unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));

        // Create another backup with different port
        config.server.port = 9999;
        manager.create_backup(&config, "config.toml").unwrap();

        // Restore latest should get the second backup
        let restored = manager.restore_latest("config.toml").unwrap();
        assert_eq!(restored.server.port, 9999);
    }

    #[test]
    fn test_cleanup_old_backups() {
        let temp_dir = TempDir::new().unwrap();
        let manager = BackupManager::new(temp_dir.path()).unwrap();

        let config = HsmConfig::default();

        // Create 5 backups
        for _ in 0..5 {
            manager.create_backup(&config, "config.toml").unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let backups = manager.list_backups("config.toml").unwrap();
        assert_eq!(backups.len(), 5);

        // Keep only 2 most recent
        let deleted = manager.cleanup_old_backups("config.toml", 2).unwrap();
        assert_eq!(deleted, 3);

        let backups = manager.list_backups("config.toml").unwrap();
        assert_eq!(backups.len(), 2);
    }

    #[test]
    fn test_backup_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let manager = BackupManager::new(temp_dir.path()).unwrap();

        let result = manager.restore_latest("nonexistent.toml");
        assert!(matches!(result, Err(BackupError::BackupNotFound(_))));
    }

    #[test]
    fn test_get_total_backup_size() {
        let temp_dir = TempDir::new().unwrap();
        let manager = BackupManager::new(temp_dir.path()).unwrap();

        let config = HsmConfig::default();

        manager.create_backup(&config, "config.toml").unwrap();
        manager.create_backup(&config, "config.toml").unwrap();

        let total_size = manager.get_total_backup_size("config.toml").unwrap();
        assert!(total_size > 0);
    }
}
