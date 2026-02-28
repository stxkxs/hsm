//! Backup health checks and restore verification.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{BackupError, Result};
use crate::export::EncryptedBackup;
use crate::import::KeyImporter;
use crate::integrity::BackupHealth;

/// Backup restore test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreTestResult {
    /// Whether restore was successful
    pub success: bool,
    /// Number of keys restored
    pub keys_restored: usize,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Duration of restore in milliseconds
    pub duration_ms: u64,
}

/// Backup health checker
pub struct BackupHealthChecker {
    importer: KeyImporter,
}

impl Default for BackupHealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl BackupHealthChecker {
    /// Create a new health checker
    pub fn new() -> Self {
        Self {
            importer: KeyImporter::new(),
        }
    }

    /// Perform comprehensive health check on a backup
    pub fn check_backup_health(&self, backup: &EncryptedBackup, password: &[u8]) -> BackupHealth {
        let mut health = BackupHealth::new();

        // 1. Check backup structure
        if let Err(e) = self.importer.verify_backup(backup) {
            health.add_error(format!("Backup structure invalid: {}", e));
            return health;
        }

        // 2. Check password
        match self.importer.check_password(backup, password) {
            Ok(true) => {}
            Ok(false) => {
                health.add_error("Password verification failed".to_string());
                return health;
            }
            Err(e) => {
                health.add_error(format!("Password check error: {}", e));
                return health;
            }
        }

        // 3. Attempt decryption
        match self.importer.import_keys(backup, password) {
            Ok(imported) => {
                if imported.data.is_empty() {
                    health.add_warning("Backup contains no data".to_string());
                }
            }
            Err(e) => {
                health.add_error(format!("Decryption failed: {}", e));
                return health;
            }
        }

        // 4. Check metadata
        if backup.timestamp <= 0 {
            health.add_warning("Invalid timestamp".to_string());
        }

        // 5. Check encryption data size
        if backup.encrypted_data.len() < 16 {
            health.add_warning("Suspiciously small encrypted data".to_string());
        }

        health
    }

    /// Test restore capability
    pub fn test_restore(&self, backup: &EncryptedBackup, password: &[u8]) -> RestoreTestResult {
        let start = std::time::Instant::now();
        let mut result = RestoreTestResult {
            success: false,
            keys_restored: 0,
            errors: Vec::new(),
            duration_ms: 0,
        };

        match self.importer.import_keys(backup, password) {
            Ok(imported) => {
                result.success = true;
                result.keys_restored = imported.key_count;
            }
            Err(e) => {
                result.errors.push(format!("Restore failed: {}", e));
            }
        }

        result.duration_ms = start.elapsed().as_millis() as u64;
        result
    }

    /// Verify backup can be fully restored
    pub fn verify_restorable(&self, backup: &EncryptedBackup, password: &[u8]) -> Result<()> {
        // Try to import
        let imported = self.importer.import_keys(backup, password)?;

        // Verify we got data
        if imported.data.is_empty() {
            return Err(BackupError::EmptyData);
        }

        // Verify key count matches
        if imported.key_count == 0 {
            return Err(BackupError::InvalidFormat("No keys in backup".to_string()));
        }

        Ok(())
    }

    /// Sample restore test (restore first N keys)
    pub fn sample_restore_test(
        &self,
        backup: &EncryptedBackup,
        password: &[u8],
        sample_size: usize,
    ) -> Result<RestoreTestResult> {
        let start = std::time::Instant::now();
        let mut result = RestoreTestResult {
            success: false,
            keys_restored: 0,
            errors: Vec::new(),
            duration_ms: 0,
        };

        match self.importer.import_keys(backup, password) {
            Ok(imported) => {
                let keys_to_verify = sample_size.min(imported.key_count);
                result.success = true;
                result.keys_restored = keys_to_verify;
            }
            Err(e) => {
                result.errors.push(format!("Sample restore failed: {}", e));
            }
        }

        result.duration_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// Generate health report
    pub fn generate_health_report(
        &self,
        backup: &EncryptedBackup,
        password: &[u8],
    ) -> HashMap<String, String> {
        let mut report = HashMap::new();

        // Basic info
        report.insert("version".to_string(), backup.version.to_string());
        report.insert("timestamp".to_string(), backup.timestamp.to_string());
        report.insert(
            "encrypted_size".to_string(),
            backup.encrypted_data.len().to_string(),
        );

        // Namespace
        if let Some(ns) = &backup.namespace {
            report.insert("namespace".to_string(), ns.clone());
        }

        // Health check
        let health = self.check_backup_health(backup, password);
        report.insert(
            "health_status".to_string(),
            if health.is_healthy() {
                "HEALTHY".to_string()
            } else {
                "UNHEALTHY".to_string()
            },
        );
        report.insert("error_count".to_string(), health.errors.len().to_string());
        report.insert(
            "warning_count".to_string(),
            health.warnings.len().to_string(),
        );

        // Restore test
        let restore_result = self.test_restore(backup, password);
        report.insert(
            "restore_test".to_string(),
            if restore_result.success {
                "PASS".to_string()
            } else {
                "FAIL".to_string()
            },
        );
        report.insert(
            "keys_restored".to_string(),
            restore_result.keys_restored.to_string(),
        );
        report.insert(
            "restore_duration_ms".to_string(),
            restore_result.duration_ms.to_string(),
        );

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::KeyExporter;

    #[test]
    fn test_check_backup_health() {
        let exporter = KeyExporter::new();
        let checker = BackupHealthChecker::new();

        let password = b"test-password-1234";
        let backup = exporter.export_keys(b"test_data", password, None).unwrap();

        let health = checker.check_backup_health(&backup, password);
        assert!(health.is_healthy());
        assert!(health.errors.is_empty());
    }

    #[test]
    fn test_check_wrong_password() {
        let exporter = KeyExporter::new();
        let checker = BackupHealthChecker::new();

        let backup = exporter
            .export_keys(b"test_data", b"correct-password1", None)
            .unwrap();

        let health = checker.check_backup_health(&backup, b"wrong");
        assert!(!health.is_healthy());
        assert!(!health.errors.is_empty());
    }

    #[test]
    fn test_restore_capability() {
        let exporter = KeyExporter::new();
        let checker = BackupHealthChecker::new();

        let password = b"test-password-1234";
        let backup = exporter.export_keys(b"test_data", password, None).unwrap();

        let result = checker.test_restore(&backup, password);
        assert!(result.success);
        assert_eq!(result.keys_restored, 1);
        assert!(result.duration_ms > 0);
    }

    #[test]
    fn test_verify_restorable() {
        let exporter = KeyExporter::new();
        let checker = BackupHealthChecker::new();

        let password = b"test-password-1234";
        let backup = exporter.export_keys(b"test_data", password, None).unwrap();

        assert!(checker.verify_restorable(&backup, password).is_ok());
    }

    #[test]
    fn test_sample_restore() {
        let exporter = KeyExporter::new();
        let checker = BackupHealthChecker::new();

        let password = b"test-password-1234";
        let backup = exporter.export_keys(b"test_data", password, None).unwrap();

        let result = checker.sample_restore_test(&backup, password, 10).unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_health_report() {
        let exporter = KeyExporter::new();
        let checker = BackupHealthChecker::new();

        let password = b"test-password-1234";
        let backup = exporter
            .export_keys(b"test_data", password, Some("test_ns".to_string()))
            .unwrap();

        let report = checker.generate_health_report(&backup, password);

        assert_eq!(report.get("version"), Some(&"1".to_string()));
        assert_eq!(report.get("health_status"), Some(&"HEALTHY".to_string()));
        assert_eq!(report.get("restore_test"), Some(&"PASS".to_string()));
        assert_eq!(report.get("namespace"), Some(&"test_ns".to_string()));
    }

    #[test]
    fn test_corrupted_backup() {
        let exporter = KeyExporter::new();
        let checker = BackupHealthChecker::new();

        let password = b"test-password-1234";
        let mut backup = exporter.export_keys(b"test_data", password, None).unwrap();

        // Corrupt the data
        backup.encrypted_data[0] ^= 0xFF;

        let health = checker.check_backup_health(&backup, password);
        assert!(!health.is_healthy());

        let result = checker.test_restore(&backup, password);
        assert!(!result.success);
    }

    #[test]
    fn test_empty_backup() {
        let exporter = KeyExporter::new();

        // This should fail during export
        let result = exporter.export_keys(&[], b"test-password-1234", None);
        assert!(result.is_err());
    }
}
