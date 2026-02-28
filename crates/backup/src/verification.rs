//! Backup verification and integrity checking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::Result;
use crate::export::EncryptedBackup;
use crate::import::KeyImporter;
use crate::shamir::SerializableShare;

/// Result of backup verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationResult {
    /// Whether the backup is valid
    pub is_valid: bool,
    /// List of validation errors
    pub errors: Vec<String>,
    /// List of warnings
    pub warnings: Vec<String>,
    /// Backup metadata
    pub metadata: HashMap<String, String>,
}

impl VerificationResult {
    /// Create a new successful verification result
    pub fn success() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Create a failed verification result
    pub fn failed(error: String) -> Self {
        Self {
            is_valid: false,
            errors: vec![error],
            warnings: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add an error to the result
    pub fn add_error(&mut self, error: String) {
        self.is_valid = false;
        self.errors.push(error);
    }

    /// Add a warning to the result
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Add metadata
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Backup verifier
pub struct BackupVerifier {
    importer: KeyImporter,
}

impl Default for BackupVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl BackupVerifier {
    /// Create a new backup verifier
    pub fn new() -> Self {
        Self {
            importer: KeyImporter::new(),
        }
    }

    /// Verify an encrypted backup
    pub fn verify_backup(&self, backup: &EncryptedBackup) -> VerificationResult {
        let mut result = VerificationResult::success();

        // Check version
        if backup.version != 1 {
            result.add_error(format!("Unsupported version: {}", backup.version));
            return result;
        }
        result.add_metadata("version".to_string(), backup.version.to_string());

        // Verify backup structure using importer
        if let Err(e) = self.importer.verify_backup(backup) {
            result.add_error(format!("Backup structure validation failed: {}", e));
            return result;
        }

        // Check encrypted data size
        if backup.encrypted_data.is_empty() {
            result.add_error("Encrypted data is empty".to_string());
        } else {
            result.add_metadata(
                "encrypted_size".to_string(),
                backup.encrypted_data.len().to_string(),
            );
        }

        // Check timestamp validity
        if backup.timestamp <= 0 {
            result.add_warning("Invalid or missing timestamp".to_string());
        } else {
            result.add_metadata("timestamp".to_string(), backup.timestamp.to_string());
        }

        // Check namespace
        if let Some(ns) = &backup.namespace {
            result.add_metadata("namespace".to_string(), ns.clone());
        }

        // Verify metadata
        for (key, value) in &backup.metadata {
            result.add_metadata(format!("meta_{}", key), value.clone());
        }

        result
    }

    /// Verify backup with password
    pub fn verify_with_password(
        &self,
        backup: &EncryptedBackup,
        password: &[u8],
    ) -> VerificationResult {
        let mut result = self.verify_backup(backup);

        if !result.is_valid {
            return result;
        }

        // Verify password
        match self.importer.check_password(backup, password) {
            Ok(true) => {
                result.add_metadata("password_verified".to_string(), "true".to_string());
            }
            Ok(false) => {
                result.add_error("Password verification failed".to_string());
            }
            Err(e) => {
                result.add_error(format!("Password check error: {}", e));
            }
        }

        result
    }

    /// Verify backup by attempting full decryption
    pub fn verify_full(
        &self,
        backup: &EncryptedBackup,
        password: &[u8],
    ) -> Result<VerificationResult> {
        let mut result = self.verify_with_password(backup, password);

        if !result.is_valid {
            return Ok(result);
        }

        // Attempt to decrypt
        match self.importer.import_keys(backup, password) {
            Ok(imported) => {
                result.add_metadata(
                    "decrypted_size".to_string(),
                    imported.data.len().to_string(),
                );
                result.add_metadata("key_count".to_string(), imported.key_count.to_string());
            }
            Err(e) => {
                result.add_error(format!("Decryption failed: {}", e));
            }
        }

        Ok(result)
    }

    /// Verify a Shamir share
    pub fn verify_share(&self, share: &SerializableShare) -> VerificationResult {
        let mut result = VerificationResult::success();

        // Check share index
        if share.index == 0 {
            result.add_error("Invalid share index: 0".to_string());
        } else {
            result.add_metadata("index".to_string(), share.index.to_string());
        }

        // Check threshold
        if share.threshold == 0 {
            result.add_error("Invalid threshold: 0".to_string());
        } else if share.threshold == 1 {
            result.add_warning("Threshold of 1 provides no redundancy".to_string());
        }
        result.add_metadata("threshold".to_string(), share.threshold.to_string());

        // Check total shares
        if share.total_shares == 0 {
            result.add_error("Invalid total shares: 0".to_string());
        } else if share.total_shares < share.threshold {
            result.add_error(format!(
                "Total shares ({}) less than threshold ({})",
                share.total_shares, share.threshold
            ));
        }
        result.add_metadata("total_shares".to_string(), share.total_shares.to_string());

        // Check share data
        if share.data.is_empty() {
            result.add_error("Share data is empty".to_string());
        } else {
            result.add_metadata("data_size".to_string(), share.data.len().to_string());
        }

        result
    }

    /// Verify multiple shares for consistency
    pub fn verify_shares(&self, shares: &[SerializableShare]) -> VerificationResult {
        let mut result = VerificationResult::success();

        if shares.is_empty() {
            result.add_error("No shares provided".to_string());
            return result;
        }

        result.add_metadata("share_count".to_string(), shares.len().to_string());

        // Verify each share individually
        for (i, share) in shares.iter().enumerate() {
            let share_result = self.verify_share(share);
            if !share_result.is_valid {
                for error in share_result.errors {
                    result.add_error(format!("Share {}: {}", i + 1, error));
                }
            }
        }

        if !result.is_valid {
            return result;
        }

        // Check consistency
        let first_threshold = shares[0].threshold;
        let first_total = shares[0].total_shares;

        for (i, share) in shares.iter().enumerate().skip(1) {
            if share.threshold != first_threshold {
                result.add_error(format!(
                    "Share {} has inconsistent threshold: {} vs {}",
                    i + 1,
                    share.threshold,
                    first_threshold
                ));
            }
            if share.total_shares != first_total {
                result.add_error(format!(
                    "Share {} has inconsistent total shares: {} vs {}",
                    i + 1,
                    share.total_shares,
                    first_total
                ));
            }
        }

        // Check if we have enough shares
        if shares.len() < first_threshold as usize {
            result.add_warning(format!(
                "Only {} shares provided, need {} for recovery",
                shares.len(),
                first_threshold
            ));
        }

        // Check for duplicate indices
        let mut seen_indices = std::collections::HashSet::new();
        for share in shares {
            if !seen_indices.insert(share.index) {
                result.add_error(format!("Duplicate share index: {}", share.index));
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::KeyExporter;
    use crate::shamir::{ShamirConfig, ShamirSecretSharing};

    #[test]
    fn test_verify_backup() {
        let exporter = KeyExporter::new();
        let verifier = BackupVerifier::new();

        let backup = exporter
            .export_keys(b"test_data", b"test-password-1234", Some("test".to_string()))
            .unwrap();

        let result = verifier.verify_backup(&backup);
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_verify_with_password() {
        let exporter = KeyExporter::new();
        let verifier = BackupVerifier::new();

        let password = b"correct_password";
        let backup = exporter.export_keys(b"test_data", password, None).unwrap();

        let result = verifier.verify_with_password(&backup, password);
        assert!(result.is_valid);
        assert_eq!(
            result.metadata.get("password_verified"),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn test_verify_wrong_password() {
        let exporter = KeyExporter::new();
        let verifier = BackupVerifier::new();

        let backup = exporter
            .export_keys(b"test_data", b"correct-password1", None)
            .unwrap();

        let result = verifier.verify_with_password(&backup, b"wrong");
        assert!(!result.is_valid);
    }

    #[test]
    fn test_verify_full() {
        let exporter = KeyExporter::new();
        let verifier = BackupVerifier::new();

        let password = b"test-password-1234";
        let data = b"test_key_data";
        let backup = exporter.export_keys(data, password, None).unwrap();

        let result = verifier.verify_full(&backup, password).unwrap();
        assert!(result.is_valid);
        assert_eq!(
            result.metadata.get("decrypted_size"),
            Some(&data.len().to_string())
        );
    }

    #[test]
    fn test_verify_share() {
        let config = ShamirConfig::new(3, 5).unwrap();
        let shamir = ShamirSecretSharing::new(config);
        let verifier = BackupVerifier::new();

        let shares = shamir.split_secret(b"test_secret").unwrap();
        let result = verifier.verify_share(&shares[0]);

        assert!(result.is_valid);
        assert_eq!(result.metadata.get("threshold"), Some(&"3".to_string()));
        assert_eq!(result.metadata.get("total_shares"), Some(&"5".to_string()));
    }

    #[test]
    fn test_verify_shares() {
        let config = ShamirConfig::new(3, 5).unwrap();
        let shamir = ShamirSecretSharing::new(config);
        let verifier = BackupVerifier::new();

        let shares = shamir.split_secret(b"test_secret").unwrap();
        let result = verifier.verify_shares(&shares);

        assert!(result.is_valid);
        assert_eq!(result.metadata.get("share_count"), Some(&"5".to_string()));
    }

    #[test]
    fn test_verify_insufficient_shares() {
        let config = ShamirConfig::new(3, 5).unwrap();
        let shamir = ShamirSecretSharing::new(config);
        let verifier = BackupVerifier::new();

        let shares = shamir.split_secret(b"test_secret").unwrap();
        let result = verifier.verify_shares(&shares[0..2]);

        assert!(result.is_valid);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_verify_inconsistent_shares() {
        let verifier = BackupVerifier::new();

        let mut shares = vec![
            SerializableShare {
                index: 1,
                data: vec![1, 2, 3],
                threshold: 3,
                total_shares: 5,
            },
            SerializableShare {
                index: 2,
                data: vec![4, 5, 6],
                threshold: 2, // Different threshold
                total_shares: 5,
            },
        ];

        let result = verifier.verify_shares(&shares);
        assert!(!result.is_valid);

        // Fix threshold, break total
        shares[1].threshold = 3;
        shares[1].total_shares = 4;

        let result = verifier.verify_shares(&shares);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_verification_result() {
        let mut result = VerificationResult::success();
        assert!(result.is_valid);

        result.add_error("test error".to_string());
        assert!(!result.is_valid);
        assert_eq!(result.errors.len(), 1);

        result.add_warning("test warning".to_string());
        assert_eq!(result.warnings.len(), 1);

        result.add_metadata("key".to_string(), "value".to_string());
        assert_eq!(result.metadata.get("key"), Some(&"value".to_string()));
    }
}
