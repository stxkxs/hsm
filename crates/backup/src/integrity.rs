//! Backup integrity verification using HMAC.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BackupError, Result};

type HmacSha256 = Hmac<Sha256>;

/// HMAC tag for integrity verification
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IntegrityTag {
    /// HMAC-SHA256 tag
    pub tag: Vec<u8>,
    /// Timestamp when tag was created
    pub created_at: i64,
}

/// Verified backup with integrity protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedBackup<T> {
    /// The backup data
    pub data: T,
    /// Integrity tag
    pub integrity_tag: IntegrityTag,
    /// Timestamp of backup
    pub timestamp: i64,
}

/// Integrity manager for backup verification
#[derive(ZeroizeOnDrop)]
pub struct IntegrityManager {
    /// Secret key for HMAC (32 bytes)
    integrity_key: Vec<u8>,
}

impl IntegrityManager {
    /// Create a new integrity manager with a given key
    pub fn new(integrity_key: Vec<u8>) -> Result<Self> {
        if integrity_key.len() != 32 {
            return Err(BackupError::InvalidKeySize);
        }

        Ok(Self { integrity_key })
    }

    /// Generate a random integrity key
    pub fn generate_key() -> Vec<u8> {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    /// Create a verified backup with integrity tag
    pub fn create_verified<T: Serialize>(&self, data: &T) -> Result<VerifiedBackup<T>>
    where
        T: Clone,
    {
        let data_bytes =
            postcard::to_allocvec(data).map_err(|e| BackupError::Serialization(e.to_string()))?;

        let tag = self.compute_hmac(&data_bytes)?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Ok(VerifiedBackup {
            data: data.clone(),
            integrity_tag: IntegrityTag {
                tag,
                created_at: timestamp,
            },
            timestamp,
        })
    }

    /// Verify a backup's integrity
    pub fn verify<T: Serialize>(&self, verified_backup: &VerifiedBackup<T>) -> Result<()> {
        let data_bytes = postcard::to_allocvec(&verified_backup.data)
            .map_err(|e| BackupError::Serialization(e.to_string()))?;

        let computed_tag = self.compute_hmac(&data_bytes)?;

        // Constant-time comparison
        if computed_tag.len() != verified_backup.integrity_tag.tag.len() {
            return Err(BackupError::IntegrityCheckFailed);
        }

        let mut mac = HmacSha256::new_from_slice(&self.integrity_key)
            .map_err(|_| BackupError::IntegrityCheckFailed)?;
        mac.update(&data_bytes);

        mac.verify_slice(&verified_backup.integrity_tag.tag)
            .map_err(|_| BackupError::IntegrityCheckFailed)?;

        Ok(())
    }

    /// Compute HMAC-SHA256 tag for data
    fn compute_hmac(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&self.integrity_key)
            .map_err(|_| BackupError::IntegrityCheckFailed)?;

        mac.update(data);
        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }

    /// Compute HMAC tag for raw bytes (without serialization)
    pub fn tag_bytes(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.compute_hmac(data)
    }

    /// Verify HMAC tag for raw bytes
    pub fn verify_bytes(&self, data: &[u8], tag: &[u8]) -> Result<()> {
        let mut mac = HmacSha256::new_from_slice(&self.integrity_key)
            .map_err(|_| BackupError::IntegrityCheckFailed)?;

        mac.update(data);
        mac.verify_slice(tag)
            .map_err(|_| BackupError::IntegrityCheckFailed)?;

        Ok(())
    }
}

/// Backup health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupHealth {
    /// Whether backup is healthy
    pub is_healthy: bool,
    /// List of errors found
    pub errors: Vec<String>,
    /// List of warnings
    pub warnings: Vec<String>,
    /// Health check timestamp
    pub checked_at: i64,
}

impl BackupHealth {
    /// Create a new healthy status
    pub fn new() -> Self {
        Self {
            is_healthy: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            checked_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        }
    }

    /// Add an error (marks as unhealthy)
    pub fn add_error(&mut self, error: String) {
        self.is_healthy = false;
        self.errors.push(error);
    }

    /// Add a warning (keeps healthy status)
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Check if healthy
    pub fn is_healthy(&self) -> bool {
        self.is_healthy
    }
}

impl Default for BackupHealth {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestBackup {
        id: String,
        data: Vec<u8>,
    }

    #[test]
    fn test_create_and_verify() {
        let key = IntegrityManager::generate_key();
        let manager = IntegrityManager::new(key).unwrap();

        let backup = TestBackup {
            id: "test1".to_string(),
            data: vec![1, 2, 3, 4, 5],
        };

        let verified = manager.create_verified(&backup).unwrap();
        assert!(manager.verify(&verified).is_ok());
    }

    #[test]
    fn test_invalid_key_size() {
        let short_key = vec![0u8; 16]; // Too short
        assert!(IntegrityManager::new(short_key).is_err());

        let long_key = vec![0u8; 64]; // Too long
        assert!(IntegrityManager::new(long_key).is_err());
    }

    #[test]
    fn test_tampered_data() {
        let key = IntegrityManager::generate_key();
        let manager = IntegrityManager::new(key).unwrap();

        let backup = TestBackup {
            id: "test1".to_string(),
            data: vec![1, 2, 3],
        };

        let mut verified = manager.create_verified(&backup).unwrap();

        // Tamper with the data
        verified.data.data.push(99);

        // Verification should fail
        assert!(manager.verify(&verified).is_err());
    }

    #[test]
    fn test_tampered_tag() {
        let key = IntegrityManager::generate_key();
        let manager = IntegrityManager::new(key).unwrap();

        let backup = TestBackup {
            id: "test1".to_string(),
            data: vec![1, 2, 3],
        };

        let mut verified = manager.create_verified(&backup).unwrap();

        // Tamper with the tag
        verified.integrity_tag.tag[0] ^= 0xFF;

        // Verification should fail
        assert!(manager.verify(&verified).is_err());
    }

    #[test]
    fn test_different_keys() {
        let key1 = IntegrityManager::generate_key();
        let key2 = IntegrityManager::generate_key();

        let manager1 = IntegrityManager::new(key1).unwrap();
        let manager2 = IntegrityManager::new(key2).unwrap();

        let backup = TestBackup {
            id: "test1".to_string(),
            data: vec![1, 2, 3],
        };

        let verified = manager1.create_verified(&backup).unwrap();

        // Different key should fail verification
        assert!(manager2.verify(&verified).is_err());
    }

    #[test]
    fn test_tag_bytes() {
        let key = IntegrityManager::generate_key();
        let manager = IntegrityManager::new(key).unwrap();

        let data = b"test data for hmac";
        let tag = manager.tag_bytes(data).unwrap();

        assert_eq!(tag.len(), 32); // SHA-256 output
        assert!(manager.verify_bytes(data, &tag).is_ok());
    }

    #[test]
    fn test_verify_bytes_wrong_data() {
        let key = IntegrityManager::generate_key();
        let manager = IntegrityManager::new(key).unwrap();

        let data = b"original data";
        let tag = manager.tag_bytes(data).unwrap();

        let wrong_data = b"modified data";
        assert!(manager.verify_bytes(wrong_data, &tag).is_err());
    }

    #[test]
    fn test_backup_health() {
        let mut health = BackupHealth::new();
        assert!(health.is_healthy());
        assert!(health.errors.is_empty());

        health.add_warning("Minor issue".to_string());
        assert!(health.is_healthy());
        assert_eq!(health.warnings.len(), 1);

        health.add_error("Critical error".to_string());
        assert!(!health.is_healthy());
        assert_eq!(health.errors.len(), 1);
    }

    #[test]
    fn test_hmac_consistency() {
        let key = IntegrityManager::generate_key();
        let manager = IntegrityManager::new(key).unwrap();

        let data = b"test data";
        let tag1 = manager.tag_bytes(data).unwrap();
        let tag2 = manager.tag_bytes(data).unwrap();

        // Same data should produce same tag
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_generate_key() {
        let key1 = IntegrityManager::generate_key();
        let key2 = IntegrityManager::generate_key();

        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2); // Should be random
    }
}
