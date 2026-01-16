//! Checksum Module
//!
//! Provides corruption detection via SHA-256 checksums.

use crate::backend::{StorageError, StorageResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Size of SHA-256 checksum in bytes
const CHECKSUM_SIZE: usize = 32;

/// A SHA-256 checksum for data integrity verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checksum([u8; CHECKSUM_SIZE]);

impl Checksum {
    /// Compute a checksum from data
    pub fn compute(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut checksum = [0u8; CHECKSUM_SIZE];
        checksum.copy_from_slice(&result);
        Self(checksum)
    }

    /// Verify that data matches this checksum
    ///
    /// # Arguments
    ///
    /// * `data` - Data to verify
    ///
    /// # Errors
    ///
    /// Returns an error if the checksum doesn't match
    pub fn verify(&self, data: &[u8]) -> StorageResult<()> {
        let computed = Self::compute(data);
        if computed != *self {
            return Err(StorageError::CorruptionDetected(
                "Checksum mismatch".to_string(),
            ));
        }
        Ok(())
    }

    /// Get the raw checksum bytes
    pub fn as_bytes(&self) -> &[u8; CHECKSUM_SIZE] {
        &self.0
    }

    /// Create a checksum from raw bytes
    pub fn from_bytes(bytes: [u8; CHECKSUM_SIZE]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for Checksum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Data with an associated checksum for integrity verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksummedData {
    pub data: Vec<u8>,
    pub checksum: Checksum,
}

impl ChecksummedData {
    /// Create checksummed data from raw bytes
    pub fn new(data: Vec<u8>) -> Self {
        let checksum = Checksum::compute(&data);
        Self { data, checksum }
    }

    /// Verify the data integrity
    ///
    /// # Errors
    ///
    /// Returns an error if the checksum doesn't match the data
    pub fn verify(&self) -> StorageResult<()> {
        self.checksum.verify(&self.data)
    }

    /// Get a reference to the data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consume self and return the data if verification passes
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails
    pub fn into_verified_data(self) -> StorageResult<Vec<u8>> {
        self.verify()?;
        Ok(self.data)
    }
}

/// Metadata for a stored key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Checksum of the encrypted key data
    pub checksum: Checksum,
    /// Timestamp when the key was stored (Unix epoch)
    pub timestamp: u64,
    /// Size of the encrypted data in bytes
    pub size: u64,
    /// Version of the storage format
    pub version: u32,
}

impl KeyMetadata {
    /// Create new metadata for encrypted key data
    pub fn new(encrypted_data: &[u8]) -> Self {
        Self {
            checksum: Checksum::compute(encrypted_data),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            size: encrypted_data.len() as u64,
            version: 1,
        }
    }

    /// Verify that encrypted data matches this metadata
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Checksum doesn't match
    /// - Size doesn't match
    pub fn verify(&self, encrypted_data: &[u8]) -> StorageResult<()> {
        // Check size
        if encrypted_data.len() as u64 != self.size {
            return Err(StorageError::CorruptionDetected(format!(
                "Size mismatch: expected {}, got {}",
                self.size,
                encrypted_data.len()
            )));
        }

        // Check checksum
        self.checksum.verify(encrypted_data)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_compute() {
        let data = b"test data";
        let checksum = Checksum::compute(data);
        assert_eq!(checksum.as_bytes().len(), CHECKSUM_SIZE);
    }

    #[test]
    fn test_checksum_verify_success() {
        let data = b"test data";
        let checksum = Checksum::compute(data);
        assert!(checksum.verify(data).is_ok());
    }

    #[test]
    fn test_checksum_verify_failure() {
        let data1 = b"test data";
        let data2 = b"different data";
        let checksum = Checksum::compute(data1);
        assert!(checksum.verify(data2).is_err());
    }

    #[test]
    fn test_checksum_deterministic() {
        let data = b"test data";
        let checksum1 = Checksum::compute(data);
        let checksum2 = Checksum::compute(data);
        assert_eq!(checksum1, checksum2);
    }

    #[test]
    fn test_checksum_display() {
        let data = b"test";
        let checksum = Checksum::compute(data);
        let display = format!("{}", checksum);
        assert_eq!(display.len(), CHECKSUM_SIZE * 2); // Each byte is 2 hex chars
    }

    #[test]
    fn test_checksummed_data_new() {
        let data = vec![1, 2, 3, 4, 5];
        let checksummed = ChecksummedData::new(data.clone());
        assert_eq!(checksummed.data, data);
    }

    #[test]
    fn test_checksummed_data_verify() {
        let data = vec![1, 2, 3, 4, 5];
        let checksummed = ChecksummedData::new(data);
        assert!(checksummed.verify().is_ok());
    }

    #[test]
    fn test_checksummed_data_corrupted() {
        let data = vec![1, 2, 3, 4, 5];
        let mut checksummed = ChecksummedData::new(data);
        checksummed.data[0] = 99; // Corrupt the data
        assert!(checksummed.verify().is_err());
    }

    #[test]
    fn test_checksummed_data_into_verified() {
        let data = vec![1, 2, 3, 4, 5];
        let checksummed = ChecksummedData::new(data.clone());
        let verified = checksummed.into_verified_data().unwrap();
        assert_eq!(verified, data);
    }

    #[test]
    fn test_key_metadata_new() {
        let data = b"encrypted key data";
        let metadata = KeyMetadata::new(data);
        assert_eq!(metadata.size, data.len() as u64);
        assert_eq!(metadata.version, 1);
        assert!(metadata.timestamp > 0);
    }

    #[test]
    fn test_key_metadata_verify_success() {
        let data = b"encrypted key data";
        let metadata = KeyMetadata::new(data);
        assert!(metadata.verify(data).is_ok());
    }

    #[test]
    fn test_key_metadata_verify_size_mismatch() {
        let data1 = b"encrypted key data";
        let data2 = b"different";
        let metadata = KeyMetadata::new(data1);
        assert!(metadata.verify(data2).is_err());
    }

    #[test]
    fn test_key_metadata_verify_checksum_mismatch() {
        let data1 = b"12345678901234567890"; // 20 bytes
        let data2 = b"09876543210987654321"; // 20 bytes, same size
        let metadata = KeyMetadata::new(data1);
        assert!(metadata.verify(data2).is_err());
    }
}
