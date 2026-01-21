//! Integrity Protection
//!
//! Provides HMAC-based integrity protection for stored keys.

use crate::backend::{StorageError, StorageResult};
use crate::master_key::EncryptedData;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Key protected with HMAC integrity check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityProtectedKey {
    /// The encrypted key data
    pub encrypted_key: EncryptedData,
    /// HMAC of the encrypted key
    pub hmac: Vec<u8>,
    /// HMAC algorithm version (for future upgrades)
    pub version: u32,
}

impl IntegrityProtectedKey {
    /// Create a new integrity-protected key
    ///
    /// # Arguments
    ///
    /// * `encrypted_key` - The encrypted key data
    /// * `integrity_key` - HMAC key for integrity protection
    pub fn new(encrypted_key: EncryptedData, integrity_key: &[u8]) -> StorageResult<Self> {
        let hmac = Self::compute_hmac(&encrypted_key, integrity_key)?;

        Ok(Self {
            encrypted_key,
            hmac,
            version: 1,
        })
    }

    /// Verify the integrity of this key
    ///
    /// # Arguments
    ///
    /// * `integrity_key` - HMAC key to verify with
    ///
    /// # Security
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify(&self, integrity_key: &[u8]) -> StorageResult<()> {
        let expected_hmac = Self::compute_hmac(&self.encrypted_key, integrity_key)?;

        // Use constant-time comparison to prevent timing attacks
        if expected_hmac.ct_eq(&self.hmac).into() {
            Ok(())
        } else {
            Err(StorageError::CorruptionDetected(
                "HMAC verification failed".to_string(),
            ))
        }
    }

    /// Compute HMAC for encrypted data
    fn compute_hmac(encrypted_key: &EncryptedData, integrity_key: &[u8]) -> StorageResult<Vec<u8>> {
        // Serialize the encrypted key
        let bytes = postcard::to_allocvec(encrypted_key).map_err(|e| {
            StorageError::Serialization(format!("Failed to serialize for HMAC: {}", e))
        })?;

        // Compute HMAC
        let mut mac = HmacSha256::new_from_slice(integrity_key)
            .map_err(|e| StorageError::Encryption(format!("Failed to create HMAC: {}", e)))?;

        mac.update(&bytes);
        let result = mac.finalize();

        Ok(result.into_bytes().to_vec())
    }

    /// Get the encrypted key data (after verification)
    pub fn into_encrypted_key(self, integrity_key: &[u8]) -> StorageResult<EncryptedData> {
        self.verify(integrity_key)?;
        Ok(self.encrypted_key)
    }
}

/// Integrity key manager
///
/// Manages the HMAC key used for integrity protection.
/// In production, this should be stored securely (e.g., in a separate HSM).
pub struct IntegrityKeyManager {
    /// HMAC key for integrity protection
    integrity_key: Vec<u8>,
}

impl IntegrityKeyManager {
    /// Create a new integrity key manager with a generated key
    pub fn generate() -> Self {
        use rand::RngCore;

        let mut key = vec![0u8; 32]; // 256-bit key
        rand::rngs::OsRng.fill_bytes(&mut key);

        Self { integrity_key: key }
    }

    /// Create from existing key bytes
    pub fn from_bytes(key: Vec<u8>) -> StorageResult<Self> {
        if key.len() < 32 {
            return Err(StorageError::MasterKey(
                "Integrity key must be at least 32 bytes".to_string(),
            ));
        }

        Ok(Self { integrity_key: key })
    }

    /// Get the integrity key
    pub fn key(&self) -> &[u8] {
        &self.integrity_key
    }

    /// Protect a key with HMAC
    pub fn protect(&self, encrypted_key: EncryptedData) -> StorageResult<IntegrityProtectedKey> {
        IntegrityProtectedKey::new(encrypted_key, &self.integrity_key)
    }

    /// Verify and extract encrypted key
    pub fn verify(&self, protected: &IntegrityProtectedKey) -> StorageResult<EncryptedData> {
        protected.verify(&self.integrity_key)?;
        Ok(protected.encrypted_key.clone())
    }
}

impl std::fmt::Debug for IntegrityKeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IntegrityKeyManager([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_encrypted_data() -> EncryptedData {
        EncryptedData {
            nonce: [0u8; 12],
            ciphertext: b"encrypted data".to_vec(),
        }
    }

    #[test]
    fn test_integrity_protection() {
        let encrypted = create_test_encrypted_data();
        let integrity_key = b"test-integrity-key-32-bytes!!!";

        let protected = IntegrityProtectedKey::new(encrypted.clone(), integrity_key).unwrap();
        assert!(protected.verify(integrity_key).is_ok());
    }

    #[test]
    fn test_integrity_verification_failure() {
        let encrypted = create_test_encrypted_data();
        let integrity_key1 = b"test-integrity-key-32-bytes!!!";
        let integrity_key2 = b"different-key-32-bytes!!!!!!!!";

        let protected = IntegrityProtectedKey::new(encrypted, integrity_key1).unwrap();

        // Verification with wrong key should fail
        assert!(protected.verify(integrity_key2).is_err());
    }

    #[test]
    fn test_integrity_tampering_detection() {
        let encrypted = create_test_encrypted_data();
        let integrity_key = b"test-integrity-key-32-bytes!!!";

        let mut protected = IntegrityProtectedKey::new(encrypted, integrity_key).unwrap();

        // Tamper with the encrypted data
        protected.encrypted_key.ciphertext[0] ^= 1;

        // Verification should fail
        assert!(protected.verify(integrity_key).is_err());
    }

    #[test]
    fn test_integrity_key_manager() {
        let manager = IntegrityKeyManager::generate();
        let encrypted = create_test_encrypted_data();

        let protected = manager.protect(encrypted.clone()).unwrap();
        let verified = manager.verify(&protected).unwrap();

        assert_eq!(verified.ciphertext, encrypted.ciphertext);
    }

    #[test]
    fn test_integrity_key_manager_from_bytes() {
        let key = vec![42u8; 32];
        let manager = IntegrityKeyManager::from_bytes(key.clone()).unwrap();

        assert_eq!(manager.key(), &key[..]);
    }

    #[test]
    fn test_integrity_key_manager_invalid_size() {
        let key = vec![42u8; 16]; // Too small
        assert!(IntegrityKeyManager::from_bytes(key).is_err());
    }

    #[test]
    fn test_into_encrypted_key() {
        let encrypted = create_test_encrypted_data();
        let integrity_key = b"test-integrity-key-32-bytes!!!";

        let protected = IntegrityProtectedKey::new(encrypted.clone(), integrity_key).unwrap();
        let extracted = protected.into_encrypted_key(integrity_key).unwrap();

        assert_eq!(extracted.ciphertext, encrypted.ciphertext);
    }

    #[test]
    fn test_into_encrypted_key_failure() {
        let encrypted = create_test_encrypted_data();
        let integrity_key1 = b"test-integrity-key-32-bytes!!!";
        let integrity_key2 = b"different-key-32-bytes!!!!!!!!";

        let protected = IntegrityProtectedKey::new(encrypted, integrity_key1).unwrap();

        // Should fail with wrong key
        assert!(protected.into_encrypted_key(integrity_key2).is_err());
    }

    #[test]
    fn test_version_tracking() {
        let encrypted = create_test_encrypted_data();
        let integrity_key = b"test-integrity-key-32-bytes!!!";

        let protected = IntegrityProtectedKey::new(encrypted, integrity_key).unwrap();
        assert_eq!(protected.version, 1);
    }

    #[test]
    fn test_deterministic_hmac() {
        let encrypted = create_test_encrypted_data();
        let integrity_key = b"test-integrity-key-32-bytes!!!";

        let protected1 = IntegrityProtectedKey::new(encrypted.clone(), integrity_key).unwrap();
        let protected2 = IntegrityProtectedKey::new(encrypted, integrity_key).unwrap();

        assert_eq!(protected1.hmac, protected2.hmac);
    }
}
