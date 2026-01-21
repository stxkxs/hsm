//! Master Key Management
//!
//! Handles generation, storage, and loading of the master encryption key.

use crate::backend::{StorageError, StorageResult};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of the master key in bytes (256 bits)
const MASTER_KEY_SIZE: usize = 32;

/// Size of the AES-GCM nonce in bytes
const NONCE_SIZE: usize = 12;

/// A zeroizing wrapper for sensitive key material
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretVec<T: Zeroize>(Vec<T>);

impl<T: Zeroize> SecretVec<T> {
    /// Create a new SecretVec
    pub fn new(data: Vec<T>) -> Self {
        Self(data)
    }

    /// Get a reference to the inner data
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Get the length of the inner data
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the inner data is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T: Zeroize> AsRef<[T]> for SecretVec<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T: Zeroize + std::fmt::Debug> std::fmt::Debug for SecretVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretVec([REDACTED])")
    }
}

/// Master key for encrypting all stored keys
pub struct MasterKey {
    key: SecretVec<u8>,
}

impl MasterKey {
    /// Generate a new random master key
    pub fn generate() -> Self {
        let mut key = vec![0u8; MASTER_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self {
            key: SecretVec::new(key),
        }
    }

    /// Create a master key from existing bytes
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - The key material (must be 32 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not 32 bytes
    pub fn from_bytes(key_bytes: Vec<u8>) -> StorageResult<Self> {
        if key_bytes.len() != MASTER_KEY_SIZE {
            return Err(StorageError::MasterKey(format!(
                "Invalid key size: expected {}, got {}",
                MASTER_KEY_SIZE,
                key_bytes.len()
            )));
        }
        Ok(Self {
            key: SecretVec::new(key_bytes),
        })
    }

    /// Save the master key to disk, encrypted with a key-encryption-key (KEK)
    ///
    /// In a production system, the KEK would be derived from a passphrase or HSM.
    /// For this implementation, we'll use a placeholder KEK derived from the system.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to save the encrypted master key
    /// * `kek` - Key-encryption-key to protect the master key
    ///
    /// # Errors
    ///
    /// Returns an error if encryption or file write fails
    pub fn save(&self, path: &Path, kek: &[u8; 32]) -> StorageResult<()> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let encrypted = self.encrypt_with_kek(kek)?;
        fs::write(
            path,
            postcard::to_allocvec(&encrypted).map_err(|e| {
                StorageError::Serialization(format!("Failed to serialize master key: {}", e))
            })?,
        )
        .map_err(StorageError::Io)?;

        Ok(())
    }

    /// Load the master key from disk
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the encrypted master key file
    /// * `kek` - Key-encryption-key to decrypt the master key
    ///
    /// # Errors
    ///
    /// Returns an error if file read, decryption, or deserialization fails
    pub fn load(path: &Path, kek: &[u8; 32]) -> StorageResult<Self> {
        let data = fs::read(path)?;
        let encrypted: EncryptedMasterKey = postcard::from_bytes(&data).map_err(|e| {
            StorageError::Serialization(format!("Failed to deserialize master key: {}", e))
        })?;

        Self::decrypt_with_kek(&encrypted, kek)
    }

    /// Get a reference to the master key bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_slice()
    }

    /// Encrypt data using this master key
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data to encrypt
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn encrypt(&self, plaintext: &[u8]) -> StorageResult<EncryptedData> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_slice())
            .map_err(|e| StorageError::Encryption(format!("Failed to create cipher: {}", e)))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| StorageError::Encryption(format!("Encryption failed: {}", e)))?;

        Ok(EncryptedData {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt data using this master key
    ///
    /// # Arguments
    ///
    /// * `encrypted` - Encrypted data to decrypt
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails
    pub fn decrypt(&self, encrypted: &EncryptedData) -> StorageResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_slice())
            .map_err(|e| StorageError::Encryption(format!("Failed to create cipher: {}", e)))?;

        let nonce = Nonce::from_slice(&encrypted.nonce);

        cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| StorageError::Encryption(format!("Decryption failed: {}", e)))
    }

    /// Encrypt the master key with a key-encryption-key
    fn encrypt_with_kek(&self, kek: &[u8; 32]) -> StorageResult<EncryptedMasterKey> {
        let cipher = Aes256Gcm::new_from_slice(kek)
            .map_err(|e| StorageError::Encryption(format!("Failed to create KEK cipher: {}", e)))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, self.key.as_slice())
            .map_err(|e| StorageError::Encryption(format!("KEK encryption failed: {}", e)))?;

        Ok(EncryptedMasterKey {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt the master key with a key-encryption-key
    fn decrypt_with_kek(encrypted: &EncryptedMasterKey, kek: &[u8; 32]) -> StorageResult<Self> {
        let cipher = Aes256Gcm::new_from_slice(kek)
            .map_err(|e| StorageError::Encryption(format!("Failed to create KEK cipher: {}", e)))?;

        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| StorageError::Encryption(format!("KEK decryption failed: {}", e)))?;

        Self::from_bytes(plaintext)
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey([REDACTED])")
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        // Zeroization is handled by SecretVec
    }
}

/// Encrypted master key stored on disk
#[derive(Serialize, Deserialize)]
struct EncryptedMasterKey {
    nonce: [u8; NONCE_SIZE],
    ciphertext: Vec<u8>,
}

/// Encrypted data with nonce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_master_key_generation() {
        let key = MasterKey::generate();
        assert_eq!(key.as_bytes().len(), MASTER_KEY_SIZE);
    }

    #[test]
    fn test_master_key_from_bytes() {
        let bytes = vec![0u8; MASTER_KEY_SIZE];
        let key = MasterKey::from_bytes(bytes).unwrap();
        assert_eq!(key.as_bytes().len(), MASTER_KEY_SIZE);
    }

    #[test]
    fn test_master_key_from_bytes_invalid_size() {
        let bytes = vec![0u8; 16]; // Wrong size
        assert!(MasterKey::from_bytes(bytes).is_err());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = MasterKey::generate();
        let plaintext = b"secret data";

        let encrypted = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_save_load_master_key() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("master_key.enc");
        let kek = [42u8; 32];

        let original_key = MasterKey::generate();
        original_key.save(&key_path, &kek).unwrap();

        let loaded_key = MasterKey::load(&key_path, &kek).unwrap();

        // Test that both keys can encrypt/decrypt the same way
        let plaintext = b"test data";
        let encrypted = original_key.encrypt(plaintext).unwrap();
        let decrypted = loaded_key.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_wrong_kek() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("master_key.enc");
        let kek1 = [42u8; 32];
        let kek2 = [99u8; 32];

        let original_key = MasterKey::generate();
        original_key.save(&key_path, &kek1).unwrap();

        // Try to load with wrong KEK
        assert!(MasterKey::load(&key_path, &kek2).is_err());
    }

    #[test]
    fn test_secret_vec_zeroize() {
        let data = vec![1u8, 2, 3, 4, 5];
        let secret = SecretVec::new(data);
        assert_eq!(secret.len(), 5);
        drop(secret);
        // Memory should be zeroed after drop
    }
}
