//! Encrypted configuration file support.
//!
//! This module provides encryption and decryption of configuration files
//! using AES-256-GCM with Argon2 key derivation.

use crate::schema::HsmConfig;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::RngCore, SaltString},
    Argon2, PasswordHasher,
};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroize;

/// Errors that can occur during encryption/decryption.
#[derive(Error, Debug)]
pub enum EncryptionError {
    /// Failed to encrypt data
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Failed to decrypt data
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Failed to derive key
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Invalid ciphertext format
    #[error("Invalid ciphertext format")]
    InvalidFormat,

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

pub type Result<T> = std::result::Result<T, EncryptionError>;

/// Encrypted configuration manager.
///
/// Provides encryption and decryption of configuration files at rest using
/// AES-256-GCM with Argon2id key derivation from passphrases.
///
/// # Security
///
/// - Uses Argon2id for password-based key derivation (resistant to side-channel attacks)
/// - AES-256-GCM provides authenticated encryption
/// - Random nonces generated for each encryption
/// - Keys are zeroized after use
/// - File format: VERSION (1 byte) || SALT (16 bytes) || NONCE (12 bytes) || CIPHERTEXT
///
/// # Examples
///
/// ```rust,no_run
/// use hsm_config::encryption::EncryptedConfigManager;
/// use hsm_config::HsmConfig;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let manager = EncryptedConfigManager::new();
///
/// // Encrypt and save
/// let config = HsmConfig::default();
/// manager.save_encrypted(&config, "config.enc", "my-secret-passphrase")?;
///
/// // Load and decrypt
/// let loaded = manager.load_encrypted("config.enc", "my-secret-passphrase")?;
/// # Ok(())
/// # }
/// ```
pub struct EncryptedConfigManager {
    argon2: Argon2<'static>,
}

impl EncryptedConfigManager {
    /// File format version
    const VERSION: u8 = 1;
    /// Salt length in bytes
    const SALT_LEN: usize = 16;
    /// Nonce length in bytes
    const NONCE_LEN: usize = 12;
    /// Derived key length in bytes (256 bits)
    const KEY_LEN: usize = 32;

    /// Create a new encrypted configuration manager.
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    /// Load and decrypt a configuration file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the encrypted configuration file
    /// * `passphrase` - Passphrase used for encryption
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, decryption fails, or
    /// deserialization fails.
    pub fn load_encrypted<P: AsRef<Path>>(&self, path: P, passphrase: &str) -> Result<HsmConfig> {
        // Read encrypted file
        let encrypted_data = std::fs::read(path.as_ref())?;

        // Parse format
        if encrypted_data.len() < 1 + Self::SALT_LEN + Self::NONCE_LEN {
            return Err(EncryptionError::InvalidFormat);
        }

        // Check version
        if encrypted_data[0] != Self::VERSION {
            return Err(EncryptionError::InvalidFormat);
        }

        // Extract components
        let salt = &encrypted_data[1..1 + Self::SALT_LEN];
        let nonce = &encrypted_data[1 + Self::SALT_LEN..1 + Self::SALT_LEN + Self::NONCE_LEN];
        let ciphertext = &encrypted_data[1 + Self::SALT_LEN + Self::NONCE_LEN..];

        // Derive key from passphrase
        let mut key = self.derive_key(passphrase, salt)?;

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| EncryptionError::DecryptionFailed)?;

        // Zeroize key
        key.zeroize();

        // Deserialize TOML (convert bytes to string first)
        let plaintext_str = std::str::from_utf8(&plaintext)
            .map_err(|e| EncryptionError::DeserializationError(e.to_string()))?;

        let config: HsmConfig = toml::from_str(plaintext_str)
            .map_err(|e| EncryptionError::DeserializationError(e.to_string()))?;

        Ok(config)
    }

    /// Encrypt and save a configuration file.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration to encrypt
    /// * `path` - Path where the encrypted file will be saved
    /// * `passphrase` - Passphrase to use for encryption
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or encryption fails, or if the file
    /// cannot be written.
    pub fn save_encrypted<P: AsRef<Path>>(
        &self,
        config: &HsmConfig,
        path: P,
        passphrase: &str,
    ) -> Result<()> {
        // Serialize config to TOML
        let plaintext_str = toml::to_string(config)
            .map_err(|e| EncryptionError::SerializationError(e.to_string()))?;
        let plaintext = plaintext_str.as_bytes();

        // Generate random salt
        let mut salt = [0u8; Self::SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        // Derive key from passphrase
        let mut key = self.derive_key(passphrase, &salt)?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; Self::NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        // Zeroize key
        key.zeroize();

        // Build file format: VERSION || SALT || NONCE || CIPHERTEXT
        let mut output =
            Vec::with_capacity(1 + Self::SALT_LEN + Self::NONCE_LEN + ciphertext.len());
        output.push(Self::VERSION);
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        // Write to file
        std::fs::write(path.as_ref(), output)?;

        Ok(())
    }

    /// Derive a key from a passphrase using Argon2id.
    fn derive_key(&self, passphrase: &str, salt: &[u8]) -> Result<[u8; Self::KEY_LEN]> {
        // Create salt string from raw bytes
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| EncryptionError::KeyDerivationFailed(e.to_string()))?;

        // Hash passphrase
        let password_hash = self
            .argon2
            .hash_password(passphrase.as_bytes(), &salt_string)
            .map_err(|e| EncryptionError::KeyDerivationFailed(e.to_string()))?;

        // Extract hash bytes
        let hash = password_hash
            .hash
            .ok_or_else(|| EncryptionError::KeyDerivationFailed("No hash output".to_string()))?;

        // Convert to fixed-size array
        let hash_bytes = hash.as_bytes();
        if hash_bytes.len() < Self::KEY_LEN {
            return Err(EncryptionError::KeyDerivationFailed(
                "Hash too short".to_string(),
            ));
        }

        let mut key = [0u8; Self::KEY_LEN];
        key.copy_from_slice(&hash_bytes[..Self::KEY_LEN]);

        Ok(key)
    }
}

impl Default for EncryptedConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HsmConfig;
    use tempfile::NamedTempFile;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let manager = EncryptedConfigManager::new();
        let temp_file = NamedTempFile::new().unwrap();

        let original = HsmConfig::default();
        let passphrase = "super-secret-passphrase-123";

        // Encrypt and save
        manager
            .save_encrypted(&original, temp_file.path(), passphrase)
            .unwrap();

        // Load and decrypt
        let decrypted = manager
            .load_encrypted(temp_file.path(), passphrase)
            .unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let manager = EncryptedConfigManager::new();
        let temp_file = NamedTempFile::new().unwrap();

        let config = HsmConfig::default();
        let passphrase = "correct-passphrase";
        let wrong_passphrase = "wrong-passphrase";

        // Encrypt and save
        manager
            .save_encrypted(&config, temp_file.path(), passphrase)
            .unwrap();

        // Try to decrypt with wrong passphrase
        let result = manager.load_encrypted(temp_file.path(), wrong_passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let manager = EncryptedConfigManager::new();
        let temp_file = NamedTempFile::new().unwrap();

        let config = HsmConfig::default();
        let passphrase = "test-passphrase";

        // Encrypt and save
        manager
            .save_encrypted(&config, temp_file.path(), passphrase)
            .unwrap();

        // Corrupt the file
        let mut data = std::fs::read(temp_file.path()).unwrap();
        if data.len() > 50 {
            data[50] ^= 0xFF; // Flip some bits
        }
        std::fs::write(temp_file.path(), data).unwrap();

        // Try to decrypt corrupted data
        let result = manager.load_encrypted(temp_file.path(), passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_format_fails() {
        let manager = EncryptedConfigManager::new();
        let temp_file = NamedTempFile::new().unwrap();

        // Write invalid data
        std::fs::write(temp_file.path(), b"invalid data").unwrap();

        let result = manager.load_encrypted(temp_file.path(), "passphrase");
        assert!(matches!(result, Err(EncryptionError::InvalidFormat)));
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertexts() {
        let manager = EncryptedConfigManager::new();
        let temp_file1 = NamedTempFile::new().unwrap();
        let temp_file2 = NamedTempFile::new().unwrap();

        let config = HsmConfig::default();
        let passphrase = "test-passphrase";

        // Encrypt same config twice
        manager
            .save_encrypted(&config, temp_file1.path(), passphrase)
            .unwrap();
        manager
            .save_encrypted(&config, temp_file2.path(), passphrase)
            .unwrap();

        // Ciphertexts should be different (due to different nonces)
        let data1 = std::fs::read(temp_file1.path()).unwrap();
        let data2 = std::fs::read(temp_file2.path()).unwrap();
        assert_ne!(data1, data2);

        // But both should decrypt to the same config
        let decrypted1 = manager
            .load_encrypted(temp_file1.path(), passphrase)
            .unwrap();
        let decrypted2 = manager
            .load_encrypted(temp_file2.path(), passphrase)
            .unwrap();
        assert_eq!(decrypted1, decrypted2);
    }
}
