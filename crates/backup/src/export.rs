//! Key export functionality with encrypted backups.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::ZeroizeOnDrop;

use crate::error::{BackupError, Result};

/// Represents an encrypted backup of keys
#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedBackup {
    /// Version of the backup format
    pub version: u32,
    /// Argon2 password hash (PHC string format)
    pub password_hash: String,
    /// Salt used for key derivation (base64)
    pub salt: String,
    /// AES-GCM nonce (base64)
    pub nonce: Vec<u8>,
    /// Encrypted key data (base64)
    pub encrypted_data: Vec<u8>,
    /// Timestamp of backup creation
    pub timestamp: i64,
    /// Optional namespace for the backup
    pub namespace: Option<String>,
    /// Metadata about the backup
    pub metadata: HashMap<String, String>,
}

/// Key export manager
#[derive(ZeroizeOnDrop)]
pub struct KeyExporter {
    #[zeroize(skip)]
    argon2: Argon2<'static>,
}

impl Default for KeyExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyExporter {
    /// Create a new key exporter
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    /// Export keys with password encryption
    pub fn export_keys(
        &self,
        keys: &[u8],
        password: &[u8],
        namespace: Option<String>,
    ) -> Result<EncryptedBackup> {
        if keys.is_empty() {
            return Err(BackupError::EmptyData);
        }

        if password.is_empty() {
            return Err(BackupError::WeakPassword);
        }

        // Generate salt for password hashing
        let salt = SaltString::generate(&mut OsRng);

        // Derive encryption key from password using Argon2
        let password_hash = self
            .argon2
            .hash_password(password, &salt)
            .map_err(|e| BackupError::KeyDerivation(e.to_string()))?;

        // Extract the raw hash for use as encryption key
        let key_bytes = password_hash
            .hash
            .ok_or_else(|| BackupError::KeyDerivation("No hash generated".to_string()))?;

        // Use the first 32 bytes for AES-256
        let key_material = key_bytes.as_bytes();
        if key_material.len() < 32 {
            return Err(BackupError::KeyDerivation(
                "Insufficient key material".to_string(),
            ));
        }

        let encryption_key: [u8; 32] = key_material[..32]
            .try_into()
            .map_err(|_| BackupError::KeyDerivation("Key size mismatch".to_string()))?;

        // Create cipher
        let cipher = Aes256Gcm::new(&encryption_key.into());

        // Generate random nonce
        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the keys
        let encrypted_data = cipher
            .encrypt(nonce, keys)
            .map_err(|e| BackupError::Encryption(e.to_string()))?;

        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| BackupError::InvalidFormat(e.to_string()))?
            .as_secs() as i64;

        let mut metadata = HashMap::new();
        metadata.insert("key_count".to_string(), "1".to_string());
        metadata.insert("algorithm".to_string(), "AES-256-GCM".to_string());

        Ok(EncryptedBackup {
            version: 1,
            password_hash: password_hash.to_string(),
            salt: salt.to_string(),
            nonce: nonce_bytes.to_vec(),
            encrypted_data,
            timestamp,
            namespace,
            metadata,
        })
    }

    /// Serialize backup to JSON
    pub fn serialize_backup(&self, backup: &EncryptedBackup) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(backup).map_err(|e| BackupError::Serialization(e.to_string()))
    }

    /// Verify password against backup
    pub fn verify_password(&self, backup: &EncryptedBackup, password: &[u8]) -> Result<bool> {
        let parsed_hash = PasswordHash::new(&backup.password_hash)
            .map_err(|e| BackupError::InvalidFormat(e.to_string()))?;

        match self.argon2.verify_password(password, &parsed_hash) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Export keys to JSON format
    pub fn export_to_json(
        &self,
        keys: &[u8],
        password: &[u8],
        namespace: Option<String>,
    ) -> Result<Vec<u8>> {
        let backup = self.export_keys(keys, password, namespace)?;
        self.serialize_backup(&backup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_keys() {
        let exporter = KeyExporter::new();
        let keys = b"test_key_data";
        let password = b"strong_password_123";

        let backup = exporter
            .export_keys(keys, password, Some("test".to_string()))
            .unwrap();

        assert_eq!(backup.version, 1);
        assert!(backup.encrypted_data.len() > 0);
        assert_eq!(backup.namespace, Some("test".to_string()));
    }

    #[test]
    fn test_empty_data() {
        let exporter = KeyExporter::new();
        let result = exporter.export_keys(&[], b"password", None);
        assert!(matches!(result, Err(BackupError::EmptyData)));
    }

    #[test]
    fn test_weak_password() {
        let exporter = KeyExporter::new();
        let result = exporter.export_keys(b"data", &[], None);
        assert!(matches!(result, Err(BackupError::WeakPassword)));
    }

    #[test]
    fn test_verify_password() {
        let exporter = KeyExporter::new();
        let keys = b"test_key_data";
        let password = b"strong_password_123";

        let backup = exporter.export_keys(keys, password, None).unwrap();

        assert!(exporter.verify_password(&backup, password).unwrap());
        assert!(!exporter
            .verify_password(&backup, b"wrong_password")
            .unwrap());
    }

    #[test]
    fn test_serialize_backup() {
        let exporter = KeyExporter::new();
        let keys = b"test_key_data";
        let password = b"strong_password_123";

        let backup = exporter.export_keys(keys, password, None).unwrap();
        let json = exporter.serialize_backup(&backup).unwrap();

        assert!(json.len() > 0);
        assert!(String::from_utf8_lossy(&json).contains("version"));
    }

    #[test]
    fn test_export_to_json() {
        let exporter = KeyExporter::new();
        let keys = b"test_key_data";
        let password = b"strong_password_123";

        let json = exporter
            .export_to_json(keys, password, Some("test".to_string()))
            .unwrap();

        assert!(json.len() > 0);

        let parsed: EncryptedBackup = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.namespace, Some("test".to_string()));
    }
}
