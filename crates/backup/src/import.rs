//! Key import functionality with decryption and verification.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BackupError, Result};
use crate::export::EncryptedBackup;

/// Represents imported key data
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ImportedKeys {
    /// The decrypted key data
    #[zeroize(skip)]
    pub data: Vec<u8>,
    /// Namespace from backup
    pub namespace: Option<String>,
    /// Timestamp when backup was created
    pub timestamp: i64,
    /// Number of keys imported
    pub key_count: usize,
}

/// Key import manager
#[derive(ZeroizeOnDrop)]
pub struct KeyImporter {
    #[zeroize(skip)]
    argon2: Argon2<'static>,
}

impl Default for KeyImporter {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyImporter {
    /// Create a new key importer
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    /// Import keys from encrypted backup
    pub fn import_keys(&self, backup: &EncryptedBackup, password: &[u8]) -> Result<ImportedKeys> {
        // Verify backup version
        if backup.version != 1 {
            return Err(BackupError::UnsupportedVersion(backup.version));
        }

        // Verify password
        let password_hash = PasswordHash::new(&backup.password_hash)
            .map_err(|e| BackupError::InvalidFormat(e.to_string()))?;

        self.argon2
            .verify_password(password, &password_hash)
            .map_err(|_| BackupError::InvalidPassword)?;

        // Derive the encryption key from the password hash
        let key_bytes = password_hash
            .hash
            .ok_or_else(|| BackupError::KeyDerivation("No hash in backup".to_string()))?;

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

        // Verify nonce size
        if backup.nonce.len() != 12 {
            return Err(BackupError::InvalidFormat("Invalid nonce size".to_string()));
        }

        let nonce = Nonce::from_slice(&backup.nonce);

        // Decrypt the data
        let decrypted_data = cipher
            .decrypt(nonce, backup.encrypted_data.as_ref())
            .map_err(|e| BackupError::Decryption(e.to_string()))?;

        // Parse key count from metadata
        let key_count = backup
            .metadata
            .get("key_count")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1);

        Ok(ImportedKeys {
            data: decrypted_data,
            namespace: backup.namespace.clone(),
            timestamp: backup.timestamp,
            key_count,
        })
    }

    /// Import keys from JSON format
    pub fn import_from_json(&self, json_data: &[u8], password: &[u8]) -> Result<ImportedKeys> {
        let backup: EncryptedBackup = serde_json::from_slice(json_data)
            .map_err(|e| BackupError::Deserialization(e.to_string()))?;

        self.import_keys(&backup, password)
    }

    /// Verify backup integrity without decrypting
    pub fn verify_backup(&self, backup: &EncryptedBackup) -> Result<()> {
        // Check version
        if backup.version != 1 {
            return Err(BackupError::UnsupportedVersion(backup.version));
        }

        // Verify password hash format
        PasswordHash::new(&backup.password_hash)
            .map_err(|e| BackupError::InvalidFormat(e.to_string()))?;

        // Verify nonce size
        if backup.nonce.len() != 12 {
            return Err(BackupError::InvalidFormat("Invalid nonce size".to_string()));
        }

        // Verify encrypted data is not empty
        if backup.encrypted_data.is_empty() {
            return Err(BackupError::EmptyData);
        }

        Ok(())
    }

    /// Check if password is correct without full decryption
    pub fn check_password(&self, backup: &EncryptedBackup, password: &[u8]) -> Result<bool> {
        let password_hash = PasswordHash::new(&backup.password_hash)
            .map_err(|e| BackupError::InvalidFormat(e.to_string()))?;

        match self.argon2.verify_password(password, &password_hash) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::KeyExporter;

    #[test]
    fn test_import_keys() {
        let exporter = KeyExporter::new();
        let importer = KeyImporter::new();

        let original_data = b"test_key_data_12345";
        let password = b"strong_password_123";

        let backup = exporter
            .export_keys(original_data, password, Some("test".to_string()))
            .unwrap();

        let imported = importer.import_keys(&backup, password).unwrap();

        assert_eq!(imported.data, original_data);
        assert_eq!(imported.namespace, Some("test".to_string()));
        assert_eq!(imported.key_count, 1);
    }

    #[test]
    fn test_wrong_password() {
        let exporter = KeyExporter::new();
        let importer = KeyImporter::new();

        let backup = exporter
            .export_keys(b"data", b"correct_password", None)
            .unwrap();

        let result = importer.import_keys(&backup, b"wrong_password");
        assert!(matches!(result, Err(BackupError::InvalidPassword)));
    }

    #[test]
    fn test_import_from_json() {
        let exporter = KeyExporter::new();
        let importer = KeyImporter::new();

        let original_data = b"test_key_data";
        let password = b"strong_password_123";

        let json = exporter
            .export_to_json(original_data, password, None)
            .unwrap();

        let imported = importer.import_from_json(&json, password).unwrap();

        assert_eq!(imported.data, original_data);
    }

    #[test]
    fn test_verify_backup() {
        let exporter = KeyExporter::new();
        let importer = KeyImporter::new();

        let backup = exporter
            .export_keys(b"data", b"test-password-1234", None)
            .unwrap();

        assert!(importer.verify_backup(&backup).is_ok());
    }

    #[test]
    fn test_check_password() {
        let exporter = KeyExporter::new();
        let importer = KeyImporter::new();

        let password = b"test-password-1234";
        let backup = exporter.export_keys(b"data", password, None).unwrap();

        assert!(importer.check_password(&backup, password).unwrap());
        assert!(!importer.check_password(&backup, b"wrong").unwrap());
    }

    #[test]
    fn test_invalid_backup_format() {
        let importer = KeyImporter::new();
        let invalid_json = b"{invalid json}";

        let result = importer.import_from_json(invalid_json, b"test-password-1234");
        assert!(matches!(result, Err(BackupError::Deserialization(_))));
    }
}
