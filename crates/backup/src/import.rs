//! Key import functionality with decryption and verification.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BackupError, Result};
use crate::export::{derive_aes_key, EncryptedBackup};

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

        // Verify the supplied password against the separate verifier hash.
        // This gives a clear InvalidPassword error early; the AEAD tag check
        // below is the cryptographic guarantee.
        let verifier = PasswordHash::new(&backup.verifier_hash)
            .map_err(|e| BackupError::InvalidFormat(e.to_string()))?;

        self.argon2
            .verify_password(password, &verifier)
            .map_err(|_| BackupError::InvalidPassword)?;

        // Re-derive the AES-256 key from the supplied password and the stored
        // KDF salt. The key is NOT read from any stored hash; the backup file
        // alone does not contain it.
        let encryption_key = derive_aes_key(&self.argon2, password, &backup.kdf_salt)?;

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

        // Verify the verifier hash format
        PasswordHash::new(&backup.verifier_hash)
            .map_err(|e| BackupError::InvalidFormat(e.to_string()))?;

        // Verify KDF salt is present
        if backup.kdf_salt.is_empty() {
            return Err(BackupError::InvalidFormat("Missing KDF salt".to_string()));
        }

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
        let verifier = PasswordHash::new(&backup.verifier_hash)
            .map_err(|e| BackupError::InvalidFormat(e.to_string()))?;

        match self.argon2.verify_password(password, &verifier) {
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
            .export_keys(b"data", b"correct_password1", None)
            .unwrap();

        let result = importer.import_keys(&backup, b"wrong_password12");
        assert!(matches!(result, Err(BackupError::InvalidPassword)));
    }

    /// Regression test: even if an attacker strips the verifier-based password
    /// check, a wrong password must still fail to decrypt because the AES key
    /// is derived from the password and the AEAD tag will not validate.
    ///
    /// On the old code the key was the first 32 bytes of the stored hash, so
    /// the data was decryptable regardless of the password. This re-derives a
    /// key from the WRONG password against the stored KDF salt and asserts the
    /// AEAD decrypt fails.
    #[test]
    fn test_wrong_password_cannot_decrypt_payload() {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        let exporter = KeyExporter::new();
        let original = b"top_secret_signing_key_bytes";
        let backup = exporter
            .export_keys(original, b"the_real_password1", None)
            .unwrap();

        // Derive a key directly from the wrong password + stored salt,
        // bypassing any verifier check, and try the raw AEAD decryption.
        let argon2 = Argon2::default();
        let wrong_key = derive_aes_key(&argon2, b"the_wrong_password", &backup.kdf_salt).unwrap();
        let cipher = Aes256Gcm::new(&wrong_key.into());
        let nonce = Nonce::from_slice(&backup.nonce);
        let result = cipher.decrypt(nonce, backup.encrypted_data.as_ref());
        assert!(
            result.is_err(),
            "wrong password must not decrypt the payload"
        );

        // And the correct password must round-trip.
        let correct_key = derive_aes_key(&argon2, b"the_real_password1", &backup.kdf_salt).unwrap();
        let cipher = Aes256Gcm::new(&correct_key.into());
        let recovered = cipher
            .decrypt(nonce, backup.encrypted_data.as_ref())
            .unwrap();
        assert_eq!(recovered, original);
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
        assert!(!importer
            .check_password(&backup, b"wrong_password12")
            .unwrap());
    }

    #[test]
    fn test_invalid_backup_format() {
        let importer = KeyImporter::new();
        let invalid_json = b"{invalid json}";

        let result = importer.import_from_json(invalid_json, b"test-password-1234");
        assert!(matches!(result, Err(BackupError::Deserialization(_))));
    }
}
