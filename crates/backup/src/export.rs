//! Key export functionality with encrypted backups.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::ZeroizeOnDrop;

use crate::error::{BackupError, Result};

/// Length in bytes of the raw Argon2 KDF salt used to derive the AES key.
pub(crate) const KDF_SALT_LEN: usize = 16;

/// Derive a raw 32-byte AES-256 key from a password and salt using Argon2.
///
/// This is a raw key-derivation function: the Argon2 output bytes are written
/// directly into the returned buffer and used as the AES key. Unlike the PHC
/// encoded hash, this output is never serialized into the backup file, so the
/// backup file alone cannot be decrypted without the password.
pub(crate) fn derive_aes_key(
    argon2: &Argon2<'static>,
    password: &[u8],
    salt: &[u8],
) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| BackupError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

/// Represents an encrypted backup of keys.
///
/// Security note: this structure intentionally does NOT contain the AES
/// encryption key or any value from which it can be recovered without the
/// password. The AES key is derived on demand from the user password and the
/// raw `kdf_salt` via Argon2. The `verifier_hash` is a *separate* Argon2 PHC
/// string computed against its own independent salt and is used only for
/// password verification; it is never used as (or to derive) the AES key.
#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedBackup {
    /// Version of the backup format
    pub version: u32,
    /// Separate Argon2 password verifier (PHC string format).
    ///
    /// Computed with its own salt, distinct from `kdf_salt`. Used only to
    /// check that a supplied password is correct; never used as key material.
    pub verifier_hash: String,
    /// Raw salt used to derive the AES-256 encryption key via Argon2.
    pub kdf_salt: Vec<u8>,
    /// AES-GCM nonce
    pub nonce: Vec<u8>,
    /// Encrypted key data
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

        if password.len() < 16 {
            return Err(BackupError::WeakPassword);
        }

        // Generate a raw salt used ONLY to derive the AES encryption key.
        // This salt is stored in the backup; the derived key never is.
        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        OsRng.fill_bytes(&mut kdf_salt);

        // Derive the 32-byte AES-256 key from the password using Argon2 as a
        // raw KDF. The output bytes are used directly as the key and are never
        // serialized, so the backup file cannot be decrypted without the
        // password.
        let encryption_key = derive_aes_key(&self.argon2, password, &kdf_salt)?;

        // Compute a SEPARATE password verifier using an independent salt. This
        // PHC string is stored for convenience password checks; it shares no
        // salt with the KDF and therefore cannot be used to recover the key.
        let verifier_salt = SaltString::generate(&mut OsRng);
        let verifier_hash = self
            .argon2
            .hash_password(password, &verifier_salt)
            .map_err(|e| BackupError::KeyDerivation(e.to_string()))?
            .to_string();

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
            verifier_hash,
            kdf_salt: kdf_salt.to_vec(),
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

    /// Verify password against backup.
    ///
    /// Checks the supplied password against the stored verifier hash. This does
    /// not derive or expose the AES encryption key.
    pub fn verify_password(&self, backup: &EncryptedBackup, password: &[u8]) -> Result<bool> {
        let parsed_hash = PasswordHash::new(&backup.verifier_hash)
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
        assert!(!backup.encrypted_data.is_empty());
        assert_eq!(backup.namespace, Some("test".to_string()));
        assert_eq!(backup.kdf_salt.len(), KDF_SALT_LEN);
    }

    #[test]
    fn test_empty_data() {
        let exporter = KeyExporter::new();
        let result = exporter.export_keys(&[], b"test-password-1234", None);
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

        assert!(!json.is_empty());
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

        assert!(!json.is_empty());

        let parsed: EncryptedBackup = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.namespace, Some("test".to_string()));
    }

    /// Regression test for the "backup contains its own decryption key" defect.
    ///
    /// Previously the AES-256 key was the first 32 bytes of the stored Argon2
    /// PHC hash, so the serialized backup carried its own key and could be
    /// decrypted with no password. This test derives the real AES key, then
    /// asserts that those raw key bytes do NOT appear anywhere in the
    /// serialized backup JSON. It fails on the old code and passes on the fix.
    #[test]
    fn test_serialized_backup_does_not_contain_aes_key() {
        let exporter = KeyExporter::new();
        let keys = b"super_secret_private_key_material";
        let password = b"strong_password_123";

        let backup = exporter.export_keys(keys, password, None).unwrap();

        // Re-derive the actual AES key from password + stored salt.
        let key = derive_aes_key(&exporter.argon2, password, &backup.kdf_salt).unwrap();

        let json = exporter.serialize_backup(&backup).unwrap();

        // The raw 32-byte key must not be byte-recoverable from the file.
        assert!(
            !contains_subslice(&json, &key),
            "serialized backup leaks the raw AES key bytes"
        );

        // Defense in depth: the legacy field name must be gone, and the
        // verifier hash (which uses a different salt) must not be the key.
        let json_str = String::from_utf8_lossy(&json);
        assert!(!json_str.contains("password_hash"));
        assert!(json_str.contains("verifier_hash"));
        assert!(json_str.contains("kdf_salt"));
    }

    /// The verifier hash uses a salt distinct from the KDF salt, so deriving
    /// an AES key from the verifier salt must NOT reproduce the real key.
    #[test]
    fn test_verifier_salt_is_distinct_from_kdf_salt() {
        let exporter = KeyExporter::new();
        let password = b"strong_password_123";
        let backup = exporter.export_keys(b"data", password, None).unwrap();

        let parsed = PasswordHash::new(&backup.verifier_hash).unwrap();
        let verifier_salt = parsed.salt.unwrap();
        let mut verifier_salt_bytes = [0u8; KDF_SALT_LEN];
        let decoded = verifier_salt.decode_b64(&mut verifier_salt_bytes).unwrap();

        assert_ne!(
            decoded,
            backup.kdf_salt.as_slice(),
            "verifier salt must differ from KDF salt"
        );
    }

    /// Helper: does `haystack` contain `needle` as a contiguous subslice?
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
