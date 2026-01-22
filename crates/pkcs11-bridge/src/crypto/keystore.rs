//! Key store for PKCS#11 bridge.
//!
//! This module manages cryptographic keys for use with PKCS#11 operations.
//! In a production environment, keys would be stored securely in the HSM.
//! This implementation provides a local key store for testing and development.

use dashmap::DashMap;
use hsm_crypto_engine::KeyMaterial;
use once_cell::sync::Lazy;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ffi::CK_OBJECT_HANDLE;

/// Key type stored in the key store.
#[derive(Clone)]
pub enum StoredKey {
    /// Ed25519 private key (32 bytes)
    Ed25519 {
        private_key: KeyMaterial,
        public_key: Vec<u8>,
    },
    /// ECDSA P-256 private key
    EcdsaP256 {
        private_key: KeyMaterial,
        public_key: Vec<u8>,
    },
    /// ECDSA P-384 private key
    EcdsaP384 {
        private_key: KeyMaterial,
        public_key: Vec<u8>,
    },
    /// RSA private key (DER encoded)
    Rsa {
        private_key: KeyMaterial,
        public_key: Vec<u8>,
        key_bits: usize,
    },
}

impl fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoredKey::Ed25519 { public_key, .. } => f
                .debug_struct("Ed25519")
                .field("private_key", &"<redacted>")
                .field("public_key_len", &public_key.len())
                .finish(),
            StoredKey::EcdsaP256 { public_key, .. } => f
                .debug_struct("EcdsaP256")
                .field("private_key", &"<redacted>")
                .field("public_key_len", &public_key.len())
                .finish(),
            StoredKey::EcdsaP384 { public_key, .. } => f
                .debug_struct("EcdsaP384")
                .field("private_key", &"<redacted>")
                .field("public_key_len", &public_key.len())
                .finish(),
            StoredKey::Rsa {
                public_key,
                key_bits,
                ..
            } => f
                .debug_struct("Rsa")
                .field("private_key", &"<redacted>")
                .field("public_key_len", &public_key.len())
                .field("key_bits", key_bits)
                .finish(),
        }
    }
}

impl StoredKey {
    /// Get the private key material.
    pub fn private_key(&self) -> &KeyMaterial {
        match self {
            StoredKey::Ed25519 { private_key, .. } => private_key,
            StoredKey::EcdsaP256 { private_key, .. } => private_key,
            StoredKey::EcdsaP384 { private_key, .. } => private_key,
            StoredKey::Rsa { private_key, .. } => private_key,
        }
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> &[u8] {
        match self {
            StoredKey::Ed25519 { public_key, .. } => public_key,
            StoredKey::EcdsaP256 { public_key, .. } => public_key,
            StoredKey::EcdsaP384 { public_key, .. } => public_key,
            StoredKey::Rsa { public_key, .. } => public_key,
        }
    }
}

/// Global key store for PKCS#11 operations.
pub struct KeyStore {
    /// Keys stored by object handle
    keys: DashMap<CK_OBJECT_HANDLE, StoredKey>,
    /// Counter for generating unique object handles
    next_handle: AtomicU64,
}

impl KeyStore {
    /// Create a new key store.
    pub fn new() -> Self {
        Self {
            keys: DashMap::new(),
            next_handle: AtomicU64::new(1),
        }
    }

    /// Store a key and return its handle.
    pub fn store(&self, key: StoredKey) -> CK_OBJECT_HANDLE {
        let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);
        self.keys.insert(handle, key);
        handle
    }

    /// Get a key by handle.
    pub fn get(&self, handle: CK_OBJECT_HANDLE) -> Option<StoredKey> {
        self.keys.get(&handle).map(|r| r.clone())
    }

    /// Remove a key by handle.
    pub fn remove(&self, handle: CK_OBJECT_HANDLE) -> Option<StoredKey> {
        self.keys.remove(&handle).map(|(_, v)| v)
    }

    /// Generate and store an Ed25519 keypair.
    pub fn generate_ed25519(&self) -> Result<CK_OBJECT_HANDLE, String> {
        let (private_key, public_key) =
            hsm_crypto_engine::asymmetric::ed25519::Ed25519Engine::generate_keypair()
                .map_err(|e| format!("Ed25519 key generation failed: {}", e))?;

        let key = StoredKey::Ed25519 {
            private_key,
            public_key,
        };
        Ok(self.store(key))
    }

    /// Generate and store an ECDSA P-256 keypair.
    pub fn generate_ecdsa_p256(&self) -> Result<CK_OBJECT_HANDLE, String> {
        let (private_key, public_key) =
            hsm_crypto_engine::asymmetric::ecdsa::EcdsaEngine::generate_p256_keypair()
                .map_err(|e| format!("ECDSA P-256 key generation failed: {}", e))?;

        let key = StoredKey::EcdsaP256 {
            private_key,
            public_key,
        };
        Ok(self.store(key))
    }

    /// Generate and store an ECDSA P-384 keypair.
    pub fn generate_ecdsa_p384(&self) -> Result<CK_OBJECT_HANDLE, String> {
        let (private_key, public_key) =
            hsm_crypto_engine::asymmetric::ecdsa::EcdsaEngine::generate_p384_keypair()
                .map_err(|e| format!("ECDSA P-384 key generation failed: {}", e))?;

        let key = StoredKey::EcdsaP384 {
            private_key,
            public_key,
        };
        Ok(self.store(key))
    }

    /// Generate and store an RSA keypair.
    pub fn generate_rsa(&self, bits: usize) -> Result<CK_OBJECT_HANDLE, String> {
        let (private_key, public_key) =
            hsm_crypto_engine::asymmetric::rsa::RsaEngine::generate_keypair(bits)
                .map_err(|e| format!("RSA key generation failed: {}", e))?;

        let key = StoredKey::Rsa {
            private_key,
            public_key,
            key_bits: bits,
        };
        Ok(self.store(key))
    }

    /// Import an Ed25519 private key.
    pub fn import_ed25519(&self, private_key_bytes: &[u8]) -> Result<CK_OBJECT_HANDLE, String> {
        if private_key_bytes.len() != 32 {
            return Err("Ed25519 private key must be 32 bytes".to_string());
        }

        // Derive public key from private key
        use ed25519_dalek::{SigningKey, VerifyingKey};
        let signing_key = SigningKey::from_bytes(private_key_bytes.try_into().unwrap());
        let verifying_key: VerifyingKey = (&signing_key).into();

        let key = StoredKey::Ed25519 {
            private_key: KeyMaterial::from_bytes(private_key_bytes.to_vec()),
            public_key: verifying_key.to_bytes().to_vec(),
        };
        Ok(self.store(key))
    }

    /// List all key handles.
    pub fn list_handles(&self) -> Vec<CK_OBJECT_HANDLE> {
        self.keys.iter().map(|r| *r.key()).collect()
    }

    /// Clear all keys (for testing).
    #[cfg(test)]
    pub fn clear(&self) {
        self.keys.clear();
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Global key store singleton.
pub static KEY_STORE: Lazy<KeyStore> = Lazy::new(KeyStore::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519() {
        let store = KeyStore::new();
        let handle = store.generate_ed25519().unwrap();
        assert!(handle > 0);

        let key = store.get(handle).unwrap();
        match key {
            StoredKey::Ed25519 {
                private_key,
                public_key,
            } => {
                assert_eq!(private_key.as_bytes().len(), 32);
                assert_eq!(public_key.len(), 32);
            }
            _ => panic!("Expected Ed25519 key"),
        }
    }

    #[test]
    fn test_generate_ecdsa_p256() {
        let store = KeyStore::new();
        let handle = store.generate_ecdsa_p256().unwrap();
        assert!(handle > 0);

        let key = store.get(handle).unwrap();
        assert!(matches!(key, StoredKey::EcdsaP256 { .. }));
    }

    #[test]
    fn test_store_and_remove() {
        let store = KeyStore::new();
        let handle = store.generate_ed25519().unwrap();

        assert!(store.get(handle).is_some());
        store.remove(handle);
        assert!(store.get(handle).is_none());
    }
}
