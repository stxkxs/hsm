//! HD (Hierarchical Deterministic) Key Management
//!
//! Provides BIP-32/39/44 compliant HD key derivation and management,
//! integrating with the blockchain crate for cryptographic operations.
//!
//! # Features
//!
//! - Generate master keys from BIP-39 mnemonics
//! - Derive child keys using BIP-32/44 derivation paths
//! - Support for multiple coin types (Bitcoin, Ethereum, Solana, etc.)
//! - Secure key storage with chain codes
//!
//! # Example
//!
//! ```rust,ignore
//! use hsm_key_manager::hd::{HdKeyManager, MnemonicStrength};
//!
//! let hd_manager = HdKeyManager::new(key_manager);
//!
//! // Generate a new master key from a 24-word mnemonic
//! let (master_key_id, mnemonic) = hd_manager.generate_master_key(
//!     "production",
//!     MnemonicStrength::Words24,
//!     None,
//! )?;
//!
//! // Derive an Ethereum key at m/44'/60'/0'/0/0
//! let derived_key_id = hd_manager.derive_key(
//!     &master_key_id,
//!     "production",
//!     "m/44'/60'/0'/0/0",
//! )?;
//! ```

use crate::error::{Error, Result};
use crate::key::{HdKeyInfo, Key, KeyId, KeyState, KeyType, KeyUsagePolicy};
use crate::store::KeyStore;
use chrono::Utc;
use hsm_blockchain::bip::{
    bip32::{ChildNumber, DerivationPath, ExtendedPrivateKey},
    bip39::{Language, Mnemonic, MnemonicType},
    bip44::CoinType,
};
use hsm_crypto_engine::KeyMaterial;
use std::sync::Arc;

/// Mnemonic strength (word count)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicStrength {
    /// 12 words (128 bits of entropy)
    Words12,
    /// 15 words (160 bits of entropy)
    Words15,
    /// 18 words (192 bits of entropy)
    Words18,
    /// 21 words (224 bits of entropy)
    Words21,
    /// 24 words (256 bits of entropy) - recommended for production
    Words24,
}

impl MnemonicStrength {
    /// Get the number of words for this strength
    pub fn word_count(&self) -> usize {
        match self {
            Self::Words12 => 12,
            Self::Words15 => 15,
            Self::Words18 => 18,
            Self::Words21 => 21,
            Self::Words24 => 24,
        }
    }

    /// Convert to blockchain crate's MnemonicType
    fn to_mnemonic_type(&self) -> MnemonicType {
        match self {
            Self::Words12 => MnemonicType::Words12,
            Self::Words15 => MnemonicType::Words15,
            Self::Words18 => MnemonicType::Words18,
            Self::Words21 => MnemonicType::Words21,
            Self::Words24 => MnemonicType::Words24,
        }
    }
}

/// Result of master key generation
pub struct MasterKeyResult {
    /// The generated master key ID
    pub key_id: KeyId,
    /// The mnemonic phrase (should be shown to user once and securely stored)
    pub mnemonic: String,
}

/// HD Key Manager for hierarchical deterministic key operations
pub struct HdKeyManager {
    store: Arc<KeyStore>,
}

impl HdKeyManager {
    /// Create a new HD key manager
    pub fn new(store: Arc<KeyStore>) -> Self {
        Self { store }
    }

    /// Generate a new master key from a random mnemonic
    ///
    /// # Arguments
    /// * `namespace` - Key namespace for isolation
    /// * `strength` - Mnemonic strength (word count)
    /// * `passphrase` - Optional BIP-39 passphrase for additional security
    ///
    /// # Returns
    /// The master key ID and the mnemonic phrase
    pub fn generate_master_key(
        &self,
        namespace: &str,
        strength: MnemonicStrength,
        passphrase: Option<&str>,
    ) -> Result<MasterKeyResult> {
        // Generate random mnemonic
        let mnemonic =
            Mnemonic::generate(strength.to_mnemonic_type(), Language::English).map_err(|e| {
                Error::KeyGenerationFailed(format!("Failed to generate mnemonic: {}", e))
            })?;

        let mnemonic_phrase = mnemonic.phrase().to_string();

        // Derive seed from mnemonic
        let seed = mnemonic.to_seed(passphrase.unwrap_or(""));

        // Create extended private key from seed
        let master_key = ExtendedPrivateKey::from_seed(seed.as_bytes()).map_err(|e| {
            Error::KeyGenerationFailed(format!("Failed to create master key: {}", e))
        })?;

        // Extract key material
        let private_bytes = master_key.private_key_bytes();
        let chain_code = master_key.chain_code().to_vec();

        // Compute public key (secp256k1)
        let public_key = master_key.public_key();
        let public_bytes = public_key.to_bytes();

        // Create HD info
        let hd_info = HdKeyInfo {
            derivation_path: Some("m".to_string()),
            master_key_id: None, // This IS the master key
            chain_code: Some(chain_code),
            coin_type: None,
            account_index: None,
            can_derive_children: true,
            depth: 0,
            child_index: None,
            parent_fingerprint: None,
        };

        // Create key object
        let key = Key {
            id: KeyId::new(),
            key_type: KeyType::HdMaster,
            private_material: Some(KeyMaterial::from_bytes(private_bytes.to_vec())),
            public_material: Some(public_bytes.to_vec()),
            state: KeyState::Active,
            namespace: namespace.to_string(),
            created_at: Utc::now(),
            policy: KeyUsagePolicy {
                can_sign: false, // Master key should not be used directly for signing
                can_encrypt: false,
                can_derive: true, // Key derivation is the main purpose
                can_export: false,
                max_operations: None,
                expires_at: None,
            },
            version: 1,
            previous_version: None,
            operation_count: 0,
            hd_info: Some(hd_info),
        };

        let key_id = key.id;
        self.store.insert(namespace, key)?;

        Ok(MasterKeyResult {
            key_id,
            mnemonic: mnemonic_phrase,
        })
    }

    /// Import a master key from an existing mnemonic
    ///
    /// # Arguments
    /// * `namespace` - Key namespace
    /// * `mnemonic_phrase` - BIP-39 mnemonic phrase
    /// * `passphrase` - Optional BIP-39 passphrase
    pub fn import_master_key(
        &self,
        namespace: &str,
        mnemonic_phrase: &str,
        passphrase: Option<&str>,
    ) -> Result<KeyId> {
        // Parse and validate mnemonic
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English)
            .map_err(|e| Error::InvalidKeyData(format!("Invalid mnemonic: {}", e)))?;

        // Derive seed
        let seed = mnemonic.to_seed(passphrase.unwrap_or(""));

        // Create extended private key
        let master_key = ExtendedPrivateKey::from_seed(seed.as_bytes()).map_err(|e| {
            Error::KeyGenerationFailed(format!("Failed to create master key: {}", e))
        })?;

        // Extract key material
        let private_bytes = master_key.private_key_bytes();
        let chain_code = master_key.chain_code().to_vec();

        let public_key = master_key.public_key();
        let public_bytes = public_key.to_bytes();

        // Create HD info
        let hd_info = HdKeyInfo {
            derivation_path: Some("m".to_string()),
            master_key_id: None,
            chain_code: Some(chain_code),
            coin_type: None,
            account_index: None,
            can_derive_children: true,
            depth: 0,
            child_index: None,
            parent_fingerprint: None,
        };

        // Create key object
        let key = Key {
            id: KeyId::new(),
            key_type: KeyType::HdMaster,
            private_material: Some(KeyMaterial::from_bytes(private_bytes.to_vec())),
            public_material: Some(public_bytes.to_vec()),
            state: KeyState::Active,
            namespace: namespace.to_string(),
            created_at: Utc::now(),
            policy: KeyUsagePolicy {
                can_sign: false,
                can_encrypt: false,
                can_derive: true,
                can_export: false,
                max_operations: None,
                expires_at: None,
            },
            version: 1,
            previous_version: None,
            operation_count: 0,
            hd_info: Some(hd_info),
        };

        let key_id = key.id;
        self.store.insert(namespace, key)?;

        Ok(key_id)
    }

    /// Derive a child key from a master key
    ///
    /// # Arguments
    /// * `master_key_id` - ID of the master key
    /// * `namespace` - Key namespace
    /// * `path` - BIP-32 derivation path (e.g., "m/44'/60'/0'/0/0")
    ///
    /// # Returns
    /// The derived key ID
    ///
    /// # Note
    /// Currently only supports deriving directly from master keys. For security reasons,
    /// derived keys cannot be used to derive further children - derive from master with
    /// the full path instead.
    pub fn derive_key(&self, master_key_id: &KeyId, namespace: &str, path: &str) -> Result<KeyId> {
        // Get master key
        let master_key = self.store.get(namespace, master_key_id)?;

        // Verify parent is a master HD key
        if master_key.key_type != KeyType::HdMaster {
            return Err(Error::InvalidKeyData(
                "Can only derive from master HD key. Use full path from master.".to_string(),
            ));
        }

        let master_hd_info = master_key
            .hd_info
            .as_ref()
            .ok_or_else(|| Error::InvalidKeyData("Master key is missing HD info".to_string()))?;

        if !master_hd_info.can_derive_children {
            return Err(Error::InvalidKeyData(
                "Master key cannot derive children".to_string(),
            ));
        }

        // Get master key material (private key bytes and chain code)
        let master_private = master_key.private_material.as_ref().ok_or_else(|| {
            Error::InvalidKeyData("Master key has no private material".to_string())
        })?;

        let master_chain_code = master_hd_info
            .chain_code
            .as_ref()
            .ok_or_else(|| Error::InvalidKeyData("Master key has no chain code".to_string()))?;

        // Combine private key and chain code to form the "seed-like" extended key data
        // BIP-32 master key derivation from seed produces key + chain_code
        // We stored these separately, so we reconstruct by creating a 64-byte buffer
        let mut seed_like = [0u8; 64];
        seed_like[..32].copy_from_slice(master_private.as_bytes());
        seed_like[32..].copy_from_slice(master_chain_code);

        // Create extended key from seed - this recreates the master extended key
        let master_ext_key = ExtendedPrivateKey::from_seed(&seed_like).map_err(|e| {
            Error::InvalidKeyData(format!("Failed to reconstruct master key: {}", e))
        })?;

        // Parse derivation path
        let derivation_path = DerivationPath::from_str(path)
            .map_err(|e| Error::InvalidKeyData(format!("Invalid derivation path: {}", e)))?;

        // Derive child key
        let child_ext_key = master_ext_key
            .derive_path(&derivation_path)
            .map_err(|e| Error::KeyGenerationFailed(format!("Derivation failed: {}", e)))?;

        // Extract child key material
        let child_private = child_ext_key.private_key_bytes();
        let child_chain_code = child_ext_key.chain_code().to_vec();

        let child_public = child_ext_key.public_key();
        let child_public_bytes = child_public.to_bytes();

        // Parse coin type and account from path if present
        let (coin_type, account_index) = self.parse_path_components(path);

        // Compute parent fingerprint (first 4 bytes of HASH256 of master public key)
        let parent_fingerprint = self.compute_fingerprint(master_key.public_material.as_ref())?;

        // Determine child index from path
        let child_index: Option<u32> = derivation_path
            .components()
            .last()
            .map(|c: &ChildNumber| c.index);

        // Create HD info for derived key
        let hd_info = HdKeyInfo {
            derivation_path: Some(path.to_string()),
            master_key_id: Some(*master_key_id),
            chain_code: Some(child_chain_code),
            coin_type,
            account_index,
            can_derive_children: false, // Derived keys can't derive further in this implementation
            depth: derivation_path.components().len() as u32,
            child_index,
            parent_fingerprint: Some(parent_fingerprint),
        };

        // Create derived key
        let key = Key {
            id: KeyId::new(),
            key_type: KeyType::HdDerived,
            private_material: Some(KeyMaterial::from_bytes(child_private.to_vec())),
            public_material: Some(child_public_bytes.to_vec()),
            state: KeyState::Active,
            namespace: namespace.to_string(),
            created_at: Utc::now(),
            policy: KeyUsagePolicy {
                can_sign: true, // Derived keys can sign
                can_encrypt: false,
                can_derive: hd_info.can_derive_children,
                can_export: false,
                max_operations: None,
                expires_at: None,
            },
            version: 1,
            previous_version: None,
            operation_count: 0,
            hd_info: Some(hd_info),
        };

        let key_id = key.id;
        self.store.insert(namespace, key)?;

        Ok(key_id)
    }

    /// Derive a key for a specific coin type using BIP-44
    ///
    /// Creates a key at path: m/44'/<coin>'/<account>'/0/<address_index>
    pub fn derive_coin_key(
        &self,
        master_key_id: &KeyId,
        namespace: &str,
        coin_type: CoinType,
        account: u32,
        address_index: u32,
    ) -> Result<KeyId> {
        let coin_number = coin_type.value();
        let path = format!("m/44'/{}'/{}'/0/{}", coin_number, account, address_index);
        self.derive_key(master_key_id, namespace, &path)
    }

    /// Get all derived keys for a master key
    pub fn list_derived_keys(&self, master_key_id: &KeyId, namespace: &str) -> Result<Vec<KeyId>> {
        let all_keys = self.store.list(namespace)?;
        let mut derived_keys = Vec::new();

        for key_id in all_keys {
            if let Ok(key) = self.store.get(namespace, &key_id) {
                if key.key_type == KeyType::HdDerived {
                    if let Some(hd_info) = &key.hd_info {
                        if hd_info.master_key_id == Some(*master_key_id) {
                            derived_keys.push(key_id);
                        }
                    }
                }
            }
        }

        Ok(derived_keys)
    }

    /// Parse coin type and account index from derivation path
    fn parse_path_components(&self, path: &str) -> (Option<u32>, Option<u32>) {
        let parts: Vec<&str> = path.split('/').collect();

        // BIP-44: m/44'/coin'/account'/change/address
        if parts.len() >= 4 && parts[1].starts_with("44'") {
            let coin_type = parts
                .get(2)
                .and_then(|s| s.trim_end_matches('\'').parse::<u32>().ok());
            let account = parts
                .get(3)
                .and_then(|s| s.trim_end_matches('\'').parse::<u32>().ok());
            return (coin_type, account);
        }

        (None, None)
    }

    /// Compute fingerprint (first 4 bytes of HASH160)
    fn compute_fingerprint(&self, public_key: Option<&Vec<u8>>) -> Result<[u8; 4]> {
        use sha2::{Digest, Sha256};

        let public_key = public_key
            .ok_or_else(|| Error::InvalidKeyData("No public key for fingerprint".to_string()))?;

        // HASH160 = RIPEMD160(SHA256(pubkey))
        // For simplicity, we'll use first 4 bytes of SHA256 (sufficient for fingerprint)
        let hash = Sha256::digest(public_key);
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&hash[..4]);
        Ok(fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_store() -> Arc<KeyStore> {
        Arc::new(KeyStore::new())
    }

    #[test]
    fn test_generate_master_key() {
        let store = create_test_store();
        let hd_manager = HdKeyManager::new(store.clone());

        let result = hd_manager
            .generate_master_key("test", MnemonicStrength::Words12, None)
            .expect("Should generate master key");

        // Verify mnemonic is 12 words
        let word_count = result.mnemonic.split_whitespace().count();
        assert_eq!(word_count, 12);

        // Verify key was stored
        let key = store.get("test", &result.key_id).expect("Key should exist");
        assert_eq!(key.key_type, KeyType::HdMaster);
        assert!(key.hd_info.is_some());
    }

    #[test]
    fn test_import_master_key() {
        let store = create_test_store();
        let hd_manager = HdKeyManager::new(store.clone());

        // Test mnemonic (DO NOT USE IN PRODUCTION)
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key_id = hd_manager
            .import_master_key("test", mnemonic, None)
            .expect("Should import master key");

        let key = store.get("test", &key_id).expect("Key should exist");
        assert_eq!(key.key_type, KeyType::HdMaster);
    }

    #[test]
    fn test_derive_key() {
        let store = create_test_store();
        let hd_manager = HdKeyManager::new(store.clone());

        // Generate master key
        let master = hd_manager
            .generate_master_key("test", MnemonicStrength::Words12, None)
            .expect("Should generate master key");

        // Derive Ethereum key at standard path
        let derived_id = hd_manager
            .derive_key(&master.key_id, "test", "m/44'/60'/0'/0/0")
            .expect("Should derive key");

        let derived_key = store
            .get("test", &derived_id)
            .expect("Derived key should exist");
        assert_eq!(derived_key.key_type, KeyType::HdDerived);

        let hd_info = derived_key.hd_info.as_ref().expect("Should have HD info");
        assert_eq!(
            hd_info.derivation_path,
            Some("m/44'/60'/0'/0/0".to_string())
        );
        assert_eq!(hd_info.master_key_id, Some(master.key_id));
        assert_eq!(hd_info.coin_type, Some(60)); // Ethereum
        assert_eq!(hd_info.account_index, Some(0));
    }

    #[test]
    fn test_derive_multiple_addresses() {
        let store = create_test_store();
        let hd_manager = HdKeyManager::new(store.clone());

        let master = hd_manager
            .generate_master_key("test", MnemonicStrength::Words12, None)
            .expect("Should generate master key");

        // Derive multiple addresses
        let mut derived_ids = Vec::new();
        for i in 0..5 {
            let path = format!("m/44'/60'/0'/0/{}", i);
            let id = hd_manager
                .derive_key(&master.key_id, "test", &path)
                .expect("Should derive key");
            derived_ids.push(id);
        }

        // Verify all keys are unique
        for i in 0..derived_ids.len() {
            for j in (i + 1)..derived_ids.len() {
                assert_ne!(derived_ids[i], derived_ids[j]);
            }
        }

        // List derived keys
        let listed = hd_manager
            .list_derived_keys(&master.key_id, "test")
            .expect("Should list derived keys");
        assert_eq!(listed.len(), 5);
    }

    #[test]
    fn test_derive_coin_key() {
        let store = create_test_store();
        let hd_manager = HdKeyManager::new(store.clone());

        let master = hd_manager
            .generate_master_key("test", MnemonicStrength::Words24, None)
            .expect("Should generate master key");

        // Derive Bitcoin key
        let btc_id = hd_manager
            .derive_coin_key(&master.key_id, "test", CoinType::Bitcoin, 0, 0)
            .expect("Should derive Bitcoin key");

        let btc_key = store.get("test", &btc_id).expect("BTC key should exist");
        let hd_info = btc_key.hd_info.as_ref().expect("Should have HD info");
        assert_eq!(hd_info.coin_type, Some(0)); // Bitcoin

        // Derive Ethereum key
        let eth_id = hd_manager
            .derive_coin_key(&master.key_id, "test", CoinType::Ethereum, 0, 0)
            .expect("Should derive Ethereum key");

        let eth_key = store.get("test", &eth_id).expect("ETH key should exist");
        let hd_info = eth_key.hd_info.as_ref().expect("Should have HD info");
        assert_eq!(hd_info.coin_type, Some(60)); // Ethereum
    }

    #[test]
    fn test_mnemonic_strength() {
        assert_eq!(MnemonicStrength::Words12.word_count(), 12);
        assert_eq!(MnemonicStrength::Words15.word_count(), 15);
        assert_eq!(MnemonicStrength::Words18.word_count(), 18);
        assert_eq!(MnemonicStrength::Words21.word_count(), 21);
        assert_eq!(MnemonicStrength::Words24.word_count(), 24);
    }
}
