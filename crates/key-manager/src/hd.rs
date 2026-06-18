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
    fn to_mnemonic_type(self) -> MnemonicType {
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

        // Reconstruct the REAL master extended key from its stored components.
        //
        // BIP-32 child derivation (CKDpriv) is a function of the parent private
        // key, the parent chain code, and the child index only. The master key
        // is the root of the tree (depth = 0, parent fingerprint = 0,
        // child number = 0), so rebuilding it from (private_key, chain_code)
        // with those root attributes yields an XPrv that is byte-for-byte
        // identical to the one originally produced by `from_seed`, and therefore
        // derives the correct BIP-32/44 child keys.
        //
        // NOTE: This intentionally does NOT round-trip through
        // `ExtendedPrivateKey::from_seed`. `from_seed` is the BIP-32 *master
        // generation* step (HMAC-SHA512("Bitcoin seed", seed)); feeding it
        // (private||chain_code) would hash those 64 bytes into an unrelated
        // master key and silently produce wrong keys/addresses.
        let master_xprv = reconstruct_master_xprv(master_private.as_bytes(), master_chain_code)?;

        // Parse derivation path
        let derivation_path = DerivationPath::from_str(path)
            .map_err(|e| Error::InvalidKeyData(format!("Invalid derivation path: {}", e)))?;

        // Derive child key directly on the reconstructed XPrv, walking each
        // path component (CKDpriv), mirroring blockchain::ExtendedPrivateKey.
        let mut child_xprv = master_xprv;
        for component in derivation_path.components() {
            let bip32_child = bip32::ChildNumber::new(component.index, component.hardened)
                .map_err(|e| Error::InvalidKeyData(format!("Invalid child index: {}", e)))?;
            child_xprv = child_xprv
                .derive_child(bip32_child)
                .map_err(|e| Error::KeyGenerationFailed(format!("Derivation failed: {}", e)))?;
        }

        // Extract child key material
        let child_private: [u8; 32] = child_xprv.to_bytes();
        let child_chain_code = child_xprv.attrs().chain_code.to_vec();

        // Compressed secp256k1 public key (33 bytes), matching the master key's
        // public-key encoding produced by blockchain::ExtendedPublicKey.
        let child_public_bytes = child_xprv.public_key().to_bytes();

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
    /// Creates a key at path: `m/44'/<coin>'/<account>'/0/<address_index>`
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

    /// Compute the BIP-32 key fingerprint: the first 4 bytes of
    /// `HASH160(pubkey) = RIPEMD160(SHA256(pubkey))`, where `pubkey` is the
    /// 33-byte compressed secp256k1 public key (BIP-32 §"Key identifiers").
    fn compute_fingerprint(&self, public_key: Option<&Vec<u8>>) -> Result<[u8; 4]> {
        use ripemd::Ripemd160;
        use sha2::{Digest, Sha256};

        let public_key = public_key
            .ok_or_else(|| Error::InvalidKeyData("No public key for fingerprint".to_string()))?;

        // HASH160 = RIPEMD160(SHA256(pubkey))
        let sha = Sha256::digest(public_key);
        let hash160 = Ripemd160::digest(sha);

        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&hash160[..4]);
        Ok(fingerprint)
    }
}

/// Faithfully reconstruct the master BIP-32 extended private key (`XPrv`) from
/// its stored components (32-byte private key + 32-byte chain code).
///
/// The master node is the root of the derivation tree, so its extended-key
/// attributes are fixed by BIP-32: `depth = 0`, `parent_fingerprint = 0`,
/// `child_number = 0`. We rebuild the `XPrv` from these exact attributes plus
/// the stored key material, which is byte-for-byte identical to the `XPrv` that
/// `from_seed` originally produced. BIP-32 child derivation (CKDpriv) then
/// yields the correct child keys.
///
/// This must NOT be done by passing `(private||chain_code)` to `from_seed`,
/// which is the master-generation HMAC step and would derive an unrelated key.
fn reconstruct_master_xprv(
    private_key_bytes: &[u8],
    chain_code_bytes: &[u8],
) -> Result<bip32::XPrv> {
    let private_key: [u8; 32] = private_key_bytes.try_into().map_err(|_| {
        Error::InvalidKeyData(format!(
            "Master private key must be 32 bytes, got {}",
            private_key_bytes.len()
        ))
    })?;
    let chain_code: bip32::ChainCode = chain_code_bytes.try_into().map_err(|_| {
        Error::InvalidKeyData(format!(
            "Master chain code must be 32 bytes, got {}",
            chain_code_bytes.len()
        ))
    })?;

    // BIP-32 extended-key serialization places the 32-byte private scalar after
    // a single leading `0x00` tag byte.
    let mut key_bytes = [0u8; 33];
    key_bytes[1..].copy_from_slice(&private_key);

    let extended_key = bip32::ExtendedKey {
        prefix: bip32::Prefix::XPRV,
        attrs: bip32::ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: bip32::ChildNumber::default(),
            chain_code,
        },
        key_bytes,
    };

    bip32::XPrv::try_from(extended_key)
        .map_err(|e| Error::InvalidKeyData(format!("Failed to reconstruct master key: {}", e)))
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

    /// Canonical test mnemonic. DO NOT USE IN PRODUCTION.
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// KNOWN-ANSWER TEST: derivation through `derive_key` MUST reproduce the
    /// canonical BIP-32/44 secp256k1 key for the well-known
    /// "abandon ... about" mnemonic at `m/44'/60'/0'/0/0`.
    ///
    /// The buggy implementation re-hashed `(private||chain_code)` through
    /// `from_seed`, producing the WRONG private key `69f6b5...e7ad` and an
    /// unrelated Ethereum address. The fixed implementation reconstructs the
    /// real master XPrv and produces the canonical private key
    /// `1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727`
    /// and Ethereum address `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`.
    #[test]
    fn test_kat_ethereum_derivation_abandon_about() {
        use hsm_blockchain::ethereum::EthereumAddress;

        let store = create_test_store();
        let hd_manager = HdKeyManager::new(store.clone());

        let master_id = hd_manager
            .import_master_key("test", TEST_MNEMONIC, None)
            .expect("Should import master key");

        let derived_id = hd_manager
            .derive_key(&master_id, "test", "m/44'/60'/0'/0/0")
            .expect("Should derive key");

        let derived = store
            .get("test", &derived_id)
            .expect("Derived key should exist");

        // --- Private key KAT (this is what the bug corrupted) ---
        let private_material = derived
            .private_material
            .as_ref()
            .expect("Derived key has private material");
        assert_eq!(
            to_hex(private_material.as_bytes()),
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
            "derived private key must match the canonical BIP-32/44 vector; \
             the buggy from_seed round-trip produced 69f6b5...e7ad"
        );

        // --- Ethereum address KAT (end-to-end wallet interop) ---
        let public_material = derived
            .public_material
            .as_ref()
            .expect("Derived key has public material");
        let address = EthereumAddress::from_public_key(public_material)
            .expect("Should compute Ethereum address from derived pubkey");
        assert_eq!(
            address.to_checksum_string(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "derived Ethereum address must match the canonical wallet vector"
        );
    }

    /// KAT: a second standard address index must also match the canonical
    /// vector, proving derivation is correct across the path (not a fluke).
    /// `m/44'/60'/0'/0/1` => 0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0
    #[test]
    fn test_kat_ethereum_derivation_index_1() {
        use hsm_blockchain::ethereum::EthereumAddress;

        let store = create_test_store();
        let hd_manager = HdKeyManager::new(store.clone());

        let master_id = hd_manager
            .import_master_key("test", TEST_MNEMONIC, None)
            .expect("Should import master key");

        let derived_id = hd_manager
            .derive_key(&master_id, "test", "m/44'/60'/0'/0/1")
            .expect("Should derive key");

        let derived = store.get("test", &derived_id).expect("Key exists");
        let public_material = derived.public_material.as_ref().expect("pubkey");
        let address = EthereumAddress::from_public_key(public_material).expect("address");
        assert_eq!(
            address.to_checksum_string(),
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"
        );
    }

    /// Cross-check: deriving the same path twice (independent imports of the
    /// same mnemonic) MUST yield identical key material. This is deterministic
    /// HD derivation and guards against any future reconstruction regression.
    #[test]
    fn test_hd_derivation_is_deterministic() {
        let store = create_test_store();
        let hd_manager = HdKeyManager::new(store.clone());

        let m1 = hd_manager
            .import_master_key("ns1", TEST_MNEMONIC, None)
            .expect("import 1");
        let m2 = hd_manager
            .import_master_key("ns2", TEST_MNEMONIC, None)
            .expect("import 2");

        let d1 = hd_manager
            .derive_key(&m1, "ns1", "m/44'/60'/0'/0/0")
            .expect("derive 1");
        let d2 = hd_manager
            .derive_key(&m2, "ns2", "m/44'/60'/0'/0/0")
            .expect("derive 2");

        let k1 = store.get("ns1", &d1).expect("k1");
        let k2 = store.get("ns2", &d2).expect("k2");

        assert_eq!(
            k1.private_material.as_ref().unwrap().as_bytes(),
            k2.private_material.as_ref().unwrap().as_bytes(),
            "HD derivation must be deterministic for identical mnemonic + path"
        );
        assert_eq!(k1.public_material, k2.public_material);
    }

    /// Known-answer test for the BIP-32 key fingerprint.
    ///
    /// BIP-32 Test Vector 1 (seed `000102...0f`) has master public key
    /// `0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2`
    /// and identifier `3442193e008f4f3151ee9d3bb62ad5c16abb84ba`, so the
    /// 4-byte fingerprint (HASH160[..4]) is `0x3442193e`.
    ///
    /// This pins the algorithm to HASH160 = RIPEMD160(SHA256(pubkey)); a plain
    /// SHA256[..4] would produce `0x60c8022a` and fail this test.
    #[test]
    fn test_kat_bip32_fingerprint_hash160() {
        let store = create_test_store();
        let hd_manager = HdKeyManager::new(store);

        let pubkey =
            hex_decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");

        let fingerprint = hd_manager
            .compute_fingerprint(Some(&pubkey))
            .expect("fingerprint");

        assert_eq!(
            fingerprint,
            [0x34, 0x42, 0x19, 0x3e],
            "BIP-32 fingerprint must be HASH160(pubkey)[..4]"
        );

        // Negative assertion: the old (buggy) SHA256[..4] value must NOT match.
        use sha2::{Digest, Sha256};
        let sha = Sha256::digest(&pubkey);
        assert_ne!(
            fingerprint,
            [sha[0], sha[1], sha[2], sha[3]],
            "fingerprint must not be plain SHA256[..4]"
        );
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
