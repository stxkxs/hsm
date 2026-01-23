//! BIP-32: Hierarchical Deterministic Wallets
//!
//! Provides HD key derivation following BIP-32 specification.
//!
//! # Example
//!
//! ```rust
//! use hsm_blockchain::bip::bip32::{ExtendedPrivateKey, DerivationPath};
//! use hsm_blockchain::bip::bip39::{Mnemonic, MnemonicType, Language};
//!
//! // Generate mnemonic and seed
//! let mnemonic = Mnemonic::generate(MnemonicType::Words24, Language::English).unwrap();
//! let seed = mnemonic.to_seed("");
//!
//! // Create master key
//! let master = ExtendedPrivateKey::from_seed(seed.as_bytes()).unwrap();
//!
//! // Derive child key using path
//! let path = DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap();
//! let child = master.derive_path(&path).unwrap();
//! ```

use crate::error::{BlockchainError, Result};
use bip32 as bip32_crate;
use k256::{
    ecdsa::{SigningKey, VerifyingKey},
    SecretKey,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Derivation path index component
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildNumber {
    /// Index value (0-2^31-1 for normal, 0-2^31-1 for hardened)
    pub index: u32,
    /// Whether this is a hardened derivation
    pub hardened: bool,
}

impl ChildNumber {
    /// Create a normal (non-hardened) child number
    pub fn normal(index: u32) -> Self {
        Self {
            index,
            hardened: false,
        }
    }

    /// Create a hardened child number
    pub fn hardened(index: u32) -> Self {
        Self {
            index,
            hardened: true,
        }
    }

    /// Convert to bip32 ChildNumber
    fn to_bip32(&self) -> bip32_crate::ChildNumber {
        if self.hardened {
            bip32_crate::ChildNumber::new(self.index, true).expect("valid index")
        } else {
            bip32_crate::ChildNumber::new(self.index, false).expect("valid index")
        }
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.hardened {
            write!(f, "{}'", self.index)
        } else {
            write!(f, "{}", self.index)
        }
    }
}

/// BIP-32 derivation path
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationPath {
    /// Path components
    components: Vec<ChildNumber>,
}

impl DerivationPath {
    /// Create an empty (master) path
    pub fn master() -> Self {
        Self { components: vec![] }
    }

    /// Create a path from components
    pub fn from_components(components: Vec<ChildNumber>) -> Self {
        Self { components }
    }

    /// Parse a derivation path from string
    ///
    /// Supports formats like:
    /// - "m/44'/60'/0'/0/0"
    /// - "44'/60'/0'/0/0"
    pub fn from_str(path: &str) -> Result<Self> {
        let path = path.trim();

        // Handle empty path or just "m"
        if path.is_empty() || path == "m" {
            return Ok(Self::master());
        }

        // Remove "m/" prefix if present
        let path = path.strip_prefix("m/").unwrap_or(path);

        let mut components = Vec::new();
        for part in path.split('/') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (index_str, hardened) = if let Some(stripped) = part.strip_suffix('\'') {
                (stripped, true)
            } else if let Some(stripped) = part.strip_suffix('h') {
                (stripped, true)
            } else if let Some(stripped) = part.strip_suffix('H') {
                (stripped, true)
            } else {
                (part, false)
            };

            let index: u32 = index_str.parse().map_err(|_| {
                BlockchainError::InvalidDerivationPath(format!("Invalid index: {}", part))
            })?;

            components.push(if hardened {
                ChildNumber::hardened(index)
            } else {
                ChildNumber::normal(index)
            });
        }

        Ok(Self { components })
    }

    /// Get path components
    pub fn components(&self) -> &[ChildNumber] {
        &self.components
    }

    /// Get the depth of the path
    pub fn depth(&self) -> usize {
        self.components.len()
    }

    /// Append a child number to the path
    pub fn child(&self, child: ChildNumber) -> Self {
        let mut components = self.components.clone();
        components.push(child);
        Self { components }
    }

    /// Create a standard Ethereum path (BIP-44)
    pub fn ethereum(account: u32, address_index: u32) -> Self {
        Self::from_components(vec![
            ChildNumber::hardened(44), // BIP-44
            ChildNumber::hardened(60), // Ethereum
            ChildNumber::hardened(account),
            ChildNumber::normal(0), // External chain
            ChildNumber::normal(address_index),
        ])
    }

    /// Create a standard Bitcoin path (BIP-44)
    pub fn bitcoin(account: u32, address_index: u32) -> Self {
        Self::from_components(vec![
            ChildNumber::hardened(44), // BIP-44
            ChildNumber::hardened(0),  // Bitcoin
            ChildNumber::hardened(account),
            ChildNumber::normal(0), // External chain
            ChildNumber::normal(address_index),
        ])
    }

    /// Create a standard Solana path
    pub fn solana(account: u32) -> Self {
        Self::from_components(vec![
            ChildNumber::hardened(44),  // BIP-44
            ChildNumber::hardened(501), // Solana
            ChildNumber::hardened(account),
            ChildNumber::hardened(0),
        ])
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m")?;
        for component in &self.components {
            write!(f, "/{}", component)?;
        }
        Ok(())
    }
}

/// Extended private key (BIP-32)
#[derive(Clone, ZeroizeOnDrop)]
pub struct ExtendedPrivateKey {
    /// The underlying key bytes (32 bytes)
    #[zeroize(skip)]
    inner: bip32_crate::XPrv,
}

impl ExtendedPrivateKey {
    /// Create from seed bytes
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(BlockchainError::InvalidSeedLength {
                expected: 64,
                actual: seed.len(),
            });
        }

        let inner = bip32_crate::XPrv::new(seed)?;
        Ok(Self { inner })
    }

    /// Derive a child key at the given index
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self> {
        let child_key = self.inner.derive_child(child.to_bip32())?;
        Ok(Self { inner: child_key })
    }

    /// Derive a key at the given path
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self> {
        let mut current = self.clone();
        for component in path.components() {
            current = current.derive_child(*component)?;
        }
        Ok(current)
    }

    /// Get the private key bytes (32 bytes)
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }

    /// Get the secp256k1 signing key
    pub fn to_signing_key(&self) -> SigningKey {
        let secret_key = SecretKey::from_bytes(&self.inner.to_bytes().into()).expect("valid key");
        SigningKey::from(secret_key)
    }

    /// Get the public key
    pub fn public_key(&self) -> ExtendedPublicKey {
        ExtendedPublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Get the chain code
    pub fn chain_code(&self) -> [u8; 32] {
        // Extract chain code from extended key
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(self.inner.attrs().chain_code.as_slice());
        chain_code
    }

    /// Get the depth
    pub fn depth(&self) -> u8 {
        self.inner.attrs().depth
    }
}

impl fmt::Debug for ExtendedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedPrivateKey")
            .field("private_key", &"[REDACTED]")
            .field("chain_code", &"[REDACTED]")
            .field("depth", &self.depth())
            .finish()
    }
}

/// Extended public key (BIP-32)
#[derive(Debug, Clone)]
pub struct ExtendedPublicKey {
    inner: bip32_crate::XPub,
}

impl ExtendedPublicKey {
    /// Get the compressed public key bytes (33 bytes)
    pub fn to_bytes(&self) -> [u8; 33] {
        self.inner.to_bytes()
    }

    /// Get the uncompressed public key bytes (65 bytes)
    pub fn to_uncompressed_bytes(&self) -> [u8; 65] {
        let verifying_key = VerifyingKey::from_sec1_bytes(&self.to_bytes()).expect("valid key");
        verifying_key
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("65 bytes")
    }

    /// Derive a child public key (non-hardened only)
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self> {
        if child.hardened {
            return Err(BlockchainError::DerivationFailed(
                "Cannot derive hardened child from public key".to_string(),
            ));
        }
        let child_key = self.inner.derive_child(child.to_bip32())?;
        Ok(Self { inner: child_key })
    }

    /// Get the chain code
    pub fn chain_code(&self) -> [u8; 32] {
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(self.inner.attrs().chain_code.as_slice());
        chain_code
    }

    /// Get the depth
    pub fn depth(&self) -> u8 {
        self.inner.attrs().depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip::bip39::{Language, Mnemonic, MnemonicType};

    #[test]
    fn test_derivation_path_parse() {
        let path = DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(path.depth(), 5);
        assert_eq!(path.components()[0], ChildNumber::hardened(44));
        assert_eq!(path.components()[1], ChildNumber::hardened(60));
        assert_eq!(path.components()[2], ChildNumber::hardened(0));
        assert_eq!(path.components()[3], ChildNumber::normal(0));
        assert_eq!(path.components()[4], ChildNumber::normal(0));
    }

    #[test]
    fn test_derivation_path_display() {
        let path = DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(path.to_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn test_ethereum_path() {
        let path = DerivationPath::ethereum(0, 0);
        assert_eq!(path.to_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn test_bitcoin_path() {
        let path = DerivationPath::bitcoin(0, 0);
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn test_extended_key_derivation() {
        // BIP-32 test vector 1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

        // Master key should have depth 0
        assert_eq!(master.depth(), 0);

        // Derive m/0'
        let child = master.derive_child(ChildNumber::hardened(0)).unwrap();
        assert_eq!(child.depth(), 1);

        // Public key derivation
        let pubkey = master.public_key();
        assert_eq!(pubkey.depth(), 0);
    }

    #[test]
    fn test_full_derivation_from_mnemonic() {
        let mnemonic = Mnemonic::generate(MnemonicType::Words24, Language::English).unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivateKey::from_seed(seed.as_bytes()).unwrap();

        // Derive Ethereum address 0
        let path = DerivationPath::ethereum(0, 0);
        let derived = master.derive_path(&path).unwrap();

        // Should have valid key
        assert_eq!(derived.depth(), 5);
        assert_eq!(derived.private_key_bytes().len(), 32);
    }

    #[test]
    fn test_public_key_cannot_derive_hardened() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let pubkey = master.public_key();

        // Non-hardened should work
        assert!(pubkey.derive_child(ChildNumber::normal(0)).is_ok());

        // Hardened should fail
        assert!(pubkey.derive_child(ChildNumber::hardened(0)).is_err());
    }

    #[test]
    fn test_extended_key_debug_redacts() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let debug = format!("{:?}", master);
        assert!(debug.contains("REDACTED"));
    }
}
