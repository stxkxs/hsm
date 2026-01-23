//! Bitcoin address generation and validation
//!
//! Supports:
//! - P2PKH (Legacy addresses starting with 1)
//! - P2SH (Script hash addresses starting with 3)
//! - P2WPKH (Native SegWit starting with bc1q)
//! - P2TR (Taproot starting with bc1p)

use crate::error::{BlockchainError, Result};
use bitcoin::{
    address::NetworkChecked,
    key::CompressedPublicKey,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    Address, Network, PrivateKey,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Bitcoin network type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BitcoinNetwork {
    /// Bitcoin mainnet
    #[default]
    Mainnet,
    /// Bitcoin testnet
    Testnet,
    /// Bitcoin signet
    Signet,
    /// Bitcoin regtest
    Regtest,
}

impl BitcoinNetwork {
    /// Convert to bitcoin crate Network
    fn to_network(&self) -> Network {
        match self {
            BitcoinNetwork::Mainnet => Network::Bitcoin,
            BitcoinNetwork::Testnet => Network::Testnet,
            BitcoinNetwork::Signet => Network::Signet,
            BitcoinNetwork::Regtest => Network::Regtest,
        }
    }
}

/// Bitcoin address types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressType {
    /// Pay-to-Public-Key-Hash (Legacy, starts with 1)
    P2PKH,
    /// Pay-to-Script-Hash (starts with 3)
    P2SH,
    /// Pay-to-Witness-Public-Key-Hash (Native SegWit, starts with bc1q)
    P2WPKH,
    /// Pay-to-Taproot (starts with bc1p)
    P2TR,
}

/// Bitcoin address
#[derive(Debug, Clone)]
pub struct BitcoinAddress {
    /// The bitcoin address
    inner: Address<NetworkChecked>,
    /// Address type
    address_type: AddressType,
    /// Network
    network: BitcoinNetwork,
}

impl BitcoinAddress {
    /// Create P2PKH address from public key
    pub fn p2pkh(public_key: &[u8], network: BitcoinNetwork) -> Result<Self> {
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_slice(public_key)
            .map_err(|e| BlockchainError::InvalidPublicKey(e.to_string()))?;

        let compressed = CompressedPublicKey(pubkey);
        let address = Address::p2pkh(compressed, network.to_network());

        Ok(Self {
            inner: address,
            address_type: AddressType::P2PKH,
            network,
        })
    }

    /// Create P2WPKH (native SegWit) address from public key
    pub fn p2wpkh(public_key: &[u8], network: BitcoinNetwork) -> Result<Self> {
        let pubkey = PublicKey::from_slice(public_key)
            .map_err(|e| BlockchainError::InvalidPublicKey(e.to_string()))?;

        let compressed = CompressedPublicKey(pubkey);
        let address = Address::p2wpkh(&compressed, network.to_network());

        Ok(Self {
            inner: address,
            address_type: AddressType::P2WPKH,
            network,
        })
    }

    /// Create P2TR (Taproot) address from public key (x-only)
    pub fn p2tr(public_key: &[u8], network: BitcoinNetwork) -> Result<Self> {
        use bitcoin::key::UntweakedPublicKey;

        // For Taproot, we need the x-only public key (32 bytes)
        let xonly = if public_key.len() == 32 {
            UntweakedPublicKey::from_slice(public_key)
                .map_err(|e| BlockchainError::InvalidPublicKey(e.to_string()))?
        } else if public_key.len() == 33 {
            // Compressed pubkey, extract x coordinate
            UntweakedPublicKey::from_slice(&public_key[1..])
                .map_err(|e| BlockchainError::InvalidPublicKey(e.to_string()))?
        } else {
            return Err(BlockchainError::InvalidPublicKey(
                "Expected 32 or 33 byte public key".to_string(),
            ));
        };

        let secp = Secp256k1::new();
        let address = Address::p2tr(&secp, xonly, None, network.to_network());

        Ok(Self {
            inner: address,
            address_type: AddressType::P2TR,
            network,
        })
    }

    /// Create address from private key bytes
    pub fn from_private_key(
        private_key: &[u8],
        address_type: AddressType,
        network: BitcoinNetwork,
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(private_key)
            .map_err(|e| BlockchainError::InvalidPrivateKey(e.to_string()))?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let pubkey_bytes = public_key.serialize();

        match address_type {
            AddressType::P2PKH => Self::p2pkh(&pubkey_bytes, network),
            AddressType::P2WPKH => Self::p2wpkh(&pubkey_bytes, network),
            AddressType::P2TR => Self::p2tr(&pubkey_bytes[1..], network), // x-only
            AddressType::P2SH => Err(BlockchainError::UnsupportedOperation(
                "P2SH requires a script, not just a public key".to_string(),
            )),
        }
    }

    /// Parse address from string
    pub fn from_str(address: &str, network: BitcoinNetwork) -> Result<Self> {
        let parsed: Address<NetworkChecked> = address
            .parse::<Address<_>>()
            .map_err(|e| BlockchainError::InvalidAddress(e.to_string()))?
            .require_network(network.to_network())
            .map_err(|e| BlockchainError::InvalidAddress(e.to_string()))?;

        // Determine address type from prefix
        let address_type =
            if address.starts_with('1') || address.starts_with('m') || address.starts_with('n') {
                AddressType::P2PKH
            } else if address.starts_with('3') || address.starts_with('2') {
                AddressType::P2SH
            } else if address.starts_with("bc1q") || address.starts_with("tb1q") {
                AddressType::P2WPKH
            } else if address.starts_with("bc1p") || address.starts_with("tb1p") {
                AddressType::P2TR
            } else {
                return Err(BlockchainError::InvalidAddress(
                    "Unknown address type".to_string(),
                ));
            };

        Ok(Self {
            inner: parsed,
            address_type,
            network,
        })
    }

    /// Get the address string
    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }

    /// Get the address type
    pub fn address_type(&self) -> AddressType {
        self.address_type
    }

    /// Get the network
    pub fn network(&self) -> BitcoinNetwork {
        self.network
    }

    /// Check if address is for mainnet
    pub fn is_mainnet(&self) -> bool {
        self.network == BitcoinNetwork::Mainnet
    }

    /// Validate an address string
    pub fn validate(address: &str) -> bool {
        address.parse::<Address<_>>().is_ok()
    }
}

impl fmt::Display for BitcoinAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pkh_address() {
        // Test with a known compressed public key
        let pubkey =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
                .unwrap();

        let address = BitcoinAddress::p2pkh(&pubkey, BitcoinNetwork::Mainnet).unwrap();
        assert_eq!(address.address_type(), AddressType::P2PKH);
        assert!(address.to_string().starts_with('1'));
    }

    #[test]
    fn test_p2wpkh_address() {
        let pubkey =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
                .unwrap();

        let address = BitcoinAddress::p2wpkh(&pubkey, BitcoinNetwork::Mainnet).unwrap();
        assert_eq!(address.address_type(), AddressType::P2WPKH);
        assert!(address.to_string().starts_with("bc1q"));
    }

    #[test]
    fn test_testnet_address() {
        let pubkey =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
                .unwrap();

        let address = BitcoinAddress::p2wpkh(&pubkey, BitcoinNetwork::Testnet).unwrap();
        assert!(address.to_string().starts_with("tb1q"));
    }

    #[test]
    fn test_address_validation() {
        // Valid mainnet P2PKH
        assert!(BitcoinAddress::validate(
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        ));

        // Valid mainnet P2WPKH
        assert!(BitcoinAddress::validate(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        ));

        // Invalid address
        assert!(!BitcoinAddress::validate("invalid_address"));
    }

    #[test]
    fn test_parse_address() {
        let addr = BitcoinAddress::from_str(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            BitcoinNetwork::Mainnet,
        )
        .unwrap();

        assert_eq!(addr.address_type(), AddressType::P2WPKH);
        assert_eq!(addr.network(), BitcoinNetwork::Mainnet);
    }
}
