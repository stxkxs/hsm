//! Ethereum address generation and validation
//!
//! Generates Ethereum addresses from secp256k1 public keys using Keccak-256.

use crate::error::{BlockchainError, Result};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::fmt;

/// Ethereum address (20 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthereumAddress([u8; 20]);

impl EthereumAddress {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Create from a public key
    pub fn from_public_key(public_key: &[u8]) -> Result<Self> {
        // Handle both compressed (33 bytes) and uncompressed (65 bytes) formats
        let uncompressed = if public_key.len() == 33 {
            let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|e| BlockchainError::InvalidPublicKey(e.to_string()))?;
            let point = verifying_key.to_encoded_point(false);
            point.as_bytes().to_vec()
        } else if public_key.len() == 65 {
            public_key.to_vec()
        } else {
            return Err(BlockchainError::InvalidPublicKey(format!(
                "Invalid public key length: expected 33 or 65 bytes, got {}",
                public_key.len()
            )));
        };

        // Remove the 0x04 prefix for uncompressed keys
        let key_bytes = if uncompressed[0] == 0x04 {
            &uncompressed[1..]
        } else {
            &uncompressed[..]
        };

        // Keccak-256 hash of the public key (excluding prefix)
        let hash = Keccak256::digest(key_bytes);

        // Take the last 20 bytes
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);

        Ok(Self(address))
    }

    /// Create from a verifying key
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        let point = key.to_encoded_point(false);
        let key_bytes = &point.as_bytes()[1..]; // Skip 0x04 prefix
        let hash = Keccak256::digest(key_bytes);

        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);

        Self(address)
    }

    /// Parse from hex string (with or without 0x prefix)
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

        if hex_str.len() != 40 {
            return Err(BlockchainError::InvalidAddress(format!(
                "Invalid address length: expected 40 hex characters, got {}",
                hex_str.len()
            )));
        }

        let bytes =
            hex::decode(hex_str).map_err(|e| BlockchainError::InvalidAddress(e.to_string()))?;

        let mut address = [0u8; 20];
        address.copy_from_slice(&bytes);

        Ok(Self(address))
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Get the checksummed address (EIP-55)
    pub fn to_checksum_string(&self) -> String {
        let hex_addr = hex::encode(self.0);
        let hash = Keccak256::digest(hex_addr.as_bytes());

        let mut checksum = String::with_capacity(42);
        checksum.push_str("0x");

        for (i, c) in hex_addr.chars().enumerate() {
            let hash_byte = hash[i / 2];
            let hash_nibble = if i % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0f
            };

            if c.is_ascii_alphabetic() && hash_nibble >= 8 {
                checksum.push(c.to_ascii_uppercase());
            } else {
                checksum.push(c);
            }
        }

        checksum
    }

    /// Validate checksum (EIP-55)
    pub fn validate_checksum(address: &str) -> bool {
        let address = address.strip_prefix("0x").unwrap_or(address);

        if address.len() != 40 {
            return false;
        }

        // Parse the address
        if let Ok(parsed) = Self::from_hex(address) {
            let checksum = parsed.to_checksum_string();
            let expected = if address
                .chars()
                .next()
                .map(|c| c.is_uppercase())
                .unwrap_or(false)
            {
                checksum.strip_prefix("0x").unwrap_or(&checksum)
            } else if address.starts_with("0x") || address.starts_with("0X") {
                &checksum
            } else {
                checksum.strip_prefix("0x").unwrap_or(&checksum)
            };

            // Compare case-sensitive for checksum validation
            address.eq_ignore_ascii_case(expected)
        } else {
            false
        }
    }
}

impl fmt::Debug for EthereumAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EthereumAddress({})", self.to_checksum_string())
    }
}

impl fmt::Display for EthereumAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_checksum_string())
    }
}

impl From<[u8; 20]> for EthereumAddress {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for EthereumAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_from_hex() {
        let addr = EthereumAddress::from_hex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();
        assert_eq!(
            addr.to_checksum_string(),
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        );
    }

    #[test]
    fn test_address_from_hex_no_prefix() {
        let addr = EthereumAddress::from_hex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();
        assert_eq!(
            addr.to_checksum_string(),
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        );
    }

    #[test]
    fn test_checksum_addresses() {
        // Test vectors from EIP-55
        let test_cases = vec![
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ];

        for expected in test_cases {
            let addr = EthereumAddress::from_hex(expected).unwrap();
            assert_eq!(addr.to_checksum_string(), expected);
        }
    }

    #[test]
    fn test_invalid_address_length() {
        assert!(EthereumAddress::from_hex("0x1234").is_err());
        assert!(
            EthereumAddress::from_hex("0x1234567890abcdef1234567890abcdef1234567890ab").is_err()
        );
    }

    #[test]
    fn test_address_display() {
        let addr = EthereumAddress::from_hex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();
        assert_eq!(
            format!("{}", addr),
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        );
    }

    proptest::proptest! {
        /// Parsing an arbitrary string as an Ethereum address must never panic;
        /// malformed input must return `Err`.
        #[test]
        fn eth_address_from_hex_never_panics(s in ".*") {
            let _ = EthereumAddress::from_hex(&s);
        }
    }
}
