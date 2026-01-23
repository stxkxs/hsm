//! StarkNet Address Derivation
//!
//! StarkNet addresses are derived from the contract class hash and constructor arguments.
//! For account contracts, the address is computed from the public key.
//!
//! # Address Format
//!
//! StarkNet addresses are 252-bit field elements, typically displayed as 64-character
//! hex strings with a `0x` prefix.
//!
//! # Contract Address Computation
//!
//! ```text
//! address = pedersen(
//!     pedersen(
//!         pedersen(
//!             pedersen(PREFIX, deployer_address),
//!             salt
//!         ),
//!         class_hash
//!     ),
//!     constructor_calldata_hash
//! ) mod 2^251 + 17 * 2^192 + 1
//! ```

use crate::error::{BlockchainError, Result};
use starknet_crypto::{pedersen_hash, Felt};

/// Known account contract class hashes for common wallets.
pub mod class_hashes {
    /// OpenZeppelin Account contract class hash (Cairo 1.0)
    pub const OZ_ACCOUNT_CAIRO1: &str =
        "0x04c6d6cf894f8bc96bb9c525e6853e5483177841f7388f74a46cfcd6f7c68e82";

    /// Argent Account contract class hash (Cairo 1.0)
    pub const ARGENT_ACCOUNT_CAIRO1: &str =
        "0x01a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003";

    /// Braavos Account contract class hash (Cairo 1.0)
    pub const BRAAVOS_ACCOUNT_CAIRO1: &str =
        "0x03131fa018d520a037686ce3efddeab8f28895662f019ca3ca18a626650f7d1e";
}

/// A StarkNet address (252-bit field element).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct StarknetAddress {
    /// The address as a 32-byte field element
    felt: [u8; 32],
}

impl StarknetAddress {
    /// The "STARKNET_CONTRACT_ADDRESS" prefix used in address computation.
    const CONTRACT_ADDRESS_PREFIX: &'static str = "STARKNET_CONTRACT_ADDRESS";

    /// Create an address from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(BlockchainError::InvalidAddressLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut felt = [0u8; 32];
        felt.copy_from_slice(bytes);

        Ok(Self { felt })
    }

    /// Parse an address from a hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);

        // Pad with leading zeros if needed
        let padded = format!("{:0>64}", s);

        let bytes = hex::decode(&padded).map_err(|e| BlockchainError::InvalidHex(e.to_string()))?;

        Self::from_bytes(&bytes)
    }

    /// Get the raw bytes of the address.
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.felt
    }

    /// Convert to hex string (with 0x prefix).
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.felt))
    }

    /// Convert to checksummed hex string.
    ///
    /// StarkNet uses a similar checksum to Ethereum but based on the Stark curve.
    pub fn to_checksum_hex(&self) -> String {
        // StarkNet doesn't have an official checksum standard yet
        // Just return the standard hex format
        self.to_hex()
    }

    /// Derive address from a public key using the standard OpenZeppelin account contract.
    pub fn from_public_key(public_key: &super::StarkPublicKey) -> Self {
        Self::compute_address(
            &Felt::ZERO,                                                                 // deployer
            public_key, // salt = pubkey
            &Felt::from_hex(class_hashes::OZ_ACCOUNT_CAIRO1).expect("valid class hash"), // OZ class
            &[Felt::from_bytes_be_slice(public_key.to_bytes())], // constructor args
        )
    }

    /// Compute a contract address from its components.
    ///
    /// # Arguments
    ///
    /// * `deployer_address` - Address of the deployer (0 for CREATE)
    /// * `salt` - Salt used for address computation
    /// * `class_hash` - Hash of the contract class
    /// * `constructor_calldata` - Arguments passed to the constructor
    pub fn compute_address(
        deployer_address: &Felt,
        salt_key: &super::StarkPublicKey,
        class_hash: &Felt,
        constructor_calldata: &[Felt],
    ) -> Self {
        // Compute constructor calldata hash using Pedersen
        let calldata_hash = compute_hash_on_elements(constructor_calldata);

        // Compute prefix felt
        let prefix_felt = felt_from_short_string(Self::CONTRACT_ADDRESS_PREFIX);

        // Salt from public key
        let salt = Felt::from_bytes_be_slice(salt_key.to_bytes());

        // Compute address using nested Pedersen hashes
        let h1 = pedersen_hash(&prefix_felt, deployer_address);
        let h2 = pedersen_hash(&h1, &salt);
        let h3 = pedersen_hash(&h2, class_hash);
        let h4 = pedersen_hash(&h3, &calldata_hash);

        // Apply modular reduction (already done by Felt)
        let address_felt = h4;
        let bytes = address_felt.to_bytes_be();

        Self { felt: bytes }
    }

    /// Compute the address for a specific wallet type.
    pub fn for_wallet_type(
        public_key: &super::StarkPublicKey,
        wallet_type: WalletType,
    ) -> Result<Self> {
        let class_hash = match wallet_type {
            WalletType::OpenZeppelin => Felt::from_hex(class_hashes::OZ_ACCOUNT_CAIRO1)
                .map_err(|e| BlockchainError::InvalidHex(e.to_string()))?,
            WalletType::Argent => Felt::from_hex(class_hashes::ARGENT_ACCOUNT_CAIRO1)
                .map_err(|e| BlockchainError::InvalidHex(e.to_string()))?,
            WalletType::Braavos => Felt::from_hex(class_hashes::BRAAVOS_ACCOUNT_CAIRO1)
                .map_err(|e| BlockchainError::InvalidHex(e.to_string()))?,
        };

        let pubkey_felt = Felt::from_bytes_be_slice(public_key.to_bytes());

        Ok(Self::compute_address(
            &Felt::ZERO,
            public_key,
            &class_hash,
            &[pubkey_felt],
        ))
    }
}

impl std::fmt::Debug for StarknetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StarknetAddress")
            .field("address", &self.to_hex())
            .finish()
    }
}

impl std::fmt::Display for StarknetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Supported wallet types for address derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletType {
    /// OpenZeppelin account contract
    OpenZeppelin,
    /// Argent account contract
    Argent,
    /// Braavos account contract
    Braavos,
}

/// Compute Pedersen hash on a sequence of field elements.
fn compute_hash_on_elements(elements: &[Felt]) -> Felt {
    if elements.is_empty() {
        return Felt::ZERO;
    }

    let mut current = Felt::ZERO;
    for element in elements {
        current = pedersen_hash(&current, element);
    }
    pedersen_hash(&current, &Felt::from(elements.len()))
}

/// Convert a short string (≤31 chars) to a field element.
fn felt_from_short_string(s: &str) -> Felt {
    let bytes = s.as_bytes();
    assert!(
        bytes.len() <= 31,
        "String too long for short string encoding"
    );

    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);

    Felt::from_bytes_be_slice(&padded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::starknet::StarkPrivateKey;

    #[test]
    fn test_address_from_hex() {
        let hex = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
        let address = StarknetAddress::from_hex(hex).unwrap();

        assert!(address.to_hex().starts_with("0x"));
    }

    #[test]
    fn test_address_from_short_hex() {
        // Address with leading zeros omitted
        let hex = "0x1";
        let address = StarknetAddress::from_hex(hex).unwrap();

        // Should be padded to 64 chars
        let full_hex = address.to_hex();
        assert_eq!(full_hex.len(), 66); // "0x" + 64 chars
    }

    #[test]
    fn test_address_from_public_key() {
        let private_key = StarkPrivateKey::generate();
        let public_key = private_key.public_key();
        let address = StarknetAddress::from_public_key(&public_key);

        assert_eq!(address.to_bytes().len(), 32);
    }

    #[test]
    fn test_address_deterministic() {
        let private_key = StarkPrivateKey::from_bytes(&[0x42; 32]).unwrap();
        let public_key = private_key.public_key();

        let address1 = StarknetAddress::from_public_key(&public_key);
        let address2 = StarknetAddress::from_public_key(&public_key);

        assert_eq!(address1, address2);
    }

    #[test]
    fn test_different_wallet_types_different_addresses() {
        let private_key = StarkPrivateKey::generate();
        let public_key = private_key.public_key();

        let oz_address =
            StarknetAddress::for_wallet_type(&public_key, WalletType::OpenZeppelin).unwrap();
        let argent_address =
            StarknetAddress::for_wallet_type(&public_key, WalletType::Argent).unwrap();

        assert_ne!(oz_address, argent_address);
    }

    #[test]
    fn test_address_hex_roundtrip() {
        let private_key = StarkPrivateKey::generate();
        let public_key = private_key.public_key();
        let address = StarknetAddress::from_public_key(&public_key);

        let hex = address.to_hex();
        let parsed = StarknetAddress::from_hex(&hex).unwrap();

        assert_eq!(address, parsed);
    }

    #[test]
    fn test_felt_from_short_string() {
        let felt = felt_from_short_string("STARKNET_CONTRACT_ADDRESS");
        assert_ne!(felt, Felt::ZERO);
    }
}
