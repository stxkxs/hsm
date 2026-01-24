//! Polkadot/Substrate blockchain support
//!
//! Provides signing and transaction support for Polkadot ecosystem chains:
//! - Polkadot (DOT)
//! - Kusama (KSM)
//! - Acala, Moonbeam, Astar, and other parachains

use crate::error::{BlockchainError, Result};
use sha2::{Digest, Sha512};

/// Polkadot address (SS58 encoded)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstrateAddress {
    /// Raw public key bytes (32 bytes for Sr25519/Ed25519)
    pub public_key: Vec<u8>,
    /// SS58 encoded address
    pub ss58: String,
    /// Network prefix
    pub network: u16,
}

/// Known Substrate networks with their SS58 prefixes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Polkadot (prefix 0)
    Polkadot,
    /// Kusama (prefix 2)
    Kusama,
    /// Westend testnet (prefix 42)
    Westend,
    /// Generic Substrate (prefix 42)
    Substrate,
    /// Acala (prefix 10)
    Acala,
    /// Moonbeam (prefix 1284)
    Moonbeam,
    /// Astar (prefix 5)
    Astar,
}

impl Network {
    /// Get the SS58 prefix for this network
    pub fn prefix(&self) -> u16 {
        match self {
            Self::Polkadot => 0,
            Self::Kusama => 2,
            Self::Westend | Self::Substrate => 42,
            Self::Acala => 10,
            Self::Moonbeam => 1284,
            Self::Astar => 5,
        }
    }
}

/// Signature scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// Ed25519
    Ed25519,
    /// Sr25519 (Schnorrkel)
    Sr25519,
    /// ECDSA (secp256k1)
    Ecdsa,
}

impl SubstrateAddress {
    /// Create from public key
    pub fn from_public_key(public_key: &[u8], network: Network) -> Result<Self> {
        if public_key.len() != 32 && public_key.len() != 33 {
            return Err(BlockchainError::InvalidPublicKey(
                "Public key must be 32 or 33 bytes".to_string(),
            ));
        }

        let ss58 = ss58_encode(public_key, network.prefix())?;

        Ok(Self {
            public_key: public_key.to_vec(),
            ss58,
            network: network.prefix(),
        })
    }

    /// Parse SS58 address
    pub fn from_ss58(address: &str) -> Result<Self> {
        let (public_key, network) = ss58_decode(address)?;

        Ok(Self {
            public_key,
            ss58: address.to_string(),
            network,
        })
    }
}

/// Extrinsic (transaction) structure
#[derive(Debug, Clone)]
pub struct Extrinsic {
    /// Signature type
    pub signature_type: SignatureScheme,
    /// Signer public key
    pub signer: Vec<u8>,
    /// Signature
    pub signature: Vec<u8>,
    /// Extra data (era, nonce, tip)
    pub extra: ExtrinsicExtra,
    /// Call data
    pub call: Call,
}

/// Extra extrinsic data
#[derive(Debug, Clone)]
pub struct ExtrinsicExtra {
    /// Era (mortal or immortal)
    pub era: Era,
    /// Account nonce
    pub nonce: u64,
    /// Tip
    pub tip: u128,
}

/// Transaction era
#[derive(Debug, Clone)]
pub enum Era {
    /// Immortal transaction
    Immortal,
    /// Mortal transaction (period, phase)
    Mortal { period: u64, phase: u64 },
}

/// Call data
#[derive(Debug, Clone)]
pub struct Call {
    /// Pallet index
    pub pallet_index: u8,
    /// Call index
    pub call_index: u8,
    /// Call arguments (SCALE encoded)
    pub args: Vec<u8>,
}

/// Sign a payload
pub fn sign_payload(
    private_key: &[u8],
    payload: &[u8],
    scheme: SignatureScheme,
) -> Result<Vec<u8>> {
    match scheme {
        SignatureScheme::Ed25519 => sign_ed25519(private_key, payload),
        SignatureScheme::Sr25519 => {
            // Sr25519 requires a specialized library
            Err(BlockchainError::UnsupportedAlgorithm(
                "Sr25519 not yet implemented".to_string(),
            ))
        }
        SignatureScheme::Ecdsa => sign_ecdsa(private_key, payload),
    }
}

/// Sign with Ed25519
fn sign_ed25519(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(private_key.try_into().map_err(|_| {
        BlockchainError::InvalidPrivateKey("Invalid Ed25519 private key".to_string())
    })?);

    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Sign with ECDSA
fn sign_ecdsa(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};
    use sha2::Sha256;

    let hash = Sha256::digest(message);
    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|e| BlockchainError::InvalidPrivateKey(e.to_string()))?;

    let signature: Signature = signing_key.sign(&hash);
    Ok(signature.to_bytes().to_vec())
}

/// SS58 encode
fn ss58_encode(public_key: &[u8], prefix: u16) -> Result<String> {
    use bs58;

    let mut data = Vec::new();

    // Encode prefix
    if prefix < 64 {
        data.push(prefix as u8);
    } else {
        let first = ((prefix & 0x00FC) >> 2) | 0x40;
        let second = ((prefix >> 8) | ((prefix & 0x0003) << 6)) as u8;
        data.push(first as u8);
        data.push(second);
    }

    data.extend_from_slice(public_key);

    // Add checksum
    let checksum = ss58_checksum(&data);
    data.extend_from_slice(&checksum[..2]);

    Ok(bs58::encode(data).into_string())
}

/// SS58 decode
fn ss58_decode(address: &str) -> Result<(Vec<u8>, u16)> {
    use bs58;

    let data = bs58::decode(address)
        .into_vec()
        .map_err(|e| BlockchainError::InvalidAddress(format!("Invalid base58: {}", e)))?;

    if data.len() < 3 {
        return Err(BlockchainError::InvalidAddress(
            "Address too short".to_string(),
        ));
    }

    // Decode prefix
    let (prefix, offset) = if data[0] < 64 {
        (data[0] as u16, 1)
    } else {
        let prefix = ((data[0] & 0x3F) << 2) as u16
            | ((data[1] >> 6) as u16)
            | ((data[1] & 0x3F) as u16) << 8;
        (prefix, 2)
    };

    let public_key = data[offset..data.len() - 2].to_vec();

    Ok((public_key, prefix))
}

/// Calculate SS58 checksum
fn ss58_checksum(data: &[u8]) -> [u8; 64] {
    let prefix = b"SS58PRE";
    let mut input = Vec::with_capacity(prefix.len() + data.len());
    input.extend_from_slice(prefix);
    input.extend_from_slice(data);

    let hash = Sha512::digest(&input);
    let mut result = [0u8; 64];
    result.copy_from_slice(&hash);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_prefix() {
        assert_eq!(Network::Polkadot.prefix(), 0);
        assert_eq!(Network::Kusama.prefix(), 2);
    }
}
