//! Polkadot/Substrate blockchain support
//!
//! Provides signing and transaction support for Polkadot ecosystem chains:
//! - Polkadot (DOT)
//! - Kusama (KSM)
//! - Acala, Moonbeam, Astar, and other parachains

use crate::error::{BlockchainError, Result};
use blake2::{Blake2b512, Digest as _};

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

    // Checked length conversion: a secp256k1 scalar is exactly 32 bytes.
    // `private_key.into()` would panic on a wrong-length slice, so validate
    // first and return an error instead.
    let key_bytes: &[u8; 32] = private_key.try_into().map_err(|_| {
        BlockchainError::InvalidPrivateKey(format!(
            "ECDSA private key must be 32 bytes, got {}",
            private_key.len()
        ))
    })?;

    let hash = Sha256::digest(message);
    let signing_key = SigningKey::from_bytes(key_bytes.into())
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

    if data.len() < offset + 2 {
        return Err(BlockchainError::InvalidAddress(
            "Address too short".to_string(),
        ));
    }

    // Validate the Blake2b-512 checksum (first 2 bytes of the digest over
    // "SS58PRE" || prefix-and-pubkey). A wrong checksum means a corrupted or
    // forged address and must be rejected.
    let body = &data[..data.len() - 2];
    let provided = &data[data.len() - 2..];
    let expected = ss58_checksum(body);
    if provided != &expected[..2] {
        return Err(BlockchainError::InvalidAddress(
            "SS58 checksum mismatch".to_string(),
        ));
    }

    let public_key = data[offset..data.len() - 2].to_vec();

    Ok((public_key, prefix))
}

/// Calculate the SS58 checksum.
///
/// SS58 uses `Blake2b-512` over `b"SS58PRE" || data`, and takes the first two
/// bytes of the digest as the checksum. (The previous implementation used
/// SHA-512, which produces a checksum no Substrate/Polkadot tooling accepts —
/// HIGH #6.)
fn ss58_checksum(data: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(b"SS58PRE");
    hasher.update(data);
    let hash = hasher.finalize();

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

    /// Canonical SS58 KAT for the well-known "Alice" dev account
    /// (public key `d435...da27d`). These are the published canonical addresses
    /// produced by Substrate/subkey/polkadot.js. Previously the checksum used
    /// SHA-512 instead of Blake2b-512, producing addresses no tooling accepts
    /// (HIGH #6).
    #[test]
    fn test_ss58_alice_known_answer() {
        let alice = hex::decode("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
            .unwrap();

        // Substrate generic (prefix 42).
        let substrate = SubstrateAddress::from_public_key(&alice, Network::Substrate).unwrap();
        assert_eq!(
            substrate.ss58,
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        );

        // Polkadot (prefix 0).
        let polkadot = SubstrateAddress::from_public_key(&alice, Network::Polkadot).unwrap();
        assert_eq!(
            polkadot.ss58,
            "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"
        );

        // Kusama (prefix 2).
        let kusama = SubstrateAddress::from_public_key(&alice, Network::Kusama).unwrap();
        assert_eq!(
            kusama.ss58,
            "HNZata7iMYWmk5RvZRTiAsSDhV8366zq2YGb3tLH5Upf74F"
        );
    }

    /// Decoding a canonical SS58 address recovers the correct public key and
    /// network prefix, and round-trips back to the same string.
    #[test]
    fn test_ss58_decode_round_trip() {
        let addr = "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5";
        let decoded = SubstrateAddress::from_ss58(addr).unwrap();
        assert_eq!(
            hex::encode(&decoded.public_key),
            "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
        );
        assert_eq!(decoded.network, 0);

        let reencoded =
            SubstrateAddress::from_public_key(&decoded.public_key, Network::Polkadot).unwrap();
        assert_eq!(reencoded.ss58, addr);
    }

    /// A tampered SS58 address (last checksum byte flipped) must be rejected.
    #[test]
    fn test_ss58_rejects_bad_checksum() {
        // Valid Alice substrate address with the final character altered so the
        // checksum no longer matches.
        let good = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        // Flip the last character to a different valid base58 character.
        let mut chars: Vec<char> = good.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'Y' { 'Z' } else { 'Y' };
        let bad: String = chars.into_iter().collect();

        assert!(SubstrateAddress::from_ss58(&bad).is_err());
    }

    /// A wrong-length ECDSA private key must return an error, not panic.
    /// Previously `private_key.into()` panicked on any slice that was not
    /// exactly 32 bytes (MEDIUM #18).
    #[test]
    fn test_sign_ecdsa_rejects_wrong_length_key() {
        // Too short.
        let short = [0x01u8; 16];
        let err = sign_payload(&short, b"msg", SignatureScheme::Ecdsa);
        assert!(matches!(err, Err(BlockchainError::InvalidPrivateKey(_))));

        // Too long.
        let long = [0x01u8; 33];
        let err = sign_payload(&long, b"msg", SignatureScheme::Ecdsa);
        assert!(matches!(err, Err(BlockchainError::InvalidPrivateKey(_))));

        // Empty.
        let err = sign_payload(&[], b"msg", SignatureScheme::Ecdsa);
        assert!(matches!(err, Err(BlockchainError::InvalidPrivateKey(_))));
    }

    /// A valid 32-byte ECDSA key produces a verifiable signature (round-trip).
    #[test]
    fn test_sign_ecdsa_valid_key_round_trip() {
        use k256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
        use sha2::{Digest, Sha256};

        // A fixed, valid non-zero scalar.
        let mut key = [0u8; 32];
        key[31] = 0x42;
        let message = b"polkadot ecdsa round trip";

        let sig_bytes = sign_payload(&key, message, SignatureScheme::Ecdsa).unwrap();

        let signing_key = SigningKey::from_bytes((&key).into()).unwrap();
        let verifying_key: VerifyingKey = *signing_key.verifying_key();
        let hash = Sha256::digest(message);
        let signature = Signature::from_slice(&sig_bytes).unwrap();
        assert!(verifying_key.verify(&hash, &signature).is_ok());
    }

    /// A wrong-length Ed25519 key likewise errors rather than panics.
    #[test]
    fn test_sign_ed25519_rejects_wrong_length_key() {
        let short = [0x01u8; 16];
        let err = sign_payload(&short, b"msg", SignatureScheme::Ed25519);
        assert!(matches!(err, Err(BlockchainError::InvalidPrivateKey(_))));
    }
}
