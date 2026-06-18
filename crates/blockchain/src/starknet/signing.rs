//! StarkNet Message Signing
//!
//! This module provides ECDSA signature operations on the Stark curve,
//! compatible with StarkNet wallets and smart contracts.
//!
//! # Signature Format
//!
//! StarkNet signatures consist of two field elements (r, s), each 252 bits.
//! Unlike Ethereum, there's no recovery ID (v) since the public key is always known.
//!
//! # Message Hashing
//!
//! StarkNet uses Pedersen or Poseidon hash for message hashing, depending on the context:
//! - Typed data uses Poseidon hash (SNIP-12)
//! - Legacy messages use Pedersen hash

use crate::error::{BlockchainError, Result};
use serde::{Deserialize, Serialize};
use starknet_crypto::{pedersen_hash, Felt};
use std::collections::HashMap;

/// A StarkNet ECDSA signature.
#[derive(Clone, PartialEq, Eq)]
pub struct StarkSignature {
    /// The r component of the signature
    r: [u8; 32],
    /// The s component of the signature
    s: [u8; 32],
}

impl StarkSignature {
    /// Create a signature from r and s components.
    pub fn new(r: [u8; 32], s: [u8; 32]) -> Self {
        Self { r, s }
    }

    /// Get the r component.
    pub fn r(&self) -> &[u8; 32] {
        &self.r
    }

    /// Get the s component.
    pub fn s(&self) -> &[u8; 32] {
        &self.s
    }

    /// Convert to hex strings (r, s).
    pub fn to_hex(&self) -> (String, String) {
        (
            format!("0x{}", hex::encode(self.r)),
            format!("0x{}", hex::encode(self.s)),
        )
    }

    /// Parse from hex strings.
    pub fn from_hex(r: &str, s: &str) -> Result<Self> {
        let r_str = r.strip_prefix("0x").unwrap_or(r);
        let s_str = s.strip_prefix("0x").unwrap_or(s);

        let r_padded = format!("{:0>64}", r_str);
        let s_padded = format!("{:0>64}", s_str);

        let r_bytes =
            hex::decode(&r_padded).map_err(|e| BlockchainError::InvalidHex(e.to_string()))?;
        let s_bytes =
            hex::decode(&s_padded).map_err(|e| BlockchainError::InvalidHex(e.to_string()))?;

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&r_bytes);
        s.copy_from_slice(&s_bytes);

        Ok(Self { r, s })
    }

    /// Serialize to bytes (64 bytes total).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r);
        bytes[32..].copy_from_slice(&self.s);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(BlockchainError::InvalidSignatureLength {
                expected: 64,
                actual: bytes.len(),
            });
        }

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);

        Ok(Self { r, s })
    }
}

impl std::fmt::Debug for StarkSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (r_hex, s_hex) = self.to_hex();
        f.debug_struct("StarkSignature")
            .field("r", &r_hex)
            .field("s", &s_hex)
            .finish()
    }
}

/// SNIP-12 Typed Data for structured signing.
///
/// This is the StarkNet equivalent of EIP-712.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedData {
    /// Types defined in the schema
    pub types: HashMap<String, Vec<TypedDataField>>,
    /// Primary type being signed
    #[serde(rename = "primaryType")]
    pub primary_type: String,
    /// Domain separator
    pub domain: StarknetDomain,
    /// The actual message data
    pub message: HashMap<String, serde_json::Value>,
}

/// A field in a typed data structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedDataField {
    /// Field name
    pub name: String,
    /// Field type (e.g., "felt", "ContractAddress", "u256")
    #[serde(rename = "type")]
    pub field_type: String,
}

/// StarkNet domain separator for SNIP-12.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarknetDomain {
    /// Name of the signing domain
    pub name: String,
    /// Version of the signing domain
    pub version: String,
    /// Chain ID (e.g., "SN_MAIN", "SN_GOERLI", "SN_SEPOLIA")
    #[serde(rename = "chainId")]
    pub chain_id: String,
    /// Optional revision (defaults to "1")
    #[serde(default = "default_revision")]
    pub revision: String,
}

fn default_revision() -> String {
    "1".to_string()
}

impl TypedData {
    /// Create a new typed data structure.
    pub fn new(
        types: HashMap<String, Vec<TypedDataField>>,
        primary_type: String,
        domain: StarknetDomain,
        message: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            types,
            primary_type,
            domain,
            message,
        }
    }

    /// Compute the SNIP-12 message hash for signing.
    ///
    /// # Fail-closed: not implemented (GATE, HIGH #8)
    ///
    /// A correct SNIP-12 implementation requires, for the declared `revision`:
    ///
    /// * **revision 1** — Poseidon hashing (not Pedersen), and `struct_hash`
    ///   prefixed by a *type hash* `starknet_keccak(encode_type(...))`, with the
    ///   `StarknetDomain` type and full `encode_type` dependency ordering
    ///   (nested structs, `enum`, arrays, `u256`, `i128`, `timestamp`,
    ///   `selector`, `merkletree`, ...).
    /// * **revision 0** — Pedersen hashing with the legacy `StarkNetDomain`
    ///   type and the rev-0 type-encoding rules.
    ///
    /// The previous implementation used Pedersen for everything and **omitted
    /// the per-struct type hashes entirely**, so it produced a digest that does
    /// not match `starknet.js` / `starknet-rs` for any revision. Signing that
    /// digest yields a signature that wallets and account contracts reject.
    ///
    /// Faithfully reimplementing the full SNIP-12 encoder (with an interop KAT)
    /// is out of scope for this change, and emitting a plausible-but-wrong hash
    /// is a security footgun. This entry point is therefore **fail-closed**: it
    /// returns an explicit error instead of a non-interoperable hash. For
    /// signing a raw, already-correct message digest, use
    /// [`super::StarkPrivateKey::sign_deterministic`] directly with a hash you
    /// computed with a conformant SNIP-12 library.
    pub fn compute_hash(&self, _account_address: &super::StarknetAddress) -> Result<[u8; 32]> {
        Err(BlockchainError::UnsupportedOperation(format!(
            "SNIP-12 typed-data hashing (revision {:?}) is not implemented: a \
             conformant hash needs per-struct type hashes via starknet_keccak \
             and Poseidon (rev 1) / Pedersen (rev 0) with full encode_type \
             dependency ordering. Refusing to emit a non-interoperable hash.",
            self.domain.revision
        )))
    }

    /// Encode each declared field of the primary type to a felt (used for
    /// validating that field values parse). This does NOT compute a
    /// SNIP-12-conformant hash; see [`Self::compute_hash`].
    #[cfg(test)]
    fn encode_primary_fields(&self) -> Result<Vec<Felt>> {
        let fields = self
            .types
            .get(&self.primary_type)
            .ok_or_else(|| BlockchainError::InvalidTypedData("Primary type not found".into()))?;

        let mut out = Vec::with_capacity(fields.len());
        for field in fields {
            let value = self.message.get(&field.name).ok_or_else(|| {
                BlockchainError::InvalidTypedData(format!("Missing field: {}", field.name))
            })?;
            out.push(encode_value(&field.field_type, value)?);
        }
        Ok(out)
    }
}

/// Encode a value based on its type.
///
/// Used only for field-value validation in tests now that SNIP-12 hashing is
/// fail-closed (see [`TypedData::compute_hash`]).
#[cfg(test)]
fn encode_value(field_type: &str, value: &serde_json::Value) -> Result<Felt> {
    match field_type {
        "felt" | "felt252" => {
            let s = value.as_str().ok_or_else(|| {
                BlockchainError::InvalidTypedData("Expected string for felt".into())
            })?;

            if s.starts_with("0x") {
                Felt::from_hex(s)
                    .map_err(|e| BlockchainError::InvalidTypedData(format!("Invalid hex: {}", e)))
            } else {
                s.parse::<u128>().map(Felt::from).map_err(|e| {
                    BlockchainError::InvalidTypedData(format!("Invalid number: {}", e))
                })
            }
        }
        "ContractAddress" | "address" => {
            let s = value.as_str().ok_or_else(|| {
                BlockchainError::InvalidTypedData("Expected string for address".into())
            })?;
            Felt::from_hex(s)
                .map_err(|e| BlockchainError::InvalidTypedData(format!("Invalid address: {}", e)))
        }
        "u128" | "u64" | "u32" | "u16" | "u8" => {
            if let Some(n) = value.as_u64() {
                Ok(Felt::from(n))
            } else if let Some(s) = value.as_str() {
                s.parse::<u128>().map(Felt::from).map_err(|e| {
                    BlockchainError::InvalidTypedData(format!("Invalid number: {}", e))
                })
            } else {
                Err(BlockchainError::InvalidTypedData("Expected number".into()))
            }
        }
        "bool" => {
            let b = value
                .as_bool()
                .ok_or_else(|| BlockchainError::InvalidTypedData("Expected boolean".into()))?;
            Ok(Felt::from(b as u64))
        }
        "shortstring" | "string" => {
            let s = value
                .as_str()
                .ok_or_else(|| BlockchainError::InvalidTypedData("Expected string".into()))?;
            felt_from_short_string(s)
        }
        _ => Err(BlockchainError::InvalidTypedData(format!(
            "Unsupported type: {}",
            field_type
        ))),
    }
}

/// Convert a short string to a felt.
///
/// StarkNet short strings must be at most 31 bytes. Returns an error
/// if the input exceeds this limit. Test-only since SNIP-12 hashing is
/// fail-closed (see [`TypedData::compute_hash`]).
#[cfg(test)]
fn felt_from_short_string(s: &str) -> Result<Felt> {
    let bytes = s.as_bytes();
    if bytes.len() > 31 {
        return Err(BlockchainError::InvalidTypedData(format!(
            "Short string exceeds 31-byte limit: {} bytes",
            bytes.len()
        )));
    }

    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(Felt::from_bytes_be_slice(&padded))
}

/// Compute Pedersen hash of a message (legacy format).
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    // For arbitrary length messages, we chunk and hash iteratively
    let mut current = Felt::ZERO;

    for chunk in message.chunks(31) {
        let mut padded = [0u8; 32];
        padded[32 - chunk.len()..].copy_from_slice(chunk);
        let chunk_felt = Felt::from_bytes_be_slice(&padded);
        current = pedersen_hash(&current, &chunk_felt);
    }

    // Include message length
    let len_felt = Felt::from(message.len());
    let final_hash = pedersen_hash(&current, &len_felt);

    final_hash.to_bytes_be()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::starknet::{StarkPrivateKey, StarknetAddress};

    #[test]
    fn test_signature_roundtrip() {
        let r = [0xab; 32];
        let s = [0xcd; 32];

        let sig = StarkSignature::new(r, s);
        let bytes = sig.to_bytes();
        let parsed = StarkSignature::from_bytes(&bytes).unwrap();

        assert_eq!(sig, parsed);
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let r = [0x12; 32];
        let s = [0x34; 32];

        let sig = StarkSignature::new(r, s);
        let (r_hex, s_hex) = sig.to_hex();
        let parsed = StarkSignature::from_hex(&r_hex, &s_hex).unwrap();

        assert_eq!(sig, parsed);
    }

    #[test]
    fn test_typed_data_hash() {
        let mut types = HashMap::new();
        types.insert(
            "Transfer".to_string(),
            vec![
                TypedDataField {
                    name: "to".to_string(),
                    field_type: "ContractAddress".to_string(),
                },
                TypedDataField {
                    name: "amount".to_string(),
                    field_type: "u128".to_string(),
                },
            ],
        );

        let domain = StarknetDomain {
            name: "TestApp".to_string(),
            version: "1".to_string(),
            chain_id: "SN_SEPOLIA".to_string(),
            revision: "1".to_string(),
        };

        let mut message = HashMap::new();
        message.insert(
            "to".to_string(),
            serde_json::json!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
        );
        message.insert("amount".to_string(), serde_json::json!(1000));

        let typed_data = TypedData::new(types, "Transfer".to_string(), domain, message);

        let private_key = StarkPrivateKey::generate();
        let public_key = private_key.public_key();
        let address = StarknetAddress::from_public_key(&public_key);

        // SNIP-12 typed-data hashing is fail-closed (GATE, HIGH #8): the
        // previous Pedersen-without-type-hashes implementation was not
        // interoperable, so we refuse to emit a hash rather than produce a
        // wrong-but-plausible one.
        assert!(matches!(
            typed_data.compute_hash(&address),
            Err(BlockchainError::UnsupportedOperation(_))
        ));

        // Field values still parse/encode (validation helper), proving the
        // refusal is about the hashing scheme, not malformed input.
        let fields = typed_data.encode_primary_fields().unwrap();
        assert_eq!(fields.len(), 2);
    }

    #[test]
    fn test_hash_message() {
        let message = b"Hello, StarkNet!";
        let hash1 = hash_message(message);
        let hash2 = hash_message(message);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_different_messages_different_hashes() {
        let hash1 = hash_message(b"message one");
        let hash2 = hash_message(b"message two");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_sign_typed_data() {
        let mut types = HashMap::new();
        types.insert(
            "Message".to_string(),
            vec![TypedDataField {
                name: "content".to_string(),
                field_type: "shortstring".to_string(),
            }],
        );

        let domain = StarknetDomain {
            name: "TestDApp".to_string(),
            version: "1".to_string(),
            chain_id: "SN_MAIN".to_string(),
            revision: "1".to_string(),
        };

        let mut message = HashMap::new();
        message.insert("content".to_string(), serde_json::json!("Hello"));

        let typed_data = TypedData::new(types, "Message".to_string(), domain, message);

        let private_key = StarkPrivateKey::generate();
        let public_key = private_key.public_key();
        let address = StarknetAddress::from_public_key(&public_key);

        // Typed-data hashing is fail-closed.
        assert!(typed_data.compute_hash(&address).is_err());

        // The signing primitive itself remains correct: signing a raw,
        // already-computed digest round-trips (sign -> verify), and a forged
        // digest is rejected (negative test).
        let digest = [0x37u8; 32];
        let signature = private_key.sign_deterministic(&digest).unwrap();
        assert!(public_key.verify(&digest, &signature));

        let forged = [0x38u8; 32];
        assert!(!public_key.verify(&forged, &signature));
    }
}
