//! EIP-712: Typed structured data signing
//!
//! Implements the EIP-712 standard for signing typed data with domain separation.
//!
//! # Example
//!
//! ```rust
//! use hsm_blockchain::ethereum::eip712::{Eip712Domain, Eip712TypedData, TypedDataHasher};
//! use serde_json::json;
//!
//! let domain = Eip712Domain::new("MyApp")
//!     .with_version("1")
//!     .with_chain_id(1);
//!
//! let types = json!({
//!     "Person": [
//!         {"name": "name", "type": "string"},
//!         {"name": "wallet", "type": "address"}
//!     ]
//! });
//!
//! let message = json!({
//!     "name": "Bob",
//!     "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
//! });
//!
//! let typed_data = Eip712TypedData::new(domain, "Person", types, message);
//! ```

use crate::error::{BlockchainError, Result};
use alloy_primitives::U256;
use k256::ecdsa::{
    signature::hazmat::PrehashVerifier, RecoveryId, Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

/// EIP-712 domain separator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip712Domain {
    /// Application name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Protocol version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Chain ID
    #[serde(rename = "chainId", skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    /// Verifying contract address
    #[serde(rename = "verifyingContract", skip_serializing_if = "Option::is_none")]
    pub verifying_contract: Option<String>,
    /// Salt for domain separation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<[u8; 32]>,
}

impl Eip712Domain {
    /// Create a new domain with name
    pub fn new(name: &str) -> Self {
        Self {
            name: Some(name.to_string()),
            version: None,
            chain_id: None,
            verifying_contract: None,
            salt: None,
        }
    }

    /// Add version
    pub fn with_version(mut self, version: &str) -> Self {
        self.version = Some(version.to_string());
        self
    }

    /// Add chain ID
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Add verifying contract
    pub fn with_verifying_contract(mut self, address: &str) -> Self {
        self.verifying_contract = Some(address.to_string());
        self
    }

    /// Add salt
    pub fn with_salt(mut self, salt: [u8; 32]) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Get the type hash for EIP712Domain
    pub fn type_hash(&self) -> [u8; 32] {
        let mut type_str = String::from("EIP712Domain(");
        let mut parts = Vec::new();

        if self.name.is_some() {
            parts.push("string name");
        }
        if self.version.is_some() {
            parts.push("string version");
        }
        if self.chain_id.is_some() {
            parts.push("uint256 chainId");
        }
        if self.verifying_contract.is_some() {
            parts.push("address verifyingContract");
        }
        if self.salt.is_some() {
            parts.push("bytes32 salt");
        }

        type_str.push_str(&parts.join(","));
        type_str.push(')');

        Keccak256::digest(type_str.as_bytes()).into()
    }

    /// Hash the domain separator
    pub fn hash(&self) -> [u8; 32] {
        let mut encoder = Vec::new();

        // Type hash
        encoder.extend_from_slice(&self.type_hash());

        // Encode each field
        if let Some(ref name) = self.name {
            let name_hash = Keccak256::digest(name.as_bytes());
            encoder.extend_from_slice(&name_hash);
        }
        if let Some(ref version) = self.version {
            let version_hash = Keccak256::digest(version.as_bytes());
            encoder.extend_from_slice(&version_hash);
        }
        if let Some(chain_id) = self.chain_id {
            let mut chain_bytes = [0u8; 32];
            chain_bytes[24..].copy_from_slice(&chain_id.to_be_bytes());
            encoder.extend_from_slice(&chain_bytes);
        }
        if let Some(ref contract) = self.verifying_contract {
            let addr = contract.strip_prefix("0x").unwrap_or(contract);
            let addr_bytes = hex::decode(addr).unwrap_or_default();
            let mut padded = [0u8; 32];
            if addr_bytes.len() == 20 {
                padded[12..].copy_from_slice(&addr_bytes);
            }
            encoder.extend_from_slice(&padded);
        }
        if let Some(salt) = self.salt {
            encoder.extend_from_slice(&salt);
        }

        Keccak256::digest(&encoder).into()
    }
}

/// Type field definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeField {
    /// Field name
    pub name: String,
    /// Field type (e.g., "string", "uint256", "address", "bytes32", or custom type)
    #[serde(rename = "type")]
    pub field_type: String,
}

/// EIP-712 typed data
#[derive(Debug, Clone)]
pub struct Eip712TypedData {
    /// Domain separator
    pub domain: Eip712Domain,
    /// Primary type name
    pub primary_type: String,
    /// Type definitions
    pub types: HashMap<String, Vec<TypeField>>,
    /// Message data
    pub message: Value,
}

impl Eip712TypedData {
    /// Create new typed data
    pub fn new(
        domain: Eip712Domain,
        primary_type: &str,
        types: Value,
        message: Value,
    ) -> Result<Self> {
        let types_map = Self::parse_types(&types)?;

        Ok(Self {
            domain,
            primary_type: primary_type.to_string(),
            types: types_map,
            message,
        })
    }

    /// Parse types from JSON value
    fn parse_types(types: &Value) -> Result<HashMap<String, Vec<TypeField>>> {
        let obj = types.as_object().ok_or_else(|| {
            BlockchainError::InvalidTypedData("Types must be an object".to_string())
        })?;

        let mut result = HashMap::new();

        for (type_name, fields) in obj {
            let fields_arr = fields.as_array().ok_or_else(|| {
                BlockchainError::InvalidTypedData(format!(
                    "Type {} fields must be an array",
                    type_name
                ))
            })?;

            let mut parsed_fields = Vec::new();
            for field in fields_arr {
                let field_obj = field.as_object().ok_or_else(|| {
                    BlockchainError::InvalidTypedData("Field must be an object".to_string())
                })?;

                let name = field_obj
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        BlockchainError::InvalidTypedData("Field must have name".to_string())
                    })?;

                let field_type =
                    field_obj
                        .get("type")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            BlockchainError::InvalidTypedData("Field must have type".to_string())
                        })?;

                parsed_fields.push(TypeField {
                    name: name.to_string(),
                    field_type: field_type.to_string(),
                });
            }

            result.insert(type_name.clone(), parsed_fields);
        }

        Ok(result)
    }

    /// Get the type hash for a type
    pub fn type_hash(&self, type_name: &str) -> Result<[u8; 32]> {
        let type_str = self.encode_type(type_name)?;
        Ok(Keccak256::digest(type_str.as_bytes()).into())
    }

    /// Encode type string (including dependencies)
    fn encode_type(&self, type_name: &str) -> Result<String> {
        let fields = self.types.get(type_name).ok_or_else(|| {
            BlockchainError::InvalidTypedData(format!("Unknown type: {}", type_name))
        })?;

        // Find dependencies
        let mut deps: Vec<&str> = Vec::new();
        self.find_dependencies(type_name, &mut deps);
        deps.sort();
        deps.dedup();

        // Build type string
        let mut result = format!("{}(", type_name);
        let field_strs: Vec<String> = fields
            .iter()
            .map(|f| format!("{} {}", f.field_type, f.name))
            .collect();
        result.push_str(&field_strs.join(","));
        result.push(')');

        // Append dependencies
        for dep in deps {
            if dep != type_name {
                if let Some(dep_fields) = self.types.get(dep) {
                    result.push_str(&format!("{}(", dep));
                    let dep_field_strs: Vec<String> = dep_fields
                        .iter()
                        .map(|f| format!("{} {}", f.field_type, f.name))
                        .collect();
                    result.push_str(&dep_field_strs.join(","));
                    result.push(')');
                }
            }
        }

        Ok(result)
    }

    /// Find type dependencies
    fn find_dependencies<'a>(&'a self, type_name: &str, deps: &mut Vec<&'a str>) {
        if let Some(fields) = self.types.get(type_name) {
            for field in fields {
                let base_type = field.field_type.trim_end_matches("[]");
                if self.types.contains_key(base_type) && !deps.contains(&base_type) {
                    deps.push(base_type);
                    self.find_dependencies(base_type, deps);
                }
            }
        }
    }
}

/// Typed data hasher for EIP-712
pub struct TypedDataHasher;

impl TypedDataHasher {
    /// Hash typed data according to EIP-712
    pub fn hash(typed_data: &Eip712TypedData) -> Result<[u8; 32]> {
        let domain_separator = typed_data.domain.hash();
        let struct_hash =
            Self::hash_struct(typed_data, &typed_data.primary_type, &typed_data.message)?;

        let mut encoder = Vec::new();
        encoder.push(0x19);
        encoder.push(0x01);
        encoder.extend_from_slice(&domain_separator);
        encoder.extend_from_slice(&struct_hash);

        Ok(Keccak256::digest(&encoder).into())
    }

    /// Hash a struct
    pub fn hash_struct(
        typed_data: &Eip712TypedData,
        type_name: &str,
        data: &Value,
    ) -> Result<[u8; 32]> {
        let type_hash = typed_data.type_hash(type_name)?;
        let encoded = Self::encode_data(typed_data, type_name, data)?;

        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(&type_hash);
        to_hash.extend_from_slice(&encoded);

        Ok(Keccak256::digest(&to_hash).into())
    }

    /// Encode data according to type
    fn encode_data(typed_data: &Eip712TypedData, type_name: &str, data: &Value) -> Result<Vec<u8>> {
        let fields = typed_data.types.get(type_name).ok_or_else(|| {
            BlockchainError::InvalidTypedData(format!("Unknown type: {}", type_name))
        })?;

        let obj = data.as_object().ok_or_else(|| {
            BlockchainError::InvalidTypedData("Data must be an object".to_string())
        })?;

        let mut encoded = Vec::new();

        for field in fields {
            let value = obj.get(&field.name).unwrap_or(&Value::Null);
            let encoded_value = Self::encode_value(typed_data, &field.field_type, value)?;
            encoded.extend_from_slice(&encoded_value);
        }

        Ok(encoded)
    }

    /// Encode a single value
    fn encode_value(
        typed_data: &Eip712TypedData,
        field_type: &str,
        value: &Value,
    ) -> Result<Vec<u8>> {
        // Handle arrays
        if field_type.ends_with("[]") {
            let base_type = &field_type[..field_type.len() - 2];
            let arr = value
                .as_array()
                .ok_or_else(|| BlockchainError::InvalidTypedData("Expected array".to_string()))?;

            let mut encoded = Vec::new();
            for item in arr {
                encoded.extend_from_slice(&Self::encode_value(typed_data, base_type, item)?);
            }
            return Ok(Keccak256::digest(&encoded).to_vec());
        }

        // Handle bytes and string (dynamic types)
        match field_type {
            "string" => {
                let s = value.as_str().unwrap_or("");
                Ok(Keccak256::digest(s.as_bytes()).to_vec())
            }
            "bytes" => {
                let hex_str = value.as_str().unwrap_or("0x");
                let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
                let bytes = hex::decode(hex_str)
                    .map_err(|_| BlockchainError::InvalidTypedData("Invalid bytes".to_string()))?;
                Ok(Keccak256::digest(&bytes).to_vec())
            }
            "address" => {
                let addr = value
                    .as_str()
                    .unwrap_or("0x0000000000000000000000000000000000000000");
                let addr = addr.strip_prefix("0x").unwrap_or(addr);
                let addr_bytes = hex::decode(addr).map_err(|_| {
                    BlockchainError::InvalidTypedData("Invalid address".to_string())
                })?;
                let mut padded = [0u8; 32];
                if addr_bytes.len() == 20 {
                    padded[12..].copy_from_slice(&addr_bytes);
                }
                Ok(padded.to_vec())
            }
            "bool" => {
                let b = value.as_bool().unwrap_or(false);
                let mut padded = [0u8; 32];
                if b {
                    padded[31] = 1;
                }
                Ok(padded.to_vec())
            }
            t if t.starts_with("uint") || t.starts_with("int") => Self::encode_int(value, t),
            t if t.starts_with("bytes") && t.len() > 5 => {
                // bytesN (fixed size)
                let size: usize = t[5..].parse().map_err(|_| {
                    BlockchainError::InvalidTypedData(format!("Invalid type: {}", t))
                })?;
                let hex_str = value.as_str().unwrap_or("0x");
                let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
                let bytes = hex::decode(hex_str)
                    .map_err(|_| BlockchainError::InvalidTypedData("Invalid bytes".to_string()))?;
                let mut padded = [0u8; 32];
                let len = bytes.len().min(size).min(32);
                padded[..len].copy_from_slice(&bytes[..len]);
                Ok(padded.to_vec())
            }
            // Custom type (struct)
            _ => {
                if typed_data.types.contains_key(field_type) {
                    let struct_hash = Self::hash_struct(typed_data, field_type, value)?;
                    Ok(struct_hash.to_vec())
                } else {
                    Err(BlockchainError::InvalidTypedData(format!(
                        "Unknown type: {}",
                        field_type
                    )))
                }
            }
        }
    }

    /// Encode integer value
    ///
    /// Encodes a `uintN`/`intN` ABI value into its 32-byte big-endian slot,
    /// matching the encoding produced by reference implementations (ethers/viem).
    ///
    /// Parsing rules (single 256-bit path, no silent truncation/zeroing):
    /// - JSON numbers must be exact integers; a value coerced to a float
    ///   (e.g. a literal larger than `u64::MAX` without `arbitrary_precision`)
    ///   is rejected rather than silently encoded as zero. To pass values above
    ///   `u64::MAX`, supply them as a decimal (or `0x`-prefixed hex) string, the
    ///   same convention used by ethers/viem when serializing big integers.
    /// - JSON strings are treated as hexadecimal only when they carry an explicit
    ///   `0x`/`0X` prefix; otherwise they are parsed as decimal. This prevents an
    ///   all-digit, even-length decimal wei amount from being misread as hex.
    /// - Over-width / overflowing values produce an error instead of being
    ///   masked to zero.
    fn encode_int(value: &Value, type_str: &str) -> Result<Vec<u8>> {
        let is_signed = type_str.starts_with("int");
        let bits: u32 = if is_signed {
            type_str[3..].parse().unwrap_or(256)
        } else {
            type_str[4..].parse().unwrap_or(256)
        };

        if bits == 0 || bits > 256 || !bits.is_multiple_of(8) {
            return Err(BlockchainError::InvalidTypedData(format!(
                "Invalid integer type width: {}",
                type_str
            )));
        }

        // Parse the value into a sign + magnitude pair, where the magnitude is a
        // full 256-bit unsigned integer. Decimal strings and JSON numbers are
        // both routed through alloy's U256 parser so arbitrarily large wei
        // amounts are handled correctly.
        let (negative, magnitude) = match value {
            Value::Number(n) => {
                // serde_json stores integers that fit in i64/u64 exactly; any
                // value that only round-trips as an f64 has lost precision and
                // must not be silently encoded as zero.
                if let Some(u) = n.as_u64() {
                    (false, U256::from(u))
                } else if let Some(i) = n.as_i64() {
                    let neg = i < 0;
                    (neg, U256::from(i.unsigned_abs()))
                } else {
                    return Err(BlockchainError::InvalidTypedData(format!(
                        "Integer value is not an exact integer (pass values above u64::MAX as a \
                         decimal or 0x-hex string): {}",
                        n
                    )));
                }
            }
            Value::String(s) => {
                let s = s.trim();
                let (neg, body) = match s.strip_prefix('-') {
                    Some(rest) => (true, rest.trim_start()),
                    None => (false, s),
                };

                let magnitude = if let Some(hex_body) =
                    body.strip_prefix("0x").or_else(|| body.strip_prefix("0X"))
                {
                    U256::from_str_radix(hex_body, 16).map_err(|_| {
                        BlockchainError::InvalidTypedData(format!(
                            "Invalid hexadecimal integer: {}",
                            s
                        ))
                    })?
                } else {
                    // No 0x prefix => decimal (never reinterpret as hex).
                    U256::from_str_radix(body, 10).map_err(|_| {
                        BlockchainError::InvalidTypedData(format!("Invalid decimal integer: {}", s))
                    })?
                };
                (neg, magnitude)
            }
            Value::Bool(_) | Value::Null | Value::Array(_) | Value::Object(_) => {
                return Err(BlockchainError::InvalidTypedData(format!(
                    "Expected integer for type {}",
                    type_str
                )));
            }
        };

        if negative && !is_signed {
            return Err(BlockchainError::InvalidTypedData(format!(
                "Negative value supplied for unsigned type {}",
                type_str
            )));
        }

        // Range-check the magnitude against the declared bit width, then build
        // the final 256-bit (two's complement for negatives) value.
        let encoded: U256 = if negative {
            // Signed range is [-2^(bits-1), 2^(bits-1)-1]; magnitude <= 2^(bits-1).
            let limit = U256::from(1u8) << (bits - 1);
            if magnitude > limit {
                return Err(BlockchainError::InvalidTypedData(format!(
                    "Value out of range for {}",
                    type_str
                )));
            }
            U256::ZERO.wrapping_sub(magnitude)
        } else {
            let max_unsigned = if is_signed {
                // Positive signed value: [0, 2^(bits-1)-1].
                (U256::from(1u8) << (bits - 1)) - U256::from(1u8)
            } else if bits == 256 {
                U256::MAX
            } else {
                (U256::from(1u8) << bits) - U256::from(1u8)
            };
            if magnitude > max_unsigned {
                return Err(BlockchainError::InvalidTypedData(format!(
                    "Value out of range for {}",
                    type_str
                )));
            }
            magnitude
        };

        Ok(encoded.to_be_bytes::<32>().to_vec())
    }

    /// Sign typed data
    pub fn sign(typed_data: &Eip712TypedData, signing_key: &SigningKey) -> Result<Eip712Signature> {
        let hash = Self::hash(typed_data)?;

        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| BlockchainError::CryptoError(e.to_string()))?;

        Ok(Eip712Signature {
            hash,
            signature,
            recovery_id,
        })
    }

    /// Verify typed data signature
    pub fn verify(
        typed_data: &Eip712TypedData,
        signature: &Signature,
        public_key: &VerifyingKey,
    ) -> Result<bool> {
        let hash = Self::hash(typed_data)?;
        Ok(public_key.verify_prehash(&hash, signature).is_ok())
    }

    /// Recover public key from signature
    pub fn recover_public_key(
        _typed_data: &Eip712TypedData,
        sig: &Eip712Signature,
    ) -> Result<VerifyingKey> {
        VerifyingKey::recover_from_prehash(&sig.hash, &sig.signature, sig.recovery_id)
            .map_err(|e| BlockchainError::CryptoError(e.to_string()))
    }
}

/// EIP-712 signature
#[derive(Debug, Clone)]
pub struct Eip712Signature {
    /// Message hash
    pub hash: [u8; 32],
    /// Signature
    pub signature: Signature,
    /// Recovery ID
    pub recovery_id: RecoveryId,
}

impl Eip712Signature {
    /// Get r component
    pub fn r(&self) -> [u8; 32] {
        let bytes = self.signature.to_bytes();
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        r
    }

    /// Get s component
    pub fn s(&self) -> [u8; 32] {
        let bytes = self.signature.to_bytes();
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[32..]);
        s
    }

    /// Get v component
    pub fn v(&self) -> u8 {
        27 + self.recovery_id.to_byte()
    }

    /// Convert to bytes (r || s || v)
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        let sig_bytes = self.signature.to_bytes();
        bytes[..64].copy_from_slice(&sig_bytes);
        bytes[64] = self.v();
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::SecretKey;
    use serde_json::json;

    fn generate_key() -> SigningKey {
        let secret = SecretKey::random(&mut rand::thread_rng());
        SigningKey::from(secret)
    }

    #[test]
    fn test_domain_hash() {
        let domain = Eip712Domain::new("Test App")
            .with_version("1")
            .with_chain_id(1);

        let hash = domain.hash();
        assert_eq!(hash.len(), 32);

        // Hash should be deterministic
        let hash2 = domain.hash();
        assert_eq!(hash, hash2);
    }

    /// EIP-712 known-answer test against the canonical "Mail" example from the
    /// EIP-712 specification (<https://eips.ethereum.org/EIPS/eip-712>).
    ///
    /// Both expected hashes are the spec's published constants, independently
    /// recomputed with a real keccak-256 oracle — so a wrong-but-deterministic
    /// domain separator or struct encoding fails here rather than passing a
    /// len()==32 shape check.
    #[test]
    fn test_eip712_mail_known_answer() {
        let domain = Eip712Domain::new("Ether Mail")
            .with_version("1")
            .with_chain_id(1)
            .with_verifying_contract("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC");

        // Canonical domain separator for this domain.
        assert_eq!(
            hex::encode(domain.hash()),
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f",
            "EIP-712 Mail domain separator mismatch"
        );

        let types = json!({
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"}
            ],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"}
            ]
        });
        let message = json!({
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!"
        });

        let typed_data = Eip712TypedData::new(domain, "Mail", types, message).unwrap();
        let hash = TypedDataHasher::hash(&typed_data).unwrap();

        // Canonical EIP-712 signing hash: keccak256(0x1901 || domainSep || hashStruct(message)).
        assert_eq!(
            hex::encode(hash),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2",
            "EIP-712 Mail signing hash mismatch"
        );
    }

    #[test]
    fn test_typed_data_creation() {
        let domain = Eip712Domain::new("Test").with_chain_id(1);

        let types = json!({
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"}
            ]
        });

        let message = json!({
            "name": "Bob",
            "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
        });

        let typed_data = Eip712TypedData::new(domain, "Person", types, message).unwrap();
        assert_eq!(typed_data.primary_type, "Person");
        assert!(typed_data.types.contains_key("Person"));
    }

    #[test]
    fn test_type_hash() {
        let domain = Eip712Domain::new("Test").with_chain_id(1);

        let types = json!({
            "Mail": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "contents", "type": "string"}
            ]
        });

        let message = json!({
            "from": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
            "to": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
            "contents": "Hello!"
        });

        let typed_data = Eip712TypedData::new(domain, "Mail", types, message).unwrap();
        let type_hash = typed_data.type_hash("Mail").unwrap();

        // Should be deterministic
        assert_eq!(type_hash.len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let signing_key = generate_key();
        let verifying_key = signing_key.verifying_key();

        let domain = Eip712Domain::new("Test").with_chain_id(1);

        let types = json!({
            "Message": [
                {"name": "content", "type": "string"}
            ]
        });

        let message = json!({
            "content": "Hello, EIP-712!"
        });

        let typed_data = Eip712TypedData::new(domain, "Message", types, message).unwrap();

        // Sign
        let sig = TypedDataHasher::sign(&typed_data, &signing_key).unwrap();

        // Verify
        assert!(TypedDataHasher::verify(&typed_data, &sig.signature, verifying_key).unwrap());
    }

    #[test]
    fn test_recover_public_key() {
        let signing_key = generate_key();
        let expected_verifying_key = signing_key.verifying_key();

        let domain = Eip712Domain::new("Test").with_chain_id(1);

        let types = json!({
            "Message": [
                {"name": "id", "type": "uint256"}
            ]
        });

        let message = json!({
            "id": 12345
        });

        let typed_data = Eip712TypedData::new(domain, "Message", types, message).unwrap();
        let sig = TypedDataHasher::sign(&typed_data, &signing_key).unwrap();

        let recovered = TypedDataHasher::recover_public_key(&typed_data, &sig).unwrap();
        assert_eq!(recovered, *expected_verifying_key);
    }

    /// Helper: encode a single uint/int value through the full EIP-712 value
    /// encoder and return the 32-byte slot as hex (no 0x prefix).
    fn encode_int_hex(field_type: &str, value: Value) -> String {
        // encode_int does not depend on the typed_data context, so a minimal
        // typed_data is sufficient to exercise the encoder.
        let domain = Eip712Domain::new("T");
        let typed_data = Eip712TypedData::new(domain, "X", json!({ "X": [] }), json!({})).unwrap();
        let bytes = TypedDataHasher::encode_value(&typed_data, field_type, &value).unwrap();
        hex::encode(bytes)
    }

    #[test]
    fn test_encode_int_kat_large_decimal_string() {
        // 100 * 10^18 wei. Reference big-endian bytes cross-checked against
        // ethers/viem ABI encoding of uint256(100000000000000000000).
        // Previously this silently encoded as 32 zero bytes (HIGH #8).
        let encoded = encode_int_hex("uint256", json!("100000000000000000000"));
        assert_eq!(
            encoded,
            "0000000000000000000000000000000000000000000000056bc75e2d63100000"
        );
        // It must NOT be all zeros.
        assert_ne!(
            encoded,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_encode_int_kat_even_length_decimal_not_hex() {
        // "10" is an even-length, all-digit string. It must be parsed as decimal
        // (value 10 => ...0a), NOT as hexadecimal (0x10 => ...10) (HIGH #7).
        let decimal = encode_int_hex("uint256", json!("10"));
        assert_eq!(
            decimal,
            "000000000000000000000000000000000000000000000000000000000000000a"
        );
        // Explicit 0x prefix is the only way to request hex.
        let hexed = encode_int_hex("uint256", json!("0x10"));
        assert_eq!(
            hexed,
            "0000000000000000000000000000000000000000000000000000000000000010"
        );
        assert_ne!(decimal, hexed);
    }

    #[test]
    fn test_encode_int_kat_decimal_string_round_value() {
        // 1 ether = 10^18 wei = 0xde0b6b3a7640000.
        let dec = encode_int_hex("uint256", json!("1000000000000000000"));
        let hexed = encode_int_hex("uint256", json!("0xde0b6b3a7640000"));
        assert_eq!(
            dec,
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
        );
        assert_eq!(dec, hexed);
    }

    #[test]
    fn test_encode_int_kat_small_json_number() {
        // Small bare JSON numbers still encode correctly.
        let encoded = encode_int_hex("uint256", json!(12345u64));
        assert_eq!(
            encoded,
            "0000000000000000000000000000000000000000000000000000000000003039"
        );
    }

    #[test]
    fn test_encode_int_kat_negative_signed() {
        // int256(-1) is two's complement all-ones.
        let encoded = encode_int_hex("int256", json!(-1i64));
        assert_eq!(
            encoded,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        // Negative via decimal string as well.
        let from_str = encode_int_hex("int256", json!("-42"));
        assert_eq!(
            from_str,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd6"
        );
    }

    #[test]
    fn test_encode_int_rejects_float_json_number() {
        // A fractional / float JSON number is lossy and must error, not zero.
        let domain = Eip712Domain::new("T");
        let typed_data = Eip712TypedData::new(domain, "X", json!({ "X": [] }), json!({})).unwrap();
        let result = TypedDataHasher::encode_value(&typed_data, "uint256", &json!(1.5));
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_int_rejects_negative_for_unsigned() {
        let domain = Eip712Domain::new("T");
        let typed_data = Eip712TypedData::new(domain, "X", json!({ "X": [] }), json!({})).unwrap();
        let result = TypedDataHasher::encode_value(&typed_data, "uint256", &json!("-1"));
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_int_rejects_overflow() {
        // 2^256 is one larger than the maximum uint256 and must error.
        let domain = Eip712Domain::new("T");
        let typed_data = Eip712TypedData::new(domain, "X", json!({ "X": [] }), json!({})).unwrap();
        let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        let result = TypedDataHasher::encode_value(&typed_data, "uint256", &json!(over));
        assert!(result.is_err());
        // uint8 overflow: 256 does not fit in 8 bits.
        let result8 = TypedDataHasher::encode_value(&typed_data, "uint8", &json!(256u64));
        assert!(result8.is_err());
        // uint8 = 255 is the max valid value.
        let ok = TypedDataHasher::encode_value(&typed_data, "uint8", &json!(255u64)).unwrap();
        assert_eq!(
            hex::encode(ok),
            "00000000000000000000000000000000000000000000000000000000000000ff"
        );
    }

    #[test]
    fn test_nested_types() {
        let domain = Eip712Domain::new("Test").with_chain_id(1);

        let types = json!({
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"}
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"}
            ]
        });

        let message = json!({
            "from": {
                "name": "Alice",
                "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
            },
            "to": {
                "name": "Bob",
                "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
            },
            "contents": "Hello!"
        });

        let typed_data = Eip712TypedData::new(domain, "Mail", types, message).unwrap();
        let hash = TypedDataHasher::hash(&typed_data).unwrap();

        assert_eq!(hash.len(), 32);
    }
}
