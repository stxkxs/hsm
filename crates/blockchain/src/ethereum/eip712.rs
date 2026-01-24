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
    fn encode_int(value: &Value, type_str: &str) -> Result<Vec<u8>> {
        let is_signed = type_str.starts_with("int");
        let bits: u32 = if is_signed {
            type_str[3..].parse().unwrap_or(256)
        } else {
            type_str[4..].parse().unwrap_or(256)
        };

        let mut padded = [0u8; 32];

        match value {
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    if is_signed && i < 0 {
                        // Two's complement for negative numbers
                        let abs = (-i) as u64;
                        let bytes = abs.to_be_bytes();
                        for i in 0..32 {
                            padded[i] = 0xff;
                        }
                        let start = 32 - 8;
                        for (i, &b) in bytes.iter().enumerate() {
                            padded[start + i] = !b;
                        }
                        // Add 1 for two's complement
                        let mut carry = true;
                        for i in (0..32).rev() {
                            if carry {
                                let (new_val, overflow) = padded[i].overflowing_add(1);
                                padded[i] = new_val;
                                carry = overflow;
                            }
                        }
                    } else {
                        let bytes = (i as u64).to_be_bytes();
                        padded[24..].copy_from_slice(&bytes);
                    }
                } else if let Some(u) = n.as_u64() {
                    let bytes = u.to_be_bytes();
                    padded[24..].copy_from_slice(&bytes);
                }
            }
            Value::String(s) => {
                // Handle hex string or decimal string
                let s = s.strip_prefix("0x").unwrap_or(s);
                if let Ok(bytes) = hex::decode(s) {
                    let start = 32 - bytes.len().min(32);
                    padded[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
                } else if let Ok(n) = s.parse::<u64>() {
                    let bytes = n.to_be_bytes();
                    padded[24..].copy_from_slice(&bytes);
                }
            }
            _ => {}
        }

        // Mask to correct bit width
        if bits < 256 {
            let byte_width = (bits as usize + 7) / 8;
            let start = 32 - byte_width;
            for i in 0..start {
                if is_signed && padded[start] & 0x80 != 0 {
                    // Keep sign extension for negative numbers
                } else {
                    padded[i] = 0;
                }
            }
        }

        Ok(padded.to_vec())
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
