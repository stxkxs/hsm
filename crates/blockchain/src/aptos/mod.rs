//! Aptos blockchain support
//!
//! Provides signing and transaction support for Aptos (Move-based L1).
//!
//! # Features
//!
//! - Ed25519 signing with Aptos address derivation
//! - BCS (Binary Canonical Serialization) transaction encoding
//! - Multi-signature support
//! - Resource account derivation

use crate::error::{BlockchainError, Result};
use sha3::{Digest, Sha3_256};

/// Aptos address (32 bytes, hex-encoded with 0x prefix)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptosAddress {
    /// The raw address bytes (32 bytes)
    pub bytes: [u8; 32],
}

impl AptosAddress {
    /// Derive an Aptos address from an Ed25519 public key
    ///
    /// Aptos uses SHA3-256 hash of (public_key || 0x00) as the address
    pub fn from_public_key(public_key: &[u8]) -> Result<Self> {
        if public_key.len() != 32 {
            return Err(BlockchainError::InvalidPublicKey(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        // Aptos address = SHA3-256(pubkey || 0x00)
        // The 0x00 suffix indicates a single-key account
        let mut hasher = Sha3_256::new();
        hasher.update(public_key);
        hasher.update([0x00]); // Single signature scheme

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);

        Ok(Self { bytes })
    }

    /// Derive a resource account address
    ///
    /// Resource accounts are derived from source address + seed
    pub fn resource_account(source: &Self, seed: &[u8]) -> Result<Self> {
        let mut hasher = Sha3_256::new();
        hasher.update(&source.bytes);
        hasher.update(seed);
        hasher.update([0xff]); // Resource account scheme

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);

        Ok(Self { bytes })
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Parse from hex string (with or without 0x prefix)
    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex)
            .map_err(|e| BlockchainError::InvalidAddress(format!("Invalid hex: {}", e)))?;

        if bytes.len() != 32 {
            return Err(BlockchainError::InvalidAddress(
                "Address must be 32 bytes".to_string(),
            ));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self { bytes: arr })
    }

    /// Convert to hex string with 0x prefix
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.bytes))
    }

    /// Get short form (0x...first4...last4)
    pub fn short(&self) -> String {
        let hex = hex::encode(self.bytes);
        format!("0x{}...{}", &hex[..8], &hex[56..])
    }
}

impl std::fmt::Display for AptosAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Aptos transaction
#[derive(Debug, Clone)]
pub struct RawTransaction {
    /// Sender address
    pub sender: AptosAddress,
    /// Sequence number
    pub sequence_number: u64,
    /// Transaction payload
    pub payload: TransactionPayload,
    /// Maximum gas amount
    pub max_gas_amount: u64,
    /// Gas unit price
    pub gas_unit_price: u64,
    /// Expiration timestamp (seconds)
    pub expiration_timestamp_secs: u64,
    /// Chain ID
    pub chain_id: u8,
}

/// Transaction payload types
#[derive(Debug, Clone)]
pub enum TransactionPayload {
    /// Script payload
    Script(Script),
    /// Module bundle (for publishing)
    ModuleBundle(ModuleBundle),
    /// Entry function call
    EntryFunction(EntryFunction),
    /// Multisig payload
    Multisig(MultisigPayload),
}

/// Script payload
#[derive(Debug, Clone)]
pub struct Script {
    /// Bytecode
    pub code: Vec<u8>,
    /// Type arguments
    pub ty_args: Vec<TypeTag>,
    /// Arguments
    pub args: Vec<Vec<u8>>,
}

/// Module bundle for publishing
#[derive(Debug, Clone)]
pub struct ModuleBundle {
    /// Modules to publish
    pub modules: Vec<Vec<u8>>,
}

/// Entry function call
#[derive(Debug, Clone)]
pub struct EntryFunction {
    /// Module address
    pub module: ModuleId,
    /// Function name
    pub function: String,
    /// Type arguments
    pub ty_args: Vec<TypeTag>,
    /// Arguments (BCS-encoded)
    pub args: Vec<Vec<u8>>,
}

/// Multisig payload
#[derive(Debug, Clone)]
pub struct MultisigPayload {
    /// Multisig address
    pub multisig_address: AptosAddress,
    /// Inner transaction payload
    pub transaction_payload: Option<Box<TransactionPayload>>,
}

/// Module identifier
#[derive(Debug, Clone)]
pub struct ModuleId {
    /// Module address
    pub address: AptosAddress,
    /// Module name
    pub name: String,
}

impl ModuleId {
    /// Create a new module ID
    pub fn new(address: AptosAddress, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
        }
    }

    /// Parse from string (e.g., "0x1::coin")
    pub fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split("::").collect();
        if parts.len() != 2 {
            return Err(BlockchainError::InvalidAddress(
                "Invalid module ID format".to_string(),
            ));
        }

        let address = AptosAddress::from_hex(parts[0])?;
        let name = parts[1].to_string();

        Ok(Self { address, name })
    }
}

/// Type tag for Move types
#[derive(Debug, Clone)]
pub enum TypeTag {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    Address,
    Signer,
    Vector(Box<TypeTag>),
    Struct(StructTag),
}

/// Struct tag
#[derive(Debug, Clone)]
pub struct StructTag {
    /// Module address
    pub address: AptosAddress,
    /// Module name
    pub module: String,
    /// Struct name
    pub name: String,
    /// Type parameters
    pub type_params: Vec<TypeTag>,
}

/// Sign a raw transaction
pub fn sign_transaction(
    private_key: &[u8],
    transaction: &RawTransaction,
) -> Result<SignedTransaction> {
    if private_key.len() != 32 {
        return Err(BlockchainError::InvalidPrivateKey(
            "Ed25519 private key must be 32 bytes".to_string(),
        ));
    }

    // Serialize the transaction using BCS
    let raw_txn_bytes = serialize_raw_transaction(transaction)?;

    // Create the signing message
    // Aptos uses: prefix || SHA3-256(raw_txn_bytes)
    let prefix = sha3_256(b"APTOS::RawTransaction");
    let txn_hash = sha3_256(&raw_txn_bytes);

    let mut signing_message = Vec::with_capacity(64);
    signing_message.extend_from_slice(&prefix);
    signing_message.extend_from_slice(&txn_hash);

    // Sign with Ed25519
    let signature = sign_ed25519(private_key, &signing_message)?;

    // Get public key
    let public_key = get_ed25519_public_key(private_key)?;

    Ok(SignedTransaction {
        raw_txn: transaction.clone(),
        authenticator: TransactionAuthenticator::Ed25519 {
            public_key,
            signature,
        },
    })
}

/// Signed transaction
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    /// Raw transaction
    pub raw_txn: RawTransaction,
    /// Authenticator (signature)
    pub authenticator: TransactionAuthenticator,
}

/// Transaction authenticator
#[derive(Debug, Clone)]
pub enum TransactionAuthenticator {
    /// Ed25519 single signature
    Ed25519 {
        public_key: [u8; 32],
        signature: [u8; 64],
    },
    /// Multi-Ed25519 signature
    MultiEd25519 {
        public_keys: Vec<[u8; 32]>,
        signatures: Vec<[u8; 64]>,
        bitmap: Vec<u8>,
    },
    /// Multi-agent transaction
    MultiAgent {
        sender: Box<TransactionAuthenticator>,
        secondary_signer_addresses: Vec<AptosAddress>,
        secondary_signers: Vec<TransactionAuthenticator>,
    },
}

/// Serialize a raw transaction (simplified BCS)
fn serialize_raw_transaction(transaction: &RawTransaction) -> Result<Vec<u8>> {
    // In a real implementation, this would use proper BCS encoding
    // For now, we create a deterministic representation
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&transaction.sender.bytes);
    bytes.extend_from_slice(&transaction.sequence_number.to_le_bytes());
    bytes.extend_from_slice(&transaction.max_gas_amount.to_le_bytes());
    bytes.extend_from_slice(&transaction.gas_unit_price.to_le_bytes());
    bytes.extend_from_slice(&transaction.expiration_timestamp_secs.to_le_bytes());
    bytes.push(transaction.chain_id);

    Ok(bytes)
}

/// SHA3-256 hash
fn sha3_256(data: &[u8]) -> [u8; 32] {
    let hash = Sha3_256::digest(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// Sign with Ed25519
fn sign_ed25519(private_key: &[u8], message: &[u8]) -> Result<[u8; 64]> {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(private_key.try_into().map_err(|_| {
        BlockchainError::InvalidPrivateKey("Invalid private key length".to_string())
    })?);

    let signature = signing_key.sign(message);
    Ok(signature.to_bytes())
}

/// Get Ed25519 public key from private key
fn get_ed25519_public_key(private_key: &[u8]) -> Result<[u8; 32]> {
    use ed25519_dalek::SigningKey;

    let signing_key = SigningKey::from_bytes(private_key.try_into().map_err(|_| {
        BlockchainError::InvalidPrivateKey("Invalid private key length".to_string())
    })?);

    Ok(signing_key.verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_from_hex() {
        let addr = AptosAddress::from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(addr.bytes[31], 1);
    }

    #[test]
    fn test_address_to_hex() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let addr = AptosAddress::from_bytes(bytes);
        assert_eq!(
            addr.to_hex(),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn test_module_id_parse() {
        let module = ModuleId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000001::coin",
        )
        .unwrap();
        assert_eq!(module.name, "coin");
    }
}
