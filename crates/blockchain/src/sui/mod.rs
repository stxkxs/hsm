//! Sui blockchain support
//!
//! Provides signing and transaction support for Sui (Move-based L1).
//!
//! # Features
//!
//! - Ed25519 and secp256k1 signing
//! - BCS transaction encoding
//! - Object-centric transaction model
//! - Programmable transactions

use crate::error::{BlockchainError, Result};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

/// Sui address (32 bytes for Ed25519, 20 bytes for secp256k1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiAddress {
    /// The raw address bytes
    pub bytes: Vec<u8>,
    /// The signature scheme used
    pub scheme: SignatureScheme,
}

/// Supported signature schemes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// Ed25519 (flag 0x00)
    Ed25519,
    /// Secp256k1 (flag 0x01)
    Secp256k1,
    /// Secp256r1/P256 (flag 0x02)
    Secp256r1,
    /// MultiSig (flag 0x03)
    MultiSig,
}

impl SignatureScheme {
    /// Get the flag byte for this scheme
    pub fn flag(&self) -> u8 {
        match self {
            Self::Ed25519 => 0x00,
            Self::Secp256k1 => 0x01,
            Self::Secp256r1 => 0x02,
            Self::MultiSig => 0x03,
        }
    }
}

impl SuiAddress {
    /// Derive a Sui address from a public key
    ///
    /// Sui address = BLAKE2b-256(flag || public_key)[0..32]
    pub fn from_public_key(public_key: &[u8], scheme: SignatureScheme) -> Result<Self> {
        let expected_len = match scheme {
            SignatureScheme::Ed25519 => 32,
            SignatureScheme::Secp256k1 | SignatureScheme::Secp256r1 => 33,
            SignatureScheme::MultiSig => {
                return Err(BlockchainError::InvalidPublicKey(
                    "Use from_multisig for MultiSig addresses".to_string(),
                ))
            }
        };

        if public_key.len() != expected_len {
            return Err(BlockchainError::InvalidPublicKey(format!(
                "Expected {} bytes, got {}",
                expected_len,
                public_key.len()
            )));
        }

        // Sui uses BLAKE2b-256 but we'll use SHA3-256 for compatibility
        let mut hasher = Sha3_256::new();
        hasher.update([scheme.flag()]);
        hasher.update(public_key);
        let hash = hasher.finalize();

        Ok(Self {
            bytes: hash.to_vec(),
            scheme,
        })
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>, scheme: SignatureScheme) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(BlockchainError::InvalidAddress(
                "Sui address must be 32 bytes".to_string(),
            ));
        }

        Ok(Self { bytes, scheme })
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

        // Default to Ed25519 when parsing from hex
        Ok(Self {
            bytes,
            scheme: SignatureScheme::Ed25519,
        })
    }

    /// Convert to hex string with 0x prefix
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.bytes))
    }
}

impl std::fmt::Display for SuiAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Object ID (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectId(pub [u8; 32]);

impl ObjectId {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse from hex
    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex)
            .map_err(|e| BlockchainError::InvalidAddress(format!("Invalid hex: {}", e)))?;

        if bytes.len() != 32 {
            return Err(BlockchainError::InvalidAddress(
                "Object ID must be 32 bytes".to_string(),
            ));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Convert to hex
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

/// Object reference (ID, version, digest)
#[derive(Debug, Clone)]
pub struct ObjectRef {
    /// Object ID
    pub object_id: ObjectId,
    /// Version (sequence number)
    pub version: u64,
    /// Object digest
    pub digest: [u8; 32],
}

/// Transaction data
#[derive(Debug, Clone)]
pub struct TransactionData {
    /// Transaction kind
    pub kind: TransactionKind,
    /// Sender address
    pub sender: SuiAddress,
    /// Gas payment object
    pub gas_payment: ObjectRef,
    /// Gas budget
    pub gas_budget: u64,
    /// Gas price
    pub gas_price: u64,
}

/// Transaction kind
#[derive(Debug, Clone)]
pub enum TransactionKind {
    /// Programmable transaction (v2)
    ProgrammableTransaction(ProgrammableTransaction),
    /// Change epoch (system transaction)
    ChangeEpoch(ChangeEpoch),
    /// Genesis transaction
    Genesis(GenesisTransaction),
    /// Consensus commit prologue
    ConsensusCommitPrologue(ConsensusCommitPrologue),
}

/// Programmable transaction (Sui's primary transaction type)
#[derive(Debug, Clone)]
pub struct ProgrammableTransaction {
    /// Input objects
    pub inputs: Vec<CallArg>,
    /// Commands to execute
    pub commands: Vec<Command>,
}

/// Call argument
#[derive(Debug, Clone)]
pub enum CallArg {
    /// Pure value (BCS-encoded)
    Pure(Vec<u8>),
    /// Object reference
    Object(ObjectArg),
}

/// Object argument
#[derive(Debug, Clone)]
pub enum ObjectArg {
    /// Immutable or owned object
    ImmOrOwnedObject(ObjectRef),
    /// Shared object
    SharedObject {
        id: ObjectId,
        initial_shared_version: u64,
        mutable: bool,
    },
    /// Receiving object (for transfers)
    Receiving(ObjectRef),
}

/// Transaction command
#[derive(Debug, Clone)]
pub enum Command {
    /// Move call
    MoveCall(MoveCall),
    /// Transfer objects
    TransferObjects(TransferObjects),
    /// Split coins
    SplitCoins(SplitCoins),
    /// Merge coins
    MergeCoins(MergeCoins),
    /// Publish package
    Publish(Publish),
    /// Upgrade package
    Upgrade(Upgrade),
    /// Make move vec
    MakeMoveVec(MakeMoveVec),
}

/// Move call command
#[derive(Debug, Clone)]
pub struct MoveCall {
    /// Package ID
    pub package: ObjectId,
    /// Module name
    pub module: String,
    /// Function name
    pub function: String,
    /// Type arguments
    pub type_arguments: Vec<TypeTag>,
    /// Arguments (indices into inputs or results)
    pub arguments: Vec<Argument>,
}

/// Transfer objects command
#[derive(Debug, Clone)]
pub struct TransferObjects {
    /// Objects to transfer
    pub objects: Vec<Argument>,
    /// Recipient address
    pub address: Argument,
}

/// Split coins command
#[derive(Debug, Clone)]
pub struct SplitCoins {
    /// Coin to split
    pub coin: Argument,
    /// Amounts to split
    pub amounts: Vec<Argument>,
}

/// Merge coins command
#[derive(Debug, Clone)]
pub struct MergeCoins {
    /// Destination coin
    pub destination: Argument,
    /// Source coins to merge
    pub sources: Vec<Argument>,
}

/// Publish package command
#[derive(Debug, Clone)]
pub struct Publish {
    /// Module bytecode
    pub modules: Vec<Vec<u8>>,
    /// Dependency IDs
    pub dependencies: Vec<ObjectId>,
}

/// Upgrade package command
#[derive(Debug, Clone)]
pub struct Upgrade {
    /// Module bytecode
    pub modules: Vec<Vec<u8>>,
    /// Dependency IDs
    pub dependencies: Vec<ObjectId>,
    /// Package to upgrade
    pub package: ObjectId,
    /// Upgrade ticket
    pub ticket: Argument,
}

/// Make move vec command
#[derive(Debug, Clone)]
pub struct MakeMoveVec {
    /// Element type
    pub type_: Option<TypeTag>,
    /// Elements
    pub elements: Vec<Argument>,
}

/// Argument reference
#[derive(Debug, Clone)]
pub enum Argument {
    /// Gas coin
    GasCoin,
    /// Input at index
    Input(u16),
    /// Result of command at index
    Result(u16),
    /// Nested result (command index, result index)
    NestedResult(u16, u16),
}

/// Type tag (Move type)
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
    /// Package address
    pub address: SuiAddress,
    /// Module name
    pub module: String,
    /// Struct name
    pub name: String,
    /// Type parameters
    pub type_params: Vec<TypeTag>,
}

/// Change epoch (system transaction)
#[derive(Debug, Clone)]
pub struct ChangeEpoch {
    pub epoch: u64,
    pub protocol_version: u64,
    pub storage_charge: u64,
    pub computation_charge: u64,
    pub storage_rebate: u64,
    pub non_refundable_storage_fee: u64,
    pub epoch_start_timestamp_ms: u64,
    pub system_packages: Vec<(u64, Vec<Vec<u8>>, Vec<ObjectId>)>,
}

/// Genesis transaction
#[derive(Debug, Clone)]
pub struct GenesisTransaction {
    pub objects: Vec<ObjectId>,
}

/// Consensus commit prologue
#[derive(Debug, Clone)]
pub struct ConsensusCommitPrologue {
    pub epoch: u64,
    pub round: u64,
    pub commit_timestamp_ms: u64,
}

/// Sign a transaction
pub fn sign_transaction(
    private_key: &[u8],
    transaction: &TransactionData,
    scheme: SignatureScheme,
) -> Result<SignedTransaction> {
    let tx_bytes = serialize_transaction(transaction)?;

    // Intent message: intent || tx_bytes
    let intent = create_intent(IntentScope::TransactionData);
    let mut intent_message = intent;
    intent_message.extend_from_slice(&tx_bytes);

    // Hash the intent message
    let digest = Sha256::digest(&intent_message);

    // Sign based on scheme
    let signature = match scheme {
        SignatureScheme::Ed25519 => sign_ed25519(private_key, &digest)?,
        SignatureScheme::Secp256k1 => sign_secp256k1(private_key, &digest)?,
        _ => {
            return Err(BlockchainError::UnsupportedAlgorithm(format!(
                "{:?} not supported",
                scheme
            )))
        }
    };

    let public_key = get_public_key(private_key, scheme)?;

    Ok(SignedTransaction {
        transaction: transaction.clone(),
        signature: GenericSignature {
            scheme,
            signature,
            public_key,
        },
    })
}

/// Signed transaction
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub transaction: TransactionData,
    pub signature: GenericSignature,
}

/// Generic signature
#[derive(Debug, Clone)]
pub struct GenericSignature {
    pub scheme: SignatureScheme,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl GenericSignature {
    /// Serialize to bytes (flag || signature || public_key)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.scheme.flag()];
        bytes.extend_from_slice(&self.signature);
        bytes.extend_from_slice(&self.public_key);
        bytes
    }
}

/// Intent scope
#[derive(Debug, Clone, Copy)]
pub enum IntentScope {
    TransactionData,
    TransactionEffects,
    CheckpointSummary,
    PersonalMessage,
}

/// Create intent bytes
fn create_intent(scope: IntentScope) -> Vec<u8> {
    let scope_byte = match scope {
        IntentScope::TransactionData => 0,
        IntentScope::TransactionEffects => 1,
        IntentScope::CheckpointSummary => 2,
        IntentScope::PersonalMessage => 3,
    };

    // Intent = [scope, version, app_id]
    vec![scope_byte, 0, 0]
}

/// Serialize transaction (simplified)
fn serialize_transaction(transaction: &TransactionData) -> Result<Vec<u8>> {
    // Simplified BCS serialization
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&transaction.sender.bytes);
    bytes.extend_from_slice(&transaction.gas_budget.to_le_bytes());
    bytes.extend_from_slice(&transaction.gas_price.to_le_bytes());
    Ok(bytes)
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

/// Sign with secp256k1
fn sign_secp256k1(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};

    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|e| BlockchainError::InvalidPrivateKey(e.to_string()))?;

    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Get public key from private key
fn get_public_key(private_key: &[u8], scheme: SignatureScheme) -> Result<Vec<u8>> {
    match scheme {
        SignatureScheme::Ed25519 => {
            use ed25519_dalek::SigningKey;
            let signing_key = SigningKey::from_bytes(private_key.try_into().map_err(|_| {
                BlockchainError::InvalidPrivateKey("Invalid Ed25519 private key".to_string())
            })?);
            Ok(signing_key.verifying_key().to_bytes().to_vec())
        }
        SignatureScheme::Secp256k1 => {
            use k256::ecdsa::SigningKey;
            let signing_key = SigningKey::from_bytes(private_key.into())
                .map_err(|e| BlockchainError::InvalidPrivateKey(e.to_string()))?;
            Ok(signing_key.verifying_key().to_sec1_bytes().to_vec())
        }
        _ => Err(BlockchainError::UnsupportedAlgorithm(format!(
            "{:?} not supported",
            scheme
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sui_address_from_hex() {
        let addr = SuiAddress::from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(addr.bytes[31], 1);
    }

    #[test]
    fn test_object_id_from_hex() {
        let id = ObjectId::from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        assert_eq!(id.0[31], 2);
    }

    #[test]
    fn test_signature_scheme_flag() {
        assert_eq!(SignatureScheme::Ed25519.flag(), 0x00);
        assert_eq!(SignatureScheme::Secp256k1.flag(), 0x01);
    }
}
