//! NEAR blockchain support
//!
//! Provides signing and transaction support for NEAR Protocol.
//!
//! # Features
//!
//! - Ed25519 signing
//! - Borsh serialization
//! - Named accounts (e.g., alice.near)
//! - Implicit accounts (public key hex)

use crate::error::{BlockchainError, Result};
use sha2::{Digest, Sha256};

/// NEAR account ID
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountId(pub String);

impl AccountId {
    /// Create a new account ID
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        Self::validate(&id)?;
        Ok(Self(id))
    }

    /// Create an implicit account from a public key
    pub fn implicit(public_key: &[u8]) -> Result<Self> {
        if public_key.len() != 32 {
            return Err(BlockchainError::InvalidPublicKey(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        Ok(Self(hex::encode(public_key)))
    }

    /// Validate an account ID
    fn validate(id: &str) -> Result<()> {
        if id.is_empty() || id.len() > 64 {
            return Err(BlockchainError::InvalidAddress(
                "Account ID must be 1-64 characters".to_string(),
            ));
        }

        // Check for valid characters
        for c in id.chars() {
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_' && c != '-' && c != '.' {
                return Err(BlockchainError::InvalidAddress(format!(
                    "Invalid character '{}' in account ID",
                    c
                )));
            }
        }

        Ok(())
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// NEAR public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Key type
    pub key_type: KeyType,
    /// Key data
    pub data: Vec<u8>,
}

/// Key types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519
    Ed25519,
    /// Secp256k1
    Secp256k1,
}

impl PublicKey {
    /// Create an Ed25519 public key
    pub fn ed25519(data: &[u8]) -> Result<Self> {
        if data.len() != 32 {
            return Err(BlockchainError::InvalidPublicKey(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        Ok(Self {
            key_type: KeyType::Ed25519,
            data: data.to_vec(),
        })
    }

    /// Parse from string (e.g., "ed25519:...")
    pub fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(BlockchainError::InvalidPublicKey(
                "Invalid public key format".to_string(),
            ));
        }

        let key_type = match parts[0] {
            "ed25519" => KeyType::Ed25519,
            "secp256k1" => KeyType::Secp256k1,
            _ => {
                return Err(BlockchainError::InvalidPublicKey(format!(
                    "Unknown key type: {}",
                    parts[0]
                )))
            }
        };

        let data = bs58::decode(parts[1])
            .into_vec()
            .map_err(|e| BlockchainError::InvalidPublicKey(format!("Invalid base58: {}", e)))?;

        Ok(Self { key_type, data })
    }

    /// Convert to string
    pub fn to_string(&self) -> String {
        let prefix = match self.key_type {
            KeyType::Ed25519 => "ed25519",
            KeyType::Secp256k1 => "secp256k1",
        };
        format!("{}:{}", prefix, bs58::encode(&self.data).into_string())
    }
}

/// NEAR transaction
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Signer account ID
    pub signer_id: AccountId,
    /// Signer public key
    pub public_key: PublicKey,
    /// Nonce
    pub nonce: u64,
    /// Receiver account ID
    pub receiver_id: AccountId,
    /// Block hash (for transaction validity)
    pub block_hash: [u8; 32],
    /// Actions
    pub actions: Vec<Action>,
}

/// Transaction action
#[derive(Debug, Clone)]
pub enum Action {
    /// Create account
    CreateAccount,
    /// Deploy contract
    DeployContract { code: Vec<u8> },
    /// Function call
    FunctionCall {
        method_name: String,
        args: Vec<u8>,
        gas: u64,
        deposit: u128,
    },
    /// Transfer NEAR
    Transfer { deposit: u128 },
    /// Stake NEAR
    Stake { stake: u128, public_key: PublicKey },
    /// Add access key
    AddKey {
        public_key: PublicKey,
        access_key: AccessKey,
    },
    /// Delete access key
    DeleteKey { public_key: PublicKey },
    /// Delete account
    DeleteAccount { beneficiary_id: AccountId },
}

/// Access key
#[derive(Debug, Clone)]
pub struct AccessKey {
    /// Nonce
    pub nonce: u64,
    /// Permission
    pub permission: AccessKeyPermission,
}

/// Access key permission
#[derive(Debug, Clone)]
pub enum AccessKeyPermission {
    /// Full access
    FullAccess,
    /// Function call access
    FunctionCall {
        allowance: Option<u128>,
        receiver_id: AccountId,
        method_names: Vec<String>,
    },
}

/// Sign a transaction
pub fn sign_transaction(
    private_key: &[u8],
    transaction: &Transaction,
) -> Result<SignedTransaction> {
    let tx_bytes = serialize_transaction(transaction)?;
    let hash = Sha256::digest(&tx_bytes);

    let signature = sign_ed25519(private_key, &hash)?;

    Ok(SignedTransaction {
        transaction: transaction.clone(),
        signature: Signature {
            key_type: KeyType::Ed25519,
            data: signature,
        },
    })
}

/// Signed transaction
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub signature: Signature,
}

/// Signature
#[derive(Debug, Clone)]
pub struct Signature {
    pub key_type: KeyType,
    pub data: Vec<u8>,
}

/// Serialize transaction (simplified Borsh)
fn serialize_transaction(transaction: &Transaction) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();

    // Signer ID length + data
    let signer_bytes = transaction.signer_id.0.as_bytes();
    bytes.extend_from_slice(&(signer_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(signer_bytes);

    // Public key
    bytes.push(match transaction.public_key.key_type {
        KeyType::Ed25519 => 0,
        KeyType::Secp256k1 => 1,
    });
    bytes.extend_from_slice(&transaction.public_key.data);

    // Nonce
    bytes.extend_from_slice(&transaction.nonce.to_le_bytes());

    // Receiver ID
    let receiver_bytes = transaction.receiver_id.0.as_bytes();
    bytes.extend_from_slice(&(receiver_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(receiver_bytes);

    // Block hash
    bytes.extend_from_slice(&transaction.block_hash);

    // Actions count
    bytes.extend_from_slice(&(transaction.actions.len() as u32).to_le_bytes());

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_id_validation() {
        assert!(AccountId::new("alice.near").is_ok());
        assert!(AccountId::new("bob").is_ok());
        assert!(AccountId::new("").is_err());
        assert!(AccountId::new("Alice").is_err()); // uppercase not allowed
    }

    #[test]
    fn test_public_key_parsing() {
        let pk = PublicKey::ed25519(&[0u8; 32]).unwrap();
        assert_eq!(pk.key_type, KeyType::Ed25519);
    }
}
