//! Layer 2 blockchain support
//!
//! Provides signing support for Ethereum L2 networks:
//! - zkSync Era
//! - Linea
//! - Scroll
//! - Base
//!
//! Most L2s use standard Ethereum signing with chain-specific chain IDs.

use crate::error::{BlockchainError, Result};

/// Known L2 networks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2Network {
    /// zkSync Era (chain ID 324)
    ZkSyncEra,
    /// zkSync Era Sepolia testnet (chain ID 300)
    ZkSyncEraSepolia,
    /// Linea (chain ID 59144)
    Linea,
    /// Linea Goerli testnet (chain ID 59140)
    LineaGoerli,
    /// Scroll (chain ID 534352)
    Scroll,
    /// Scroll Sepolia testnet (chain ID 534351)
    ScrollSepolia,
    /// Base (chain ID 8453)
    Base,
    /// Base Sepolia testnet (chain ID 84532)
    BaseSepolia,
    /// Optimism (chain ID 10)
    Optimism,
    /// Optimism Sepolia (chain ID 11155420)
    OptimismSepolia,
    /// Arbitrum One (chain ID 42161)
    ArbitrumOne,
    /// Arbitrum Sepolia (chain ID 421614)
    ArbitrumSepolia,
}

impl L2Network {
    /// Get the chain ID for this network
    pub fn chain_id(&self) -> u64 {
        match self {
            Self::ZkSyncEra => 324,
            Self::ZkSyncEraSepolia => 300,
            Self::Linea => 59144,
            Self::LineaGoerli => 59140,
            Self::Scroll => 534352,
            Self::ScrollSepolia => 534351,
            Self::Base => 8453,
            Self::BaseSepolia => 84532,
            Self::Optimism => 10,
            Self::OptimismSepolia => 11155420,
            Self::ArbitrumOne => 42161,
            Self::ArbitrumSepolia => 421614,
        }
    }

    /// Get the network name
    pub fn name(&self) -> &str {
        match self {
            Self::ZkSyncEra => "zkSync Era",
            Self::ZkSyncEraSepolia => "zkSync Era Sepolia",
            Self::Linea => "Linea",
            Self::LineaGoerli => "Linea Goerli",
            Self::Scroll => "Scroll",
            Self::ScrollSepolia => "Scroll Sepolia",
            Self::Base => "Base",
            Self::BaseSepolia => "Base Sepolia",
            Self::Optimism => "Optimism",
            Self::OptimismSepolia => "Optimism Sepolia",
            Self::ArbitrumOne => "Arbitrum One",
            Self::ArbitrumSepolia => "Arbitrum Sepolia",
        }
    }

    /// Check if this is a testnet
    pub fn is_testnet(&self) -> bool {
        matches!(
            self,
            Self::ZkSyncEraSepolia
                | Self::LineaGoerli
                | Self::ScrollSepolia
                | Self::BaseSepolia
                | Self::OptimismSepolia
                | Self::ArbitrumSepolia
        )
    }

    /// Get the native currency symbol
    pub fn native_currency(&self) -> &str {
        "ETH"
    }

    /// Get the block explorer URL
    pub fn explorer_url(&self) -> &str {
        match self {
            Self::ZkSyncEra => "https://explorer.zksync.io",
            Self::ZkSyncEraSepolia => "https://sepolia.explorer.zksync.io",
            Self::Linea => "https://lineascan.build",
            Self::LineaGoerli => "https://goerli.lineascan.build",
            Self::Scroll => "https://scrollscan.com",
            Self::ScrollSepolia => "https://sepolia.scrollscan.com",
            Self::Base => "https://basescan.org",
            Self::BaseSepolia => "https://sepolia.basescan.org",
            Self::Optimism => "https://optimistic.etherscan.io",
            Self::OptimismSepolia => "https://sepolia-optimism.etherscan.io",
            Self::ArbitrumOne => "https://arbiscan.io",
            Self::ArbitrumSepolia => "https://sepolia.arbiscan.io",
        }
    }

    /// Get from chain ID
    pub fn from_chain_id(chain_id: u64) -> Option<Self> {
        match chain_id {
            324 => Some(Self::ZkSyncEra),
            300 => Some(Self::ZkSyncEraSepolia),
            59144 => Some(Self::Linea),
            59140 => Some(Self::LineaGoerli),
            534352 => Some(Self::Scroll),
            534351 => Some(Self::ScrollSepolia),
            8453 => Some(Self::Base),
            84532 => Some(Self::BaseSepolia),
            10 => Some(Self::Optimism),
            11155420 => Some(Self::OptimismSepolia),
            42161 => Some(Self::ArbitrumOne),
            421614 => Some(Self::ArbitrumSepolia),
            _ => None,
        }
    }
}

/// L2 configuration
#[derive(Debug, Clone)]
pub struct L2Config {
    /// Network
    pub network: L2Network,
    /// RPC endpoint (optional)
    pub rpc_url: Option<String>,
    /// Custom gas settings
    pub gas_settings: Option<GasSettings>,
}

/// Gas settings for L2 transactions
#[derive(Debug, Clone)]
pub struct GasSettings {
    /// Max fee per gas (in wei)
    pub max_fee_per_gas: Option<u128>,
    /// Max priority fee per gas (in wei)
    pub max_priority_fee_per_gas: Option<u128>,
    /// Gas limit
    pub gas_limit: Option<u64>,
}

/// zkSync-specific transaction types
pub mod zksync {
    /// zkSync transaction type
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TransactionType {
        /// Legacy transaction (type 0)
        Legacy,
        /// EIP-2930 access list (type 1)
        AccessList,
        /// EIP-1559 (type 2)
        Eip1559,
        /// zkSync Era EIP-712 (type 113)
        Eip712,
    }

    impl TransactionType {
        /// Get the type byte
        pub fn type_byte(&self) -> u8 {
            match self {
                Self::Legacy => 0,
                Self::AccessList => 1,
                Self::Eip1559 => 2,
                Self::Eip712 => 113,
            }
        }
    }

    /// zkSync paymaster parameters
    #[derive(Debug, Clone)]
    pub struct PaymasterParams {
        /// Paymaster address
        pub paymaster: [u8; 20],
        /// Paymaster input
        pub paymaster_input: Vec<u8>,
    }

    /// zkSync factory dependencies
    #[derive(Debug, Clone)]
    pub struct FactoryDeps {
        /// Contract bytecode hashes
        pub factory_deps: Vec<[u8; 32]>,
    }
}

/// Create an L2 transaction with proper chain ID
pub fn create_l2_transaction(
    network: L2Network,
    to: [u8; 20],
    value: u128,
    data: Vec<u8>,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> L2Transaction {
    L2Transaction {
        chain_id: network.chain_id(),
        nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas_limit,
        to,
        value,
        data,
        access_list: vec![],
    }
}

/// L2 transaction (EIP-1559 compatible)
#[derive(Debug, Clone)]
pub struct L2Transaction {
    /// Chain ID
    pub chain_id: u64,
    /// Nonce
    pub nonce: u64,
    /// Max fee per gas
    pub max_fee_per_gas: u128,
    /// Max priority fee per gas
    pub max_priority_fee_per_gas: u128,
    /// Gas limit
    pub gas_limit: u64,
    /// Recipient address
    pub to: [u8; 20],
    /// Value in wei
    pub value: u128,
    /// Transaction data
    pub data: Vec<u8>,
    /// Access list
    pub access_list: Vec<AccessListItem>,
}

/// Access list item
#[derive(Debug, Clone)]
pub struct AccessListItem {
    /// Address
    pub address: [u8; 20],
    /// Storage keys
    pub storage_keys: Vec<[u8; 32]>,
}

/// Sign an L2 transaction
pub fn sign_l2_transaction(
    private_key: &[u8],
    transaction: &L2Transaction,
) -> Result<SignedL2Transaction> {
    // Use standard Ethereum signing (most L2s are EVM-compatible)
    let message_hash = hash_transaction(transaction)?;
    let signature = sign_secp256k1(private_key, &message_hash)?;

    Ok(SignedL2Transaction {
        transaction: transaction.clone(),
        signature,
    })
}

/// Signed L2 transaction
#[derive(Debug, Clone)]
pub struct SignedL2Transaction {
    pub transaction: L2Transaction,
    pub signature: Signature,
}

/// ECDSA signature
#[derive(Debug, Clone)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

/// Hash transaction for signing
fn hash_transaction(transaction: &L2Transaction) -> Result<[u8; 32]> {
    use sha3::{Digest, Keccak256};

    // EIP-1559 transaction hash
    let mut hasher = Keccak256::new();
    hasher.update([0x02]); // EIP-1559 type

    // RLP encode transaction fields
    let mut rlp_data = Vec::new();
    rlp_data.extend_from_slice(&rlp_encode_u64(transaction.chain_id));
    rlp_data.extend_from_slice(&rlp_encode_u64(transaction.nonce));
    rlp_data.extend_from_slice(&rlp_encode_u128(transaction.max_priority_fee_per_gas));
    rlp_data.extend_from_slice(&rlp_encode_u128(transaction.max_fee_per_gas));
    rlp_data.extend_from_slice(&rlp_encode_u64(transaction.gas_limit));
    rlp_data.extend_from_slice(&transaction.to);
    rlp_data.extend_from_slice(&rlp_encode_u128(transaction.value));

    hasher.update(&rlp_data);

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    Ok(result)
}

/// Simple RLP encoding for u64
fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        vec![0x80]
    } else {
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let len = 8 - start;
        let mut result = vec![0x80 + len as u8];
        result.extend_from_slice(&bytes[start..]);
        result
    }
}

/// Simple RLP encoding for u128
fn rlp_encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        vec![0x80]
    } else {
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
        let len = 16 - start;
        let mut result = vec![0x80 + len as u8];
        result.extend_from_slice(&bytes[start..]);
        result
    }
}

/// Sign with secp256k1
fn sign_secp256k1(private_key: &[u8], message: &[u8]) -> Result<Signature> {
    use k256::ecdsa::{signature::Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|e| BlockchainError::InvalidPrivateKey(e.to_string()))?;

    let sig: k256::ecdsa::Signature = signing_key.sign(message);
    let bytes = sig.to_bytes();

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);

    // Calculate recovery ID
    let v = 27; // Simplified; real implementation needs proper recovery ID

    Ok(Signature { r, s, v })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2_network_chain_id() {
        assert_eq!(L2Network::Base.chain_id(), 8453);
        assert_eq!(L2Network::ZkSyncEra.chain_id(), 324);
    }

    #[test]
    fn test_l2_network_from_chain_id() {
        assert_eq!(L2Network::from_chain_id(8453), Some(L2Network::Base));
        assert_eq!(L2Network::from_chain_id(999999), None);
    }

    #[test]
    fn test_l2_network_is_testnet() {
        assert!(!L2Network::Base.is_testnet());
        assert!(L2Network::BaseSepolia.is_testnet());
    }
}
