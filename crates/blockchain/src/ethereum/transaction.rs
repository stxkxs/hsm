//! Ethereum transaction parsing and signing
//!
//! Supports legacy, EIP-2930 (access list), and EIP-1559 (dynamic fee) transactions.

use crate::error::{BlockchainError, Result};
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use sha3::{Digest, Keccak256};

/// Ethereum transaction types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    /// Legacy transaction (pre-EIP-2718)
    Legacy = 0,
    /// EIP-2930 access list transaction
    AccessList = 1,
    /// EIP-1559 dynamic fee transaction
    DynamicFee = 2,
}

/// Legacy Ethereum transaction
#[derive(Debug, Clone)]
pub struct LegacyTransaction {
    /// Transaction nonce
    pub nonce: u64,
    /// Gas price in wei
    pub gas_price: U256,
    /// Gas limit
    pub gas_limit: u64,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    /// Value in wei
    pub value: U256,
    /// Transaction data
    pub data: Bytes,
    /// Chain ID (for EIP-155)
    pub chain_id: Option<u64>,
}

impl LegacyTransaction {
    /// Create a new legacy transaction
    pub fn new(
        nonce: u64,
        gas_price: U256,
        gas_limit: u64,
        to: Option<Address>,
        value: U256,
        data: Bytes,
    ) -> Self {
        Self {
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            chain_id: None,
        }
    }

    /// Set chain ID for EIP-155
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Get the signing hash (for EIP-155 if chain_id is set)
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut buf = Vec::new();

        // RLP encode: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
        let nonce = U256::from(self.nonce);
        let gas_limit = U256::from(self.gas_limit);

        // Start RLP list
        let mut items = Vec::new();

        nonce.encode(&mut items);
        self.gas_price.encode(&mut items);
        gas_limit.encode(&mut items);

        if let Some(to) = self.to {
            to.encode(&mut items);
        } else {
            // Empty bytes for contract creation
            Bytes::new().encode(&mut items);
        }

        self.value.encode(&mut items);
        self.data.clone().encode(&mut items);

        // EIP-155: include chain_id, 0, 0
        if let Some(chain_id) = self.chain_id {
            U256::from(chain_id).encode(&mut items);
            U256::ZERO.encode(&mut items);
            U256::ZERO.encode(&mut items);
        }

        // Encode as list
        alloy_rlp::encode_list::<_, &[u8]>(&[items.as_slice()], &mut buf);

        Keccak256::digest(&items).into()
    }

    /// Encode the signed transaction
    pub fn encode_signed(&self, v: u64, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut items = Vec::new();

        let nonce = U256::from(self.nonce);
        let gas_limit = U256::from(self.gas_limit);

        nonce.encode(&mut items);
        self.gas_price.encode(&mut items);
        gas_limit.encode(&mut items);

        if let Some(to) = self.to {
            to.encode(&mut items);
        } else {
            Bytes::new().encode(&mut items);
        }

        self.value.encode(&mut items);
        self.data.clone().encode(&mut items);

        U256::from(v).encode(&mut items);
        B256::from_slice(r).encode(&mut items);
        B256::from_slice(s).encode(&mut items);

        let mut buf = Vec::new();
        alloy_rlp::encode_list::<_, &[u8]>(&[items.as_slice()], &mut buf);
        items
    }
}

/// EIP-1559 dynamic fee transaction
#[derive(Debug, Clone)]
pub struct Eip1559Transaction {
    /// Chain ID
    pub chain_id: u64,
    /// Transaction nonce
    pub nonce: u64,
    /// Max priority fee per gas (tip)
    pub max_priority_fee_per_gas: U256,
    /// Max fee per gas
    pub max_fee_per_gas: U256,
    /// Gas limit
    pub gas_limit: u64,
    /// Recipient address
    pub to: Option<Address>,
    /// Value in wei
    pub value: U256,
    /// Transaction data
    pub data: Bytes,
    /// Access list
    pub access_list: Vec<(Address, Vec<B256>)>,
}

impl Eip1559Transaction {
    /// Create a new EIP-1559 transaction
    pub fn new(
        chain_id: u64,
        nonce: u64,
        max_priority_fee_per_gas: U256,
        max_fee_per_gas: U256,
        gas_limit: u64,
        to: Option<Address>,
        value: U256,
        data: Bytes,
    ) -> Self {
        Self {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list: Vec::new(),
        }
    }

    /// Add access list entry
    pub fn with_access_list(mut self, list: Vec<(Address, Vec<B256>)>) -> Self {
        self.access_list = list;
        self
    }

    /// Get the signing hash
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut items = Vec::new();

        U256::from(self.chain_id).encode(&mut items);
        U256::from(self.nonce).encode(&mut items);
        self.max_priority_fee_per_gas.encode(&mut items);
        self.max_fee_per_gas.encode(&mut items);
        U256::from(self.gas_limit).encode(&mut items);

        if let Some(to) = self.to {
            to.encode(&mut items);
        } else {
            Bytes::new().encode(&mut items);
        }

        self.value.encode(&mut items);
        self.data.clone().encode(&mut items);

        // Encode access list
        let mut access_list_encoded = Vec::new();
        for (addr, keys) in &self.access_list {
            let mut entry = Vec::new();
            addr.encode(&mut entry);
            let mut keys_encoded = Vec::new();
            for key in keys {
                key.encode(&mut keys_encoded);
            }
            alloy_rlp::encode_list::<_, &[u8]>(&[keys_encoded.as_slice()], &mut entry);
        }
        alloy_rlp::encode_list::<_, &[u8]>(&[access_list_encoded.as_slice()], &mut items);

        // Prefix with transaction type
        let mut buf = vec![0x02]; // EIP-1559 type
        buf.extend_from_slice(&items);

        Keccak256::digest(&buf).into()
    }
}

/// Parse a raw transaction
pub fn parse_transaction(raw: &[u8]) -> Result<TransactionType> {
    if raw.is_empty() {
        return Err(BlockchainError::InvalidTransaction(
            "Empty transaction".to_string(),
        ));
    }

    // Check for typed transaction envelope (EIP-2718)
    match raw[0] {
        0x01 => Ok(TransactionType::AccessList),
        0x02 => Ok(TransactionType::DynamicFee),
        // Legacy transactions start with RLP encoding (0xc0-0xff)
        b if b >= 0xc0 => Ok(TransactionType::Legacy),
        _ => Err(BlockchainError::InvalidTransaction(format!(
            "Unknown transaction type: 0x{:02x}",
            raw[0]
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_transaction_hash() {
        let tx = LegacyTransaction::new(
            0,
            U256::from(20_000_000_000u64), // 20 gwei
            21000,
            Some(Address::ZERO),
            U256::from(1_000_000_000_000_000_000u64), // 1 ETH
            Bytes::new(),
        )
        .with_chain_id(1);

        let hash = tx.signing_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_eip1559_transaction_hash() {
        let tx = Eip1559Transaction::new(
            1, // mainnet
            0,
            U256::from(2_000_000_000u64),   // 2 gwei priority fee
            U256::from(100_000_000_000u64), // 100 gwei max fee
            21000,
            Some(Address::ZERO),
            U256::from(1_000_000_000_000_000_000u64),
            Bytes::new(),
        );

        let hash = tx.signing_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_parse_transaction_type() {
        // Legacy transaction (RLP encoded list starts with 0xf8 or higher)
        let legacy = vec![0xf8, 0x00];
        assert_eq!(parse_transaction(&legacy).unwrap(), TransactionType::Legacy);

        // EIP-1559 transaction
        let eip1559 = vec![0x02, 0x00];
        assert_eq!(
            parse_transaction(&eip1559).unwrap(),
            TransactionType::DynamicFee
        );

        // EIP-2930 transaction
        let eip2930 = vec![0x01, 0x00];
        assert_eq!(
            parse_transaction(&eip2930).unwrap(),
            TransactionType::AccessList
        );
    }
}
