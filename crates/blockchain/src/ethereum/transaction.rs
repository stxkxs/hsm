//! Ethereum transaction parsing and signing
//!
//! Supports legacy, EIP-2930 (access list), and EIP-1559 (dynamic fee) transactions.

use crate::error::{BlockchainError, Result};
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rlp::{Encodable, Header};
use sha3::{Digest, Keccak256};

/// Wrap an already-RLP-encoded payload (the concatenation of each field's RLP
/// encoding) into a single RLP list by prepending the correct list header.
///
/// This is the correct way to build `RLP_list([field0, field1, ...])`. Using
/// `alloy_rlp::encode_list` with the payload as a single `&[u8]` element instead
/// produces `RLP_list([RLP_string(payload)])`, which double-wraps the fields and
/// yields the wrong Keccak256 signing hash.
fn rlp_wrap_list(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(payload.len() + 9);
    let header = Header {
        list: true,
        payload_length: payload.len(),
    };
    header.encode(&mut buf);
    buf.extend_from_slice(payload);
    buf
}

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
        // RLP encode: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
        let nonce = U256::from(self.nonce);
        let gas_limit = U256::from(self.gas_limit);

        // Concatenate each field's RLP encoding into the list payload.
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

        // Wrap the fields in a single RLP list header.
        let buf = rlp_wrap_list(&items);

        Keccak256::digest(&buf).into()
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

        // Wrap the fields in a single RLP list header and return the wrapped
        // bytes (previously this returned the bare, unwrapped field payload).
        rlp_wrap_list(&items)
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

        // Encode the access list as a proper nested RLP list:
        //   accessList = [ [address, [storageKey, ...]], ... ]
        let mut access_list_payload = Vec::new();
        for (addr, keys) in &self.access_list {
            // Inner list of storage keys.
            let mut keys_payload = Vec::new();
            for key in keys {
                key.encode(&mut keys_payload);
            }
            let keys_list = rlp_wrap_list(&keys_payload);

            // entry = [address, [storageKey, ...]]
            let mut entry_payload = Vec::new();
            addr.encode(&mut entry_payload);
            entry_payload.extend_from_slice(&keys_list);
            access_list_payload.extend_from_slice(&rlp_wrap_list(&entry_payload));
        }
        items.extend_from_slice(&rlp_wrap_list(&access_list_payload));

        // Wrap the fields in a single RLP list header, then prefix with the
        // EIP-2718 transaction type byte.
        let body = rlp_wrap_list(&items);
        let mut buf = vec![0x02]; // EIP-1559 type
        buf.extend_from_slice(&body);

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

    /// Known-answer test: the canonical EIP-155 example transaction.
    ///
    /// Source: EIP-155 specification example
    /// (nonce=9, gasPrice=20 gwei, gas=21000, to=0x3535..35, value=1 ETH,
    /// data=empty, chainId=1). The reference RLP for signing and its Keccak256
    /// hash are published in the EIP-155 spec. Before the RLP double-wrapping
    /// fix the encoded list started with 0xed instead of 0xec, producing a wrong
    /// signing hash (HIGH #17).
    #[test]
    fn test_legacy_signing_hash_eip155_kat() {
        let to: Address = "0x3535353535353535353535353535353535353535"
            .parse()
            .unwrap();
        let tx = LegacyTransaction::new(
            9,
            U256::from(20_000_000_000u64), // 20 gwei
            21000,
            Some(to),
            U256::from(1_000_000_000_000_000_000u64), // 1 ETH
            Bytes::new(),
        )
        .with_chain_id(1);

        // The hash must equal the canonical EIP-155 example signing hash.
        let hash = tx.signing_hash();
        let expected =
            hex::decode("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")
                .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());

        // The reference RLP for signing must be reproduced exactly, and must
        // begin with 0xec (correct), not 0xed (the double-wrapped bug).
        let expected_rlp = "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080";
        let mut items = Vec::new();
        U256::from(9u64).encode(&mut items);
        U256::from(20_000_000_000u64).encode(&mut items);
        U256::from(21000u64).encode(&mut items);
        to.encode(&mut items);
        U256::from(1_000_000_000_000_000_000u64).encode(&mut items);
        Bytes::new().encode(&mut items);
        U256::from(1u64).encode(&mut items);
        U256::ZERO.encode(&mut items);
        U256::ZERO.encode(&mut items);
        let rlp = rlp_wrap_list(&items);
        assert_eq!(hex::encode(&rlp), expected_rlp);
        assert_eq!(rlp[0], 0xec);
        // And the hash is the Keccak256 of exactly those bytes.
        let recomputed: [u8; 32] = Keccak256::digest(&rlp).into();
        assert_eq!(recomputed, hash);
    }

    /// The signed encoding must be a single RLP list (not the bare, unwrapped
    /// field payload that the buggy `encode_signed` previously returned), and
    /// must be re-parseable as a legacy transaction (LOW #27).
    #[test]
    fn test_encode_signed_is_wrapped_list() {
        let tx = LegacyTransaction::new(
            9,
            U256::from(20_000_000_000u64),
            21000,
            Some(
                "0x3535353535353535353535353535353535353535"
                    .parse()
                    .unwrap(),
            ),
            U256::from(1_000_000_000_000_000_000u64),
            Bytes::new(),
        )
        .with_chain_id(1);

        let r = [0x11u8; 32];
        let s = [0x22u8; 32];
        let encoded = tx.encode_signed(37, &r, &s);

        // A legacy signed tx is an RLP list, so the first byte is in [0xc0, 0xff].
        assert!(
            encoded[0] >= 0xc0,
            "signed tx must be an RLP list (got first byte 0x{:02x})",
            encoded[0]
        );
        // It must therefore be classified as a legacy transaction.
        assert_eq!(
            parse_transaction(&encoded).unwrap(),
            TransactionType::Legacy
        );

        // Cross-check the exact bytes against an independently built RLP list.
        let mut items = Vec::new();
        U256::from(9u64).encode(&mut items);
        U256::from(20_000_000_000u64).encode(&mut items);
        U256::from(21000u64).encode(&mut items);
        let to: Address = "0x3535353535353535353535353535353535353535"
            .parse()
            .unwrap();
        to.encode(&mut items);
        U256::from(1_000_000_000_000_000_000u64).encode(&mut items);
        Bytes::new().encode(&mut items);
        U256::from(37u64).encode(&mut items);
        B256::from_slice(&r).encode(&mut items);
        B256::from_slice(&s).encode(&mut items);
        let expected = rlp_wrap_list(&items);
        assert_eq!(encoded, expected);
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

    /// Known-answer test for EIP-1559 signing-hash preimage with an empty access
    /// list. The transaction payload (type byte 0x02 + RLP list) is built and
    /// cross-checked, then hashed. The empty access list must serialize as the
    /// empty RLP list (0xc0) and the fields must be wrapped in a single list
    /// header (HIGH #17 also affected the EIP-1559 path).
    #[test]
    fn test_eip1559_signing_hash_kat() {
        let to: Address = "0x3535353535353535353535353535353535353535"
            .parse()
            .unwrap();
        let tx = Eip1559Transaction::new(
            1,
            0,
            U256::from(1_000_000_000u64), // 1 gwei
            U256::from(2_000_000_000u64), // 2 gwei
            21000,
            Some(to),
            U256::from(1_000_000_000_000_000_000u64),
            Bytes::new(),
        );

        // Independently constructed reference preimage.
        let expected_tx = "02ef0180843b9aca008477359400825208943535353535353535353535353535353535353535880de0b6b3a764000080c0";
        let mut items = Vec::new();
        U256::from(1u64).encode(&mut items);
        U256::from(0u64).encode(&mut items);
        U256::from(1_000_000_000u64).encode(&mut items);
        U256::from(2_000_000_000u64).encode(&mut items);
        U256::from(21000u64).encode(&mut items);
        to.encode(&mut items);
        U256::from(1_000_000_000_000_000_000u64).encode(&mut items);
        Bytes::new().encode(&mut items);
        items.extend_from_slice(&rlp_wrap_list(&[])); // empty access list => 0xc0
        let body = rlp_wrap_list(&items);
        let mut preimage = vec![0x02u8];
        preimage.extend_from_slice(&body);
        assert_eq!(hex::encode(&preimage), expected_tx);
        // ...and it ends with the empty-access-list marker 0xc0.
        assert_eq!(*preimage.last().unwrap(), 0xc0);

        let expected_hash: [u8; 32] = Keccak256::digest(&preimage).into();
        assert_eq!(tx.signing_hash(), expected_hash);
    }

    /// An access-list entry must serialize as the nested RLP structure
    /// `[address, [storageKey, ...]]` and change the signing hash relative to
    /// the empty-access-list case. The old code discarded the per-entry bytes,
    /// so the access list silently had no effect on the hash.
    #[test]
    fn test_eip1559_access_list_affects_hash() {
        let to: Address = "0x3535353535353535353535353535353535353535"
            .parse()
            .unwrap();
        let base = Eip1559Transaction::new(
            1,
            0,
            U256::from(1_000_000_000u64),
            U256::from(2_000_000_000u64),
            21000,
            Some(to),
            U256::from(1_000_000_000_000_000_000u64),
            Bytes::new(),
        );

        let addr: Address = "0x0000000000000000000000000000000000001337"
            .parse()
            .unwrap();
        let key = B256::from_slice(&[0x11u8; 32]);
        let with_list = base.clone().with_access_list(vec![(addr, vec![key])]);

        assert_ne!(
            base.signing_hash(),
            with_list.signing_hash(),
            "access list entries must change the signing hash"
        );

        // Cross-check the access-list RLP fragment against an independent build.
        let mut keys_payload = Vec::new();
        key.encode(&mut keys_payload);
        let keys_list = rlp_wrap_list(&keys_payload);
        let mut entry_payload = Vec::new();
        addr.encode(&mut entry_payload);
        entry_payload.extend_from_slice(&keys_list);
        let access = rlp_wrap_list(&rlp_wrap_list(&entry_payload));
        assert_eq!(
            hex::encode(&access),
            "f838f7940000000000000000000000000000000000001337e1a01111111111111111111111111111111111111111111111111111111111111111"
        );
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
