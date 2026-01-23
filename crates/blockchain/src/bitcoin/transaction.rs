//! Bitcoin transaction parsing and creation

use crate::error::{BlockchainError, Result};
use bitcoin::{
    consensus::{deserialize, serialize},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use sha2::{Digest, Sha256};
use std::str::FromStr;

/// Bitcoin transaction wrapper
#[derive(Debug, Clone)]
pub struct BitcoinTransaction {
    inner: Transaction,
}

impl BitcoinTransaction {
    /// Create a new transaction
    pub fn new(version: i32, lock_time: u32) -> Self {
        Self {
            inner: Transaction {
                version: Version(version),
                lock_time: bitcoin::absolute::LockTime::from_consensus(lock_time),
                input: Vec::new(),
                output: Vec::new(),
            },
        }
    }

    /// Parse transaction from raw bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let tx: Transaction =
            deserialize(data).map_err(|e| BlockchainError::InvalidTransaction(e.to_string()))?;
        Ok(Self { inner: tx })
    }

    /// Parse transaction from hex string
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes =
            hex::decode(hex).map_err(|e| BlockchainError::InvalidTransaction(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Add an input
    pub fn add_input(
        &mut self,
        txid: &str,
        vout: u32,
        script_sig: Option<Vec<u8>>,
        sequence: Option<u32>,
    ) -> Result<()> {
        let txid =
            Txid::from_str(txid).map_err(|e| BlockchainError::InvalidTransaction(e.to_string()))?;

        let input = TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: script_sig
                .map(|s| ScriptBuf::from_bytes(s))
                .unwrap_or_default(),
            sequence: Sequence(sequence.unwrap_or(0xffffffff)),
            witness: Witness::default(),
        };

        self.inner.input.push(input);
        Ok(())
    }

    /// Add an output
    pub fn add_output(&mut self, value: u64, script_pubkey: Vec<u8>) {
        let output = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script_pubkey),
        };

        self.inner.output.push(output);
    }

    /// Get the transaction ID
    pub fn txid(&self) -> String {
        self.inner.compute_txid().to_string()
    }

    /// Get the witness transaction ID (for SegWit)
    pub fn wtxid(&self) -> String {
        self.inner.compute_wtxid().to_string()
    }

    /// Get the serialized transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(&self.inner)
    }

    /// Get the hex-encoded transaction
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Get the virtual size (vbytes)
    pub fn vsize(&self) -> usize {
        self.inner.vsize()
    }

    /// Get the weight
    pub fn weight(&self) -> usize {
        self.inner.weight().to_wu() as usize
    }

    /// Get number of inputs
    pub fn input_count(&self) -> usize {
        self.inner.input.len()
    }

    /// Get number of outputs
    pub fn output_count(&self) -> usize {
        self.inner.output.len()
    }

    /// Check if transaction is SegWit
    pub fn is_segwit(&self) -> bool {
        self.inner.input.iter().any(|i| !i.witness.is_empty())
    }

    /// Get the sighash for signing (legacy P2PKH)
    pub fn sighash_legacy(
        &self,
        input_index: usize,
        script_code: &[u8],
        sighash_type: u32,
    ) -> Result<[u8; 32]> {
        if input_index >= self.inner.input.len() {
            return Err(BlockchainError::InvalidTransaction(
                "Input index out of bounds".to_string(),
            ));
        }

        // Create a modified copy for hashing
        let mut tx_copy = self.inner.clone();

        // Clear all input scripts
        for input in &mut tx_copy.input {
            input.script_sig = ScriptBuf::new();
        }

        // Set the script for the input being signed
        tx_copy.input[input_index].script_sig = ScriptBuf::from_bytes(script_code.to_vec());

        // Serialize and append sighash type
        let mut data = serialize(&tx_copy);
        data.extend_from_slice(&sighash_type.to_le_bytes());

        // Double SHA256
        let hash1 = Sha256::digest(&data);
        let hash2 = Sha256::digest(&hash1);

        Ok(hash2.into())
    }

    /// Get the inner transaction
    pub fn inner(&self) -> &Transaction {
        &self.inner
    }
}

/// Sighash types
pub mod sighash {
    pub const ALL: u32 = 0x01;
    pub const NONE: u32 = 0x02;
    pub const SINGLE: u32 = 0x03;
    pub const ANYONECANPAY: u32 = 0x80;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_transaction() {
        let mut tx = BitcoinTransaction::new(2, 0);

        // Add input
        tx.add_input(
            "0000000000000000000000000000000000000000000000000000000000000001",
            0,
            None,
            None,
        )
        .unwrap();

        // Add output (1 BTC = 100_000_000 satoshis)
        let script_pubkey =
            hex::decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap();
        tx.add_output(100_000_000, script_pubkey);

        assert_eq!(tx.input_count(), 1);
        assert_eq!(tx.output_count(), 1);
    }

    #[test]
    fn test_transaction_serialization() {
        let tx = BitcoinTransaction::new(2, 0);
        let bytes = tx.to_bytes();
        assert!(!bytes.is_empty());

        let hex = tx.to_hex();
        assert!(!hex.is_empty());
    }

    #[test]
    fn test_transaction_ids() {
        let tx = BitcoinTransaction::new(2, 0);
        let txid = tx.txid();
        let wtxid = tx.wtxid();

        // Both should be valid hex transaction IDs (64 hex chars = 32 bytes)
        assert_eq!(txid.len(), 64);
        assert_eq!(wtxid.len(), 64);
        assert!(txid.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(wtxid.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
