//! Cosmos transaction types and encoding

use crate::error::{BlockchainError, Result};
use serde::{Deserialize, Serialize};

/// Cosmos transaction body
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxBody {
    /// Messages in the transaction
    pub messages: Vec<serde_json::Value>,
    /// Optional memo
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    /// Timeout height (0 = no timeout)
    #[serde(default)]
    pub timeout_height: u64,
    /// Extension options
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extension_options: Vec<serde_json::Value>,
    /// Non-critical extension options
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub non_critical_extension_options: Vec<serde_json::Value>,
}

/// Signer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    /// Public key
    pub public_key: Option<PublicKey>,
    /// Sign mode
    pub mode_info: ModeInfo,
    /// Account sequence number
    pub sequence: u64,
}

/// Public key wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(rename = "@type")]
    pub type_url: String,
    pub key: String,
}

impl PublicKey {
    /// Create a secp256k1 public key
    pub fn secp256k1(key_bytes: &[u8]) -> Self {
        Self {
            type_url: "/cosmos.crypto.secp256k1.PubKey".to_string(),
            key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_bytes),
        }
    }

    /// Create an Ed25519 public key
    pub fn ed25519(key_bytes: &[u8]) -> Self {
        Self {
            type_url: "/cosmos.crypto.ed25519.PubKey".to_string(),
            key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_bytes),
        }
    }
}

/// Mode info for signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeInfo {
    /// Single signer mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single: Option<SingleMode>,
    /// Multi-signer mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multi: Option<MultiMode>,
}

/// Single signer mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleMode {
    /// Sign mode
    pub mode: SignMode,
}

/// Multi-signer mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiMode {
    /// Bitarray of signers
    pub bitarray: CompactBitArray,
    /// Mode infos for each signer
    pub mode_infos: Vec<ModeInfo>,
}

/// Compact bit array
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactBitArray {
    pub extra_bits_stored: u32,
    pub elems: Vec<u8>,
}

/// Sign mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignMode {
    /// Direct signing (protobuf)
    SignModeDirect,
    /// Legacy Amino JSON
    SignModeLegacyAminoJson,
    /// Textual signing
    SignModeTextual,
    /// Direct aux (for auxiliary signers)
    SignModeDirectAux,
}

impl Default for SignMode {
    fn default() -> Self {
        Self::SignModeDirect
    }
}

/// Transaction fee
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fee {
    /// Fee amount
    pub amount: Vec<Coin>,
    /// Gas limit
    pub gas_limit: u64,
    /// Fee payer (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// Fee granter (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granter: Option<String>,
}

impl Default for Fee {
    fn default() -> Self {
        Self {
            amount: vec![],
            gas_limit: 200000,
            payer: None,
            granter: None,
        }
    }
}

/// Coin amount
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coin {
    /// Denomination
    pub denom: String,
    /// Amount (as string to handle large numbers)
    pub amount: String,
}

impl Coin {
    /// Create a new coin
    pub fn new(denom: impl Into<String>, amount: u128) -> Self {
        Self {
            denom: denom.into(),
            amount: amount.to_string(),
        }
    }
}

/// Authentication info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthInfo {
    /// Signer infos
    pub signer_infos: Vec<SignerInfo>,
    /// Fee
    pub fee: Fee,
}

/// Sign document (what gets signed)
#[derive(Debug, Clone)]
pub struct SignDoc {
    /// Serialized TxBody
    pub body_bytes: Vec<u8>,
    /// Serialized AuthInfo
    pub auth_info_bytes: Vec<u8>,
    /// Chain ID
    pub chain_id: String,
    /// Account number
    pub account_number: u64,
}

impl SignDoc {
    /// Create a new SignDoc
    pub fn new(
        body: &TxBody,
        auth_info: &AuthInfo,
        chain_id: impl Into<String>,
        account_number: u64,
    ) -> Result<Self> {
        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| BlockchainError::SerializationError(e.to_string()))?;
        let auth_info_bytes = serde_json::to_vec(auth_info)
            .map_err(|e| BlockchainError::SerializationError(e.to_string()))?;

        Ok(Self {
            body_bytes,
            auth_info_bytes,
            chain_id: chain_id.into(),
            account_number,
        })
    }

    /// Serialize to bytes for signing
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        // In a real implementation, this would use protobuf encoding
        // For now, we use a JSON representation
        let doc = serde_json::json!({
            "body_bytes": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.body_bytes),
            "auth_info_bytes": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.auth_info_bytes),
            "chain_id": self.chain_id,
            "account_number": self.account_number.to_string(),
        });

        serde_json::to_vec(&doc).map_err(|e| BlockchainError::SerializationError(e.to_string()))
    }
}

/// Raw transaction (signed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRaw {
    /// Serialized TxBody
    pub body_bytes: Vec<u8>,
    /// Serialized AuthInfo
    pub auth_info_bytes: Vec<u8>,
    /// Signatures
    pub signatures: Vec<Vec<u8>>,
}

impl TxRaw {
    /// Create from a SignDoc and signatures
    pub fn from_sign_doc(sign_doc: SignDoc, signatures: Vec<Vec<u8>>) -> Self {
        Self {
            body_bytes: sign_doc.body_bytes,
            auth_info_bytes: sign_doc.auth_info_bytes,
            signatures,
        }
    }

    /// Serialize to bytes for broadcast
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| BlockchainError::SerializationError(e.to_string()))
    }
}

/// Standard bank send message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsgSend {
    #[serde(rename = "@type")]
    pub type_url: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: Vec<Coin>,
}

impl MsgSend {
    /// Create a new MsgSend
    pub fn new(from: impl Into<String>, to: impl Into<String>, amount: Vec<Coin>) -> Self {
        Self {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            from_address: from.into(),
            to_address: to.into(),
            amount,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coin_creation() {
        let coin = Coin::new("uatom", 1000000);
        assert_eq!(coin.denom, "uatom");
        assert_eq!(coin.amount, "1000000");
    }

    #[test]
    fn test_msg_send() {
        let msg = MsgSend::new(
            "cosmos1abc...",
            "cosmos1def...",
            vec![Coin::new("uatom", 1000000)],
        );
        assert_eq!(msg.type_url, "/cosmos.bank.v1beta1.MsgSend");
    }

    #[test]
    fn test_fee_default() {
        let fee = Fee::default();
        assert_eq!(fee.gas_limit, 200000);
    }
}
