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

    /// Encode the canonical protobuf `cosmos.tx.v1beta1.SignDoc` sign-bytes.
    ///
    /// Proto definition (field numbers are load-bearing for on-chain verification):
    ///
    /// ```proto
    /// message SignDoc {
    ///   bytes  body_bytes      = 1;
    ///   bytes  auth_info_bytes = 2;
    ///   string chain_id        = 3;
    ///   uint64 account_number  = 4;
    /// }
    /// ```
    ///
    /// The encoding here (the `SignDoc` *wrapper*) is canonical and
    /// interoperable. NOTE: the result only verifies on-chain if `body_bytes`
    /// and `auth_info_bytes` are themselves canonical protobuf encodings of
    /// `TxBody` / `AuthInfo`. This crate does not yet produce those (see
    /// [`SignDoc::new`], which JSON-encodes them), so do not feed JSON bytes
    /// here and expect on-chain acceptance.
    pub fn to_direct_sign_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // field 1: body_bytes (bytes), wire type 2 -> tag 0x0a
        encode_len_delimited(&mut out, 1, &self.body_bytes);
        // field 2: auth_info_bytes (bytes), wire type 2 -> tag 0x12
        encode_len_delimited(&mut out, 2, &self.auth_info_bytes);
        // field 3: chain_id (string), wire type 2 -> tag 0x1a
        encode_len_delimited(&mut out, 3, self.chain_id.as_bytes());
        // field 4: account_number (uint64), wire type 0 -> tag 0x20
        if self.account_number != 0 {
            encode_varint_field(&mut out, 4, self.account_number);
        }
        out
    }

    /// Serialize to bytes for signing.
    ///
    /// # Fail-closed
    ///
    /// `SIGN_MODE_DIRECT` requires the protobuf `SignDoc` (see
    /// [`Self::to_direct_sign_bytes`]) computed over *protobuf* `body_bytes` /
    /// `auth_info_bytes`. Because [`SignDoc::new`] currently JSON-encodes those
    /// components, returning sign-bytes here would invite signing data that can
    /// never verify on-chain. This method is therefore deliberately
    /// fail-closed (GATE, HIGH #9). Callers with genuine protobuf component
    /// bytes should use [`Self::to_direct_sign_bytes`] /
    /// [`super::CosmosSigner::sign_direct_protobuf`] explicitly.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Err(BlockchainError::UnsupportedOperation(
            "Cosmos SIGN_MODE_DIRECT sign-bytes require canonical protobuf \
             TxBody/AuthInfo encoding, which is not implemented. Use \
             SignDoc::to_direct_sign_bytes with protobuf component bytes."
                .to_string(),
        ))
    }
}

/// Encode a protobuf length-delimited (wire type 2) field.
fn encode_len_delimited(out: &mut Vec<u8>, field_number: u32, data: &[u8]) {
    encode_tag(out, field_number, 2);
    encode_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// Encode a protobuf varint (wire type 0) field.
fn encode_varint_field(out: &mut Vec<u8>, field_number: u32, value: u64) {
    encode_tag(out, field_number, 0);
    encode_varint(out, value);
}

/// Encode a protobuf field tag (`field_number << 3 | wire_type`).
fn encode_tag(out: &mut Vec<u8>, field_number: u32, wire_type: u32) {
    encode_varint(out, ((field_number << 3) | wire_type) as u64);
}

/// Encode a base-128 varint.
fn encode_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
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

    /// KAT for the canonical protobuf `SignDoc` wrapper encoding.
    ///
    /// Hand-computed wire bytes for:
    ///   body_bytes=[01 02], auth_info_bytes=[03],
    ///   chain_id="cosmoshub-4", account_number=1
    ///
    /// Expected:
    ///   0a 02 0102                       (field 1, len 2)
    ///   12 01 03                         (field 2, len 1)
    ///   1a 0b 636f736d6f736875622d34     (field 3, len 11, "cosmoshub-4")
    ///   20 01                            (field 4, varint 1)
    #[test]
    fn test_signdoc_protobuf_wrapper_kat() {
        let doc = SignDoc {
            body_bytes: vec![0x01, 0x02],
            auth_info_bytes: vec![0x03],
            chain_id: "cosmoshub-4".to_string(),
            account_number: 1,
        };
        let bytes = doc.to_direct_sign_bytes();
        assert_eq!(
            hex::encode(&bytes),
            "0a0201021201031a0b636f736d6f736875622d342001"
        );
    }

    /// account_number 0 is the proto3 default and must be omitted.
    #[test]
    fn test_signdoc_protobuf_omits_default_account_number() {
        let doc = SignDoc {
            body_bytes: vec![],
            auth_info_bytes: vec![],
            chain_id: "c".to_string(),
            account_number: 0,
        };
        // field1 (empty): 0a 00, field2 (empty): 12 00, field3: 1a 01 63, no field4
        assert_eq!(hex::encode(doc.to_direct_sign_bytes()), "0a0012001a0163");
    }

    /// Varint encoding boundary: 300 -> 0xac 0x02.
    #[test]
    fn test_varint_encoding() {
        let mut out = Vec::new();
        encode_varint(&mut out, 300);
        assert_eq!(out, vec![0xac, 0x02]);

        let mut out = Vec::new();
        encode_varint(&mut out, 0);
        assert_eq!(out, vec![0x00]);
    }

    /// The legacy JSON `to_bytes` path is fail-closed (GATE, HIGH #9).
    #[test]
    fn test_signdoc_to_bytes_fail_closed() {
        let doc = SignDoc {
            body_bytes: vec![1, 2, 3],
            auth_info_bytes: vec![4, 5],
            chain_id: "cosmoshub-4".to_string(),
            account_number: 7,
        };
        assert!(matches!(
            doc.to_bytes(),
            Err(BlockchainError::UnsupportedOperation(_))
        ));
    }
}
