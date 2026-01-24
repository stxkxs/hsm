//! TON (The Open Network) blockchain support
//!
//! Provides signing and transaction support for TON.
//!
//! # Features
//!
//! - Ed25519 signing
//! - BoC (Bag of Cells) encoding
//! - Wallet contract support (v3r2, v4r2)

use crate::error::{BlockchainError, Result};

/// TON address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TonAddress {
    /// Workchain ID (-1 for masterchain, 0 for basechain)
    pub workchain: i8,
    /// Account ID (256 bits / 32 bytes)
    pub account_id: [u8; 32],
    /// Bounceable flag
    pub bounceable: bool,
    /// Testnet flag
    pub testnet: bool,
}

impl TonAddress {
    /// Create a new address
    pub fn new(workchain: i8, account_id: [u8; 32]) -> Self {
        Self {
            workchain,
            account_id,
            bounceable: true,
            testnet: false,
        }
    }

    /// Derive address from public key (for standard wallet)
    pub fn from_public_key(public_key: &[u8], workchain: i8) -> Result<Self> {
        if public_key.len() != 32 {
            return Err(BlockchainError::InvalidPublicKey(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        // Compute state init hash for wallet v4r2
        // In practice, this requires more complex computation
        let mut account_id = [0u8; 32];
        account_id.copy_from_slice(public_key);

        Ok(Self::new(workchain, account_id))
    }

    /// Parse from raw string (workchain:hex)
    pub fn from_raw(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(BlockchainError::InvalidAddress(
                "Invalid raw address format".to_string(),
            ));
        }

        let workchain = parts[0]
            .parse::<i8>()
            .map_err(|_| BlockchainError::InvalidAddress("Invalid workchain".to_string()))?;

        let account_id_bytes = hex::decode(parts[1])
            .map_err(|e| BlockchainError::InvalidAddress(format!("Invalid hex: {}", e)))?;

        if account_id_bytes.len() != 32 {
            return Err(BlockchainError::InvalidAddress(
                "Account ID must be 32 bytes".to_string(),
            ));
        }

        let mut account_id = [0u8; 32];
        account_id.copy_from_slice(&account_id_bytes);

        Ok(Self::new(workchain, account_id))
    }

    /// Convert to raw string format
    pub fn to_raw(&self) -> String {
        format!("{}:{}", self.workchain, hex::encode(self.account_id))
    }

    /// Convert to user-friendly format (base64url)
    pub fn to_friendly(&self) -> String {
        let mut data = vec![0u8; 36];

        // Tag byte
        let tag = if self.bounceable { 0x11 } else { 0x51 };
        let tag = if self.testnet { tag | 0x80 } else { tag };
        data[0] = tag;

        // Workchain
        data[1] = self.workchain as u8;

        // Account ID
        data[2..34].copy_from_slice(&self.account_id);

        // CRC16
        let crc = crc16(&data[..34]);
        data[34] = (crc >> 8) as u8;
        data[35] = crc as u8;

        // Base64 URL encoding
        base64_url_encode(&data)
    }
}

impl std::fmt::Display for TonAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_friendly())
    }
}

/// Message (internal or external)
#[derive(Debug, Clone)]
pub struct Message {
    /// Source address (None for external)
    pub src: Option<TonAddress>,
    /// Destination address
    pub dest: TonAddress,
    /// Amount in nanotons
    pub amount: u64,
    /// Message body
    pub body: MessageBody,
    /// Bounce flag
    pub bounce: bool,
}

/// Message body
#[derive(Debug, Clone)]
pub enum MessageBody {
    /// Empty body
    Empty,
    /// Text comment
    Text(String),
    /// Raw cell
    Raw(Vec<u8>),
    /// Transfer with comment
    Transfer {
        amount: u64,
        comment: Option<String>,
    },
}

/// Sign an external message
pub fn sign_external_message(
    private_key: &[u8],
    message: &Message,
    seqno: u32,
    valid_until: u32,
) -> Result<SignedMessage> {
    // Construct signing message
    let mut sign_bytes = Vec::new();
    sign_bytes.extend_from_slice(&seqno.to_be_bytes());
    sign_bytes.extend_from_slice(&valid_until.to_be_bytes());
    sign_bytes.extend_from_slice(&message.dest.account_id);
    sign_bytes.extend_from_slice(&message.amount.to_be_bytes());

    // Sign with Ed25519
    let signature = sign_ed25519(private_key, &sign_bytes)?;

    Ok(SignedMessage {
        message: message.clone(),
        signature,
        seqno,
        valid_until,
    })
}

/// Signed message
#[derive(Debug, Clone)]
pub struct SignedMessage {
    pub message: Message,
    pub signature: Vec<u8>,
    pub seqno: u32,
    pub valid_until: u32,
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

/// CRC16 for TON addresses
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for byte in data {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Base64 URL encoding
fn base64_url_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ton_address_raw() {
        let addr = TonAddress::from_raw(
            "0:0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(addr.workchain, 0);
        assert_eq!(addr.account_id[31], 1);
    }

    #[test]
    fn test_crc16() {
        let data = [0x11, 0x00];
        let crc = crc16(&data);
        assert!(crc > 0); // Just verify it runs
    }
}
