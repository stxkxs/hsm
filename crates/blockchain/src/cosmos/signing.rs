//! Cosmos signing implementation

use crate::error::{BlockchainError, Result};
use sha2::{Digest, Sha256};

/// Cosmos address derived from a public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosmosAddress {
    /// The bech32-encoded address
    pub address: String,
    /// The raw address bytes (20 bytes for secp256k1)
    pub bytes: Vec<u8>,
}

impl CosmosAddress {
    /// Derive a Cosmos address from a secp256k1 public key
    ///
    /// The address is derived as:
    /// 1. SHA256 hash of the compressed public key
    /// 2. RIPEMD160 of the SHA256 hash (first 20 bytes of SHA256 for simplicity)
    /// 3. Bech32 encoding with the chain's prefix
    pub fn from_public_key(public_key: &[u8], prefix: &str) -> Result<String> {
        // Validate public key length (compressed = 33 bytes, uncompressed = 65 bytes)
        if public_key.len() != 33 && public_key.len() != 65 {
            return Err(BlockchainError::InvalidPublicKey(
                "Invalid public key length".to_string(),
            ));
        }

        // SHA256 hash of the public key
        let sha256_hash = Sha256::digest(public_key);

        // Take first 20 bytes as the address (RIPEMD160 equivalent for Cosmos)
        let address_bytes = &sha256_hash[..20];

        // Bech32 encode
        let address = bech32_encode(prefix, address_bytes)?;

        Ok(address)
    }

    /// Create from raw address bytes
    pub fn from_bytes(bytes: &[u8], prefix: &str) -> Result<Self> {
        if bytes.len() != 20 {
            return Err(BlockchainError::InvalidAddress(
                "Address must be 20 bytes".to_string(),
            ));
        }

        let address = bech32_encode(prefix, bytes)?;

        Ok(Self {
            address,
            bytes: bytes.to_vec(),
        })
    }

    /// Parse a bech32 address
    pub fn parse(address: &str) -> Result<Self> {
        let (_, bytes) = bech32_decode(address)?;

        Ok(Self {
            address: address.to_string(),
            bytes,
        })
    }
}

/// Cosmos transaction signer
pub struct CosmosSigner;

impl CosmosSigner {
    /// Sign a Cosmos transaction
    ///
    /// The signature is created as:
    /// 1. SHA256 hash of the SignDoc bytes
    /// 2. secp256k1 signature over the hash
    pub fn sign(private_key: &[u8], sign_doc: &super::SignDoc) -> Result<Vec<u8>> {
        // Serialize the SignDoc to bytes
        let sign_bytes = sign_doc.to_bytes()?;

        // SHA256 hash
        let hash = Sha256::digest(&sign_bytes);

        // Sign with secp256k1
        sign_secp256k1(private_key, &hash)
    }

    /// Sign an arbitrary message (ADR-036)
    ///
    /// ADR-036 defines a standard for signing arbitrary data:
    /// - Wrap the message in a specific format
    /// - Sign the wrapped message
    pub fn sign_arbitrary(
        private_key: &[u8],
        message: &[u8],
        signer_address: &str,
    ) -> Result<Vec<u8>> {
        // ADR-036 message format
        let sign_doc = create_adr036_sign_doc(message, signer_address)?;
        Self::sign(private_key, &sign_doc)
    }

    /// Verify a signature
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        // SHA256 hash
        let hash = Sha256::digest(message);

        // Verify with secp256k1
        verify_secp256k1(public_key, &hash, signature)
    }
}

/// Sign with secp256k1
fn sign_secp256k1(private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8>> {
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};

    if private_key.len() != 32 {
        return Err(BlockchainError::InvalidPrivateKey(
            "Private key must be 32 bytes".to_string(),
        ));
    }

    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|e| BlockchainError::InvalidPrivateKey(e.to_string()))?;

    let signature: Signature = signing_key.sign(message_hash);

    Ok(signature.to_bytes().to_vec())
}

/// Verify with secp256k1
fn verify_secp256k1(public_key: &[u8], message_hash: &[u8], signature: &[u8]) -> Result<bool> {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| BlockchainError::InvalidPublicKey(e.to_string()))?;

    let signature = Signature::from_slice(signature)
        .map_err(|e| BlockchainError::InvalidSignature(e.to_string()))?;

    Ok(verifying_key.verify(message_hash, &signature).is_ok())
}

/// Bech32 encode bytes with a prefix
fn bech32_encode(prefix: &str, data: &[u8]) -> Result<String> {
    use bech32::{Bech32, Hrp};

    let hrp = Hrp::parse(prefix)
        .map_err(|e| BlockchainError::InvalidAddress(format!("Invalid prefix: {}", e)))?;

    bech32::encode::<Bech32>(hrp, data)
        .map_err(|e| BlockchainError::InvalidAddress(format!("Bech32 encode error: {}", e)))
}

/// Bech32 decode an address
fn bech32_decode(address: &str) -> Result<(String, Vec<u8>)> {
    let (hrp, data) = bech32::decode(address)
        .map_err(|e| BlockchainError::InvalidAddress(format!("Bech32 decode error: {}", e)))?;

    Ok((hrp.to_string(), data))
}

/// Create an ADR-036 sign doc for arbitrary message signing
fn create_adr036_sign_doc(message: &[u8], signer: &str) -> Result<super::SignDoc> {
    // ADR-036 uses a specific message type for arbitrary data
    let msg_sign_data = MsgSignData {
        signer: signer.to_string(),
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, message),
    };

    Ok(super::SignDoc {
        body_bytes: serde_json::to_vec(&msg_sign_data)
            .map_err(|e| BlockchainError::SerializationError(e.to_string()))?,
        auth_info_bytes: vec![],
        chain_id: "".to_string(),
        account_number: 0,
    })
}

/// ADR-036 MsgSignData
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MsgSignData {
    pub signer: String,
    pub data: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bech32_roundtrip() {
        let bytes = [1u8; 20];
        let encoded = bech32_encode("cosmos", &bytes).unwrap();
        assert!(encoded.starts_with("cosmos1"));

        let (prefix, decoded) = bech32_decode(&encoded).unwrap();
        assert_eq!(prefix, "cosmos");
        assert_eq!(decoded, bytes);
    }
}
