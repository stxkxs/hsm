//! EIP-191: Personal message signing
//!
//! Implements the Ethereum personal message signing standard.
//!
//! # Message Format
//!
//! ```text
//! "\x19Ethereum Signed Message:\n" + len(message) + message
//! ```
//!
//! # Example
//!
//! ```rust
//! use hsm_blockchain::ethereum::eip191::PersonalMessage;
//!
//! let message = PersonalMessage::new(b"Hello, Ethereum!");
//! let hash = message.hash();
//! ```

use crate::error::{BlockchainError, Result};
use k256::ecdsa::{
    signature::hazmat::PrehashVerifier, RecoveryId, Signature, SigningKey, VerifyingKey,
};
use sha3::{Digest, Keccak256};

/// EIP-191 message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eip191Version {
    /// Version 0x00: Data with intended validator
    Data = 0x00,
    /// Version 0x01: Structured data (EIP-712)
    StructuredData = 0x01,
    /// Version 0x45: Personal message (most common)
    PersonalMessage = 0x45, // 'E' in ASCII
}

/// EIP-191 message wrapper
pub struct Eip191Message {
    /// Version byte
    version: Eip191Version,
    /// Message data
    data: Vec<u8>,
    /// Optional validator address (for version 0x00)
    validator: Option<[u8; 20]>,
}

impl Eip191Message {
    /// Create a new EIP-191 message
    pub fn new(version: Eip191Version, data: Vec<u8>) -> Self {
        Self {
            version,
            data,
            validator: None,
        }
    }

    /// Create a data message with validator (version 0x00)
    pub fn data_with_validator(data: Vec<u8>, validator: [u8; 20]) -> Self {
        Self {
            version: Eip191Version::Data,
            data,
            validator: Some(validator),
        }
    }

    /// Get the hash of the message
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();

        match self.version {
            Eip191Version::PersonalMessage => {
                // Already handled by PersonalMessage
                hasher.update(&[0x19, self.version as u8]);
                hasher.update(&self.data);
            }
            Eip191Version::Data => {
                hasher.update(&[0x19, 0x00]);
                if let Some(validator) = &self.validator {
                    hasher.update(validator);
                }
                hasher.update(&self.data);
            }
            Eip191Version::StructuredData => {
                // EIP-712 style
                hasher.update(&[0x19, 0x01]);
                hasher.update(&self.data);
            }
        }

        hasher.finalize().into()
    }
}

/// Personal message for Ethereum signing (most common EIP-191 usage)
#[derive(Debug, Clone)]
pub struct PersonalMessage {
    /// Raw message bytes
    message: Vec<u8>,
}

impl PersonalMessage {
    /// Ethereum personal message prefix
    pub const PREFIX: &'static str = "\x19Ethereum Signed Message:\n";

    /// Create a new personal message from bytes
    pub fn new(message: &[u8]) -> Self {
        Self {
            message: message.to_vec(),
        }
    }

    /// Create from a string
    pub fn from_string(message: &str) -> Self {
        Self::new(message.as_bytes())
    }

    /// Get the raw message
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Get the prefixed message bytes
    pub fn prefixed_message(&self) -> Vec<u8> {
        let len_str = self.message.len().to_string();
        let mut prefixed =
            Vec::with_capacity(Self::PREFIX.len() + len_str.len() + self.message.len());
        prefixed.extend_from_slice(Self::PREFIX.as_bytes());
        prefixed.extend_from_slice(len_str.as_bytes());
        prefixed.extend_from_slice(&self.message);
        prefixed
    }

    /// Hash the personal message (Keccak-256)
    pub fn hash(&self) -> [u8; 32] {
        let prefixed = self.prefixed_message();
        Keccak256::digest(&prefixed).into()
    }

    /// Sign the message with a private key
    pub fn sign(&self, signing_key: &SigningKey) -> Result<RecoverableSignature> {
        let hash = self.hash();

        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| BlockchainError::CryptoError(e.to_string()))?;

        Ok(RecoverableSignature {
            signature,
            recovery_id,
        })
    }

    /// Verify a signature
    pub fn verify(&self, signature: &Signature, public_key: &VerifyingKey) -> bool {
        let hash = self.hash();
        public_key.verify_prehash(&hash, signature).is_ok()
    }

    /// Recover the public key from a signature
    pub fn recover_public_key(&self, sig: &RecoverableSignature) -> Result<VerifyingKey> {
        let hash = self.hash();
        VerifyingKey::recover_from_prehash(&hash, &sig.signature, sig.recovery_id)
            .map_err(|e| BlockchainError::CryptoError(e.to_string()))
    }
}

/// Recoverable signature with recovery ID
#[derive(Debug, Clone)]
pub struct RecoverableSignature {
    /// The ECDSA signature
    pub signature: Signature,
    /// Recovery ID (0 or 1)
    pub recovery_id: RecoveryId,
}

impl RecoverableSignature {
    /// Create from components
    pub fn from_components(r: [u8; 32], s: [u8; 32], v: u8) -> Result<Self> {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&r);
        sig_bytes[32..].copy_from_slice(&s);

        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| BlockchainError::InvalidSignature(e.to_string()))?;

        // v is typically 27 or 28 for Ethereum, or 0/1 internally
        let recovery_id = if v >= 27 {
            RecoveryId::try_from(v - 27)
                .map_err(|e| BlockchainError::InvalidSignature(e.to_string()))?
        } else {
            RecoveryId::try_from(v).map_err(|e| BlockchainError::InvalidSignature(e.to_string()))?
        };

        Ok(Self {
            signature,
            recovery_id,
        })
    }

    /// Get r component
    pub fn r(&self) -> [u8; 32] {
        let bytes = self.signature.to_bytes();
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        r
    }

    /// Get s component
    pub fn s(&self) -> [u8; 32] {
        let bytes = self.signature.to_bytes();
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[32..]);
        s
    }

    /// Get v component (Ethereum format: 27 or 28)
    pub fn v(&self) -> u8 {
        27 + self.recovery_id.to_byte()
    }

    /// Get v component for EIP-155 (with chain ID)
    pub fn v_eip155(&self, chain_id: u64) -> u64 {
        chain_id * 2 + 35 + self.recovery_id.to_byte() as u64
    }

    /// Convert to bytes (r || s || v)
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        let sig_bytes = self.signature.to_bytes();
        bytes[..64].copy_from_slice(&sig_bytes);
        bytes[64] = self.v();
        bytes
    }

    /// Convert to hex string (0x prefixed)
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::SecretKey;

    fn generate_key() -> SigningKey {
        let secret = SecretKey::random(&mut rand::thread_rng());
        SigningKey::from(secret)
    }

    #[test]
    fn test_personal_message_hash() {
        let message = PersonalMessage::from_string("Hello, World!");
        let hash = message.hash();

        // The hash should be deterministic
        let hash2 = message.hash();
        assert_eq!(hash, hash2);

        // Should be 32 bytes
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_personal_message_prefix() {
        let message = PersonalMessage::from_string("Hello");
        let prefixed = message.prefixed_message();

        // Check prefix
        assert!(prefixed.starts_with(PersonalMessage::PREFIX.as_bytes()));

        // Check length encoding
        let expected_len = "5"; // length of "Hello"
        let len_start = PersonalMessage::PREFIX.len();
        let len_bytes = &prefixed[len_start..len_start + 1];
        assert_eq!(len_bytes, expected_len.as_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let signing_key = generate_key();
        let verifying_key = signing_key.verifying_key();

        let message = PersonalMessage::from_string("Test message");
        let sig = message.sign(&signing_key).unwrap();

        // Verify should succeed with correct key
        assert!(message.verify(&sig.signature, verifying_key));

        // Verify should fail with wrong message
        let wrong_message = PersonalMessage::from_string("Wrong message");
        assert!(!wrong_message.verify(&sig.signature, verifying_key));
    }

    #[test]
    fn test_recover_public_key() {
        let signing_key = generate_key();
        let expected_verifying_key = signing_key.verifying_key();

        let message = PersonalMessage::from_string("Recovery test");
        let sig = message.sign(&signing_key).unwrap();

        let recovered = message.recover_public_key(&sig).unwrap();
        assert_eq!(recovered, *expected_verifying_key);
    }

    #[test]
    fn test_signature_components() {
        let signing_key = generate_key();
        let message = PersonalMessage::from_string("Components test");
        let sig = message.sign(&signing_key).unwrap();

        // v should be 27 or 28
        assert!(sig.v() == 27 || sig.v() == 28);

        // r and s should be 32 bytes
        assert_eq!(sig.r().len(), 32);
        assert_eq!(sig.s().len(), 32);

        // to_bytes should be 65 bytes
        assert_eq!(sig.to_bytes().len(), 65);
    }

    #[test]
    fn test_signature_from_components() {
        let signing_key = generate_key();
        let message = PersonalMessage::from_string("Components test");
        let sig = message.sign(&signing_key).unwrap();

        // Reconstruct from components
        let reconstructed =
            RecoverableSignature::from_components(sig.r(), sig.s(), sig.v()).unwrap();

        assert_eq!(sig.r(), reconstructed.r());
        assert_eq!(sig.s(), reconstructed.s());
        assert_eq!(sig.v(), reconstructed.v());
    }

    #[test]
    fn test_eip155_v() {
        let signing_key = generate_key();
        let message = PersonalMessage::from_string("EIP-155 test");
        let sig = message.sign(&signing_key).unwrap();

        // Ethereum mainnet (chain ID 1)
        let v_mainnet = sig.v_eip155(1);
        assert!(v_mainnet == 37 || v_mainnet == 38);

        // Polygon (chain ID 137)
        let v_polygon = sig.v_eip155(137);
        assert!(v_polygon == 309 || v_polygon == 310);
    }
}
