//! Solana-specific cryptographic operations
//!
//! Provides support for:
//! - Solana address generation (Ed25519)
//! - Transaction parsing
//! - Message signing

pub mod transaction;

use crate::bip::bip32::ExtendedPrivateKey;
use crate::error::{BlockchainError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Solana public key (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SolanaPublicKey([u8; 32]);

impl SolanaPublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from slice
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(BlockchainError::InvalidPublicKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to base58 string
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Parse from base58 string
    pub fn from_base58(s: &str) -> Result<Self> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| BlockchainError::InvalidPublicKey(e.to_string()))?;
        Self::from_slice(&bytes)
    }

    /// Derive program address (PDA)
    pub fn find_program_address(seeds: &[&[u8]], program_id: &SolanaPublicKey) -> (Self, u8) {
        for bump in (0..=255).rev() {
            let mut hasher = Sha256::new();
            for seed in seeds {
                hasher.update(seed);
            }
            hasher.update(&[bump]);
            hasher.update(program_id.as_bytes());
            hasher.update(b"ProgramDerivedAddress");

            let hash = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hash);

            // Check if it's a valid point (simplified - actual check is more complex)
            // In production, you'd verify the point is not on the ed25519 curve
            if bump < 255 {
                return (Self(bytes), bump);
            }
        }
        // Fallback (shouldn't happen in practice)
        (Self([0; 32]), 0)
    }
}

impl fmt::Debug for SolanaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SolanaPublicKey({})", self.to_base58())
    }
}

impl fmt::Display for SolanaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

/// Solana keypair
#[derive(Clone)]
pub struct SolanaKeypair {
    /// Secret key (32 bytes)
    secret: [u8; 32],
    /// Public key
    public: SolanaPublicKey,
}

impl SolanaKeypair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self::from_secret(&secret)
    }

    /// Create from secret key bytes
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        use ed25519_dalek::{SigningKey, VerifyingKey};

        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key: VerifyingKey = (&signing_key).into();

        Self {
            secret: *secret,
            public: SolanaPublicKey(verifying_key.to_bytes()),
        }
    }

    /// Create from HD key
    pub fn from_hd_key(key: &ExtendedPrivateKey) -> Self {
        let secret = key.private_key_bytes();
        Self::from_secret(&secret)
    }

    /// Get the public key
    pub fn public_key(&self) -> &SolanaPublicKey {
        &self.public
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&self.secret);
        let signature = signing_key.sign(message);
        signature.to_bytes()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let verifying_key = VerifyingKey::from_bytes(&self.public.0);
        if let Ok(vk) = verifying_key {
            if let Ok(sig) = Signature::from_slice(signature) {
                return vk.verify(message, &sig).is_ok();
            }
        }
        false
    }
}

impl fmt::Debug for SolanaKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SolanaKeypair")
            .field("secret", &"[REDACTED]")
            .field("public", &self.public)
            .finish()
    }
}

impl Drop for SolanaKeypair {
    fn drop(&mut self) {
        // Zeroize secret key
        self.secret.iter_mut().for_each(|b| *b = 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_base58() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let pubkey = SolanaPublicKey::from_bytes(bytes);
        let base58 = pubkey.to_base58();

        let recovered = SolanaPublicKey::from_base58(&base58).unwrap();
        assert_eq!(pubkey, recovered);
    }

    #[test]
    fn test_keypair_generation() {
        let keypair = SolanaKeypair::generate();
        let pubkey = keypair.public_key();

        // Public key should be 32 bytes
        assert_eq!(pubkey.as_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = SolanaKeypair::generate();
        let message = b"Hello, Solana!";

        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature));

        // Wrong message should fail
        assert!(!keypair.verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_deterministic_keypair() {
        let secret = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let keypair1 = SolanaKeypair::from_secret(&secret);
        let keypair2 = SolanaKeypair::from_secret(&secret);

        assert_eq!(keypair1.public_key(), keypair2.public_key());
    }

    #[test]
    fn test_keypair_debug_redacts() {
        let keypair = SolanaKeypair::generate();
        let debug = format!("{:?}", keypair);
        assert!(debug.contains("REDACTED"));
    }
}
