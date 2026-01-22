//! secp256k1 ECDSA and Schnorr signatures.
//!
//! Provides cryptographic operations using the secp256k1 curve, which is the
//! standard curve for Bitcoin, Ethereum, and most blockchain applications.
//!
//! # Signature Schemes
//!
//! - **ECDSA**: Standard signature scheme for Bitcoin/Ethereum transactions
//! - **Schnorr**: BIP-340 Schnorr signatures (Bitcoin Taproot)
//!
//! # Use Cases
//!
//! - Bitcoin transaction signing
//! - Ethereum transaction signing
//! - General Web3/blockchain applications
//! - BIP-340 Taproot (Schnorr signatures)

use crate::{CryptoError, KeyMaterial, Result};
use k256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    schnorr,
};
use rand_core::OsRng;

/// secp256k1 cryptographic engine.
///
/// Implements ECDSA and Schnorr signatures on the secp256k1 curve.
///
/// # Security
///
/// - secp256k1 provides ~128-bit security level
/// - ECDSA uses randomized nonces (nonce reuse is catastrophic)
/// - Schnorr signatures are deterministic per BIP-340
///
/// # Performance
///
/// Typical performance on modern hardware:
/// - ECDSA sign: ~5,000 ops/sec
/// - ECDSA verify: ~3,000 ops/sec
/// - Schnorr sign: ~6,000 ops/sec
/// - Schnorr verify: ~4,000 ops/sec
pub struct Secp256k1Engine;

impl Secp256k1Engine {
    /// Generates a secp256k1 keypair for ECDSA.
    ///
    /// # Returns
    ///
    /// Tuple of (32-byte private key, 33-byte compressed public key)
    ///
    /// # Examples
    ///
    /// ```
    /// use hsm_crypto_engine::asymmetric::secp256k1::Secp256k1Engine;
    ///
    /// let (private_key, public_key) = Secp256k1Engine::generate_keypair().unwrap();
    /// assert_eq!(private_key.as_bytes().len(), 32);
    /// assert_eq!(public_key.len(), 33); // Compressed public key
    /// ```
    pub fn generate_keypair() -> Result<(KeyMaterial, Vec<u8>)> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let private_bytes = signing_key.to_bytes();
        let public_bytes = verifying_key.to_sec1_bytes().to_vec();

        Ok((
            KeyMaterial::from_bytes(private_bytes.to_vec()),
            public_bytes,
        ))
    }

    /// Generates a secp256k1 keypair with uncompressed public key.
    ///
    /// Some applications (especially Ethereum) use uncompressed public keys.
    ///
    /// # Returns
    ///
    /// Tuple of (32-byte private key, 65-byte uncompressed public key)
    pub fn generate_keypair_uncompressed() -> Result<(KeyMaterial, Vec<u8>)> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let private_bytes = signing_key.to_bytes();
        let public_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        Ok((
            KeyMaterial::from_bytes(private_bytes.to_vec()),
            public_bytes,
        ))
    }

    /// Derives the public key from a private key.
    ///
    /// # Arguments
    ///
    /// * `private_key` - 32-byte secp256k1 private key
    ///
    /// # Returns
    ///
    /// 33-byte compressed public key
    pub fn derive_public_key(private_key: &KeyMaterial) -> Result<Vec<u8>> {
        let signing_key = SigningKey::from_bytes(private_key.as_bytes().into())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let verifying_key = signing_key.verifying_key();
        Ok(verifying_key.to_sec1_bytes().to_vec())
    }

    /// Signs a message using secp256k1 ECDSA with SHA-256.
    ///
    /// # Arguments
    ///
    /// * `key` - secp256k1 private key (32 bytes)
    /// * `message` - Data to sign (will be hashed with SHA-256)
    ///
    /// # Returns
    ///
    /// 64-byte ECDSA signature (r || s components in low-S normalized form)
    ///
    /// # Security
    ///
    /// Uses RFC 6979 deterministic nonce generation which is safe against
    /// nonce reuse attacks while remaining deterministic.
    pub fn sign_ecdsa(key: &KeyMaterial, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::from_bytes(key.as_bytes().into())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let signature: Signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verifies a secp256k1 ECDSA signature.
    ///
    /// # Arguments
    ///
    /// * `public_key` - secp256k1 public key (33 or 65 bytes)
    /// * `message` - Original data that was signed
    /// * `signature` - 64-byte ECDSA signature to verify
    ///
    /// # Returns
    ///
    /// `true` if signature is valid
    pub fn verify_ecdsa(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let sig = Signature::from_bytes(signature.into())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        verifying_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Generates a keypair for BIP-340 Schnorr signatures.
    ///
    /// # Returns
    ///
    /// Tuple of (32-byte private key, 32-byte x-only public key)
    ///
    /// # Note
    ///
    /// BIP-340 uses x-only public keys (32 bytes) instead of full points.
    pub fn generate_schnorr_keypair() -> Result<(KeyMaterial, Vec<u8>)> {
        let signing_key = schnorr::SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let private_bytes = signing_key.to_bytes();
        let public_bytes = verifying_key.to_bytes().to_vec();

        Ok((
            KeyMaterial::from_bytes(private_bytes.to_vec()),
            public_bytes,
        ))
    }

    /// Signs a message using BIP-340 Schnorr signatures.
    ///
    /// # Arguments
    ///
    /// * `key` - secp256k1 private key (32 bytes)
    /// * `message` - 32-byte message hash (typically a tagged hash)
    ///
    /// # Returns
    ///
    /// 64-byte Schnorr signature
    ///
    /// # Use Cases
    ///
    /// - Bitcoin Taproot transactions
    /// - MuSig2 multi-signatures
    pub fn sign_schnorr(key: &KeyMaterial, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = schnorr::SigningKey::from_bytes(key.as_bytes())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let signature: schnorr::Signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verifies a BIP-340 Schnorr signature.
    ///
    /// # Arguments
    ///
    /// * `public_key` - 32-byte x-only public key
    /// * `message` - Original 32-byte message hash
    /// * `signature` - 64-byte Schnorr signature
    ///
    /// # Returns
    ///
    /// `true` if signature is valid
    pub fn verify_schnorr(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        let verifying_key = schnorr::VerifyingKey::from_bytes(public_key)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let sig = schnorr::Signature::try_from(signature)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        verifying_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_sign_verify() {
        let (private_key, public_key) = Secp256k1Engine::generate_keypair().unwrap();
        let message = b"test message for secp256k1";

        let signature = Secp256k1Engine::sign_ecdsa(&private_key, message).unwrap();
        assert_eq!(signature.len(), 64);

        let valid = Secp256k1Engine::verify_ecdsa(&public_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_ecdsa_uncompressed_pubkey() {
        let (private_key, public_key) = Secp256k1Engine::generate_keypair_uncompressed().unwrap();
        assert_eq!(public_key.len(), 65);

        let message = b"test with uncompressed key";
        let signature = Secp256k1Engine::sign_ecdsa(&private_key, message).unwrap();
        let valid = Secp256k1Engine::verify_ecdsa(&public_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_ecdsa_wrong_message() {
        let (private_key, public_key) = Secp256k1Engine::generate_keypair().unwrap();
        let message = b"original message";
        let wrong_message = b"different message";

        let signature = Secp256k1Engine::sign_ecdsa(&private_key, message).unwrap();
        let result = Secp256k1Engine::verify_ecdsa(&public_key, wrong_message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_public_key() {
        let (private_key, public_key) = Secp256k1Engine::generate_keypair().unwrap();
        let derived = Secp256k1Engine::derive_public_key(&private_key).unwrap();
        assert_eq!(public_key, derived);
    }

    #[test]
    fn test_schnorr_sign_verify() {
        let (private_key, public_key) = Secp256k1Engine::generate_schnorr_keypair().unwrap();
        assert_eq!(public_key.len(), 32); // x-only public key

        let message = b"test schnorr message 32 bytes!!"; // 32 bytes
        let signature = Secp256k1Engine::sign_schnorr(&private_key, message).unwrap();
        assert_eq!(signature.len(), 64);

        let valid = Secp256k1Engine::verify_schnorr(&public_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_schnorr_wrong_message() {
        let (private_key, public_key) = Secp256k1Engine::generate_schnorr_keypair().unwrap();
        let message = b"original schnorr msg 32 bytes!!";
        let wrong_message = b"different schnorr msg 32 bytes!";

        let signature = Secp256k1Engine::sign_schnorr(&private_key, message).unwrap();
        let result = Secp256k1Engine::verify_schnorr(&public_key, wrong_message, &signature);
        assert!(result.is_err());
    }
}
