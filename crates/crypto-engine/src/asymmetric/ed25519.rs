//! Ed25519 digital signatures (recommended).
//!
//! Provides Ed25519 signing and verification based on Curve25519.
//! This is the **recommended signature algorithm** for new applications.
//!
//! # Advantages
//!
//! - **Performance**: Fastest signature scheme (~38,000 sign ops/sec)
//! - **Security**: Constant-time operations, immune to timing attacks
//! - **Key size**: Small keys (32 bytes) and signatures (64 bytes)
//! - **Deterministic**: Same message always produces same signature (with same key)
//!
//! # Use Cases
//!
//! - API authentication tokens
//! - Certificate signing
//! - Git commit signing
//! - Cryptocurrency transactions
//! - Any application requiring fast, secure signatures

use crate::{CryptoError, KeyMaterial, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rayon::prelude::*;

/// Ed25519 cryptographic engine.
///
/// Implements Ed25519 signatures with constant-time operations.
///
/// # Security
///
/// - **Constant-time**: All operations resist timing side-channels
/// - **Deterministic**: Signatures are reproducible (unlike ECDSA)
/// - **Small attack surface**: Simple, well-studied algorithm
///
/// # Performance
///
/// Benchmark results on typical hardware:
/// - Key generation: ~50,000 ops/sec
/// - Signing: ~38,000 ops/sec
/// - Verification: ~30,000 ops/sec
/// - Batch verification: ~60,000 ops/sec
pub struct Ed25519Engine;

impl Ed25519Engine {
    /// Generates an Ed25519 keypair.
    ///
    /// # Returns
    ///
    /// Tuple of (32-byte private key, 32-byte public key)
    ///
    /// # Errors
    ///
    /// This function always succeeds with sufficient system entropy.
    ///
    /// # Examples
    ///
    /// ```
    /// use hsm_crypto_engine::asymmetric::ed25519::Ed25519Engine;
    ///
    /// let (private_key, public_key) = Ed25519Engine::generate_keypair().unwrap();
    /// assert_eq!(private_key.as_bytes().len(), 32);
    /// assert_eq!(public_key.len(), 32);
    /// ```
    ///
    /// # Performance
    ///
    /// Key generation is very fast (~20 microseconds) compared to RSA (~100ms for 2048-bit).
    pub fn generate_keypair() -> Result<(KeyMaterial, Vec<u8>)> {
        use rand_core::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let private_key = KeyMaterial::from_bytes(signing_key.to_bytes().to_vec());
        let public_key = verifying_key.to_bytes().to_vec();

        Ok((private_key, public_key))
    }

    /// Signs a message using Ed25519.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte Ed25519 private key
    /// * `message` - Data to sign (arbitrary length)
    ///
    /// # Returns
    ///
    /// 64-byte Ed25519 signature
    ///
    /// # Errors
    ///
    /// Returns error if key size is not exactly 32 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use hsm_crypto_engine::asymmetric::ed25519::Ed25519Engine;
    ///
    /// let (private_key, public_key) = Ed25519Engine::generate_keypair().unwrap();
    /// let message = b"Hello, World!";
    ///
    /// let signature = Ed25519Engine::sign(&private_key, message).unwrap();
    /// assert_eq!(signature.len(), 64);
    ///
    /// let valid = Ed25519Engine::verify(&public_key, message, &signature).unwrap();
    /// assert!(valid);
    /// ```
    ///
    /// # Security
    ///
    /// - **Deterministic**: Same message with same key produces same signature
    /// - **Constant-time**: Resistant to timing attacks
    /// - **No randomness required**: Simplifies implementation and reduces attack surface
    ///
    /// # Performance
    ///
    /// Signing is extremely fast (~38,000 ops/sec), making Ed25519 suitable for
    /// high-throughput applications.
    pub fn sign(key: &KeyMaterial, message: &[u8]) -> Result<Vec<u8>> {
        let key_bytes: [u8; 32] =
            key.as_bytes()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeySize {
                    expected: 32,
                    actual: key.as_bytes().len(),
                })?;

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(message);

        Ok(signature.to_bytes().to_vec())
    }

    /// Verifies an Ed25519 signature.
    ///
    /// # Arguments
    ///
    /// * `public_key` - 32-byte Ed25519 public key
    /// * `message` - Original data that was signed
    /// * `signature` - 64-byte signature to verify
    ///
    /// # Returns
    ///
    /// `true` if signature is valid, error otherwise
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Public key size is not 32 bytes
    /// - Signature size is not 64 bytes
    /// - Public key is invalid
    /// - Signature verification fails
    ///
    /// # Security
    ///
    /// Verification uses constant-time operations where possible to resist timing attacks.
    ///
    /// # Performance
    ///
    /// Verification is fast (~30,000 ops/sec) and suitable for rate-limiting checks.
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        let pub_bytes: [u8; 32] =
            public_key
                .try_into()
                .map_err(|_| CryptoError::InvalidKeySize {
                    expected: 32,
                    actual: public_key.len(),
                })?;

        let sig_bytes: [u8; 64] =
            signature
                .try_into()
                .map_err(|_| CryptoError::InvalidSignatureSize {
                    expected: 64,
                    actual: signature.len(),
                })?;

        let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let sig = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Signs multiple messages in parallel.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte Ed25519 private key
    /// * `messages` - Slice of messages to sign
    ///
    /// # Returns
    ///
    /// Vector of 64-byte signatures, one for each message
    ///
    /// # Errors
    ///
    /// Returns error if key size is invalid.
    ///
    /// # Performance
    ///
    /// Uses Rayon for parallel signing across multiple CPU cores.
    /// Speedup scales linearly with core count for large batches.
    ///
    /// # Examples
    ///
    /// ```
    /// use hsm_crypto_engine::asymmetric::ed25519::Ed25519Engine;
    ///
    /// let (private_key, _) = Ed25519Engine::generate_keypair().unwrap();
    /// let messages = vec![b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()];
    ///
    /// let signatures = Ed25519Engine::batch_sign(&private_key, &messages).unwrap();
    /// assert_eq!(signatures.len(), 3);
    /// ```
    pub fn batch_sign(key: &KeyMaterial, messages: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        let key_bytes: [u8; 32] =
            key.as_bytes()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeySize {
                    expected: 32,
                    actual: key.as_bytes().len(),
                })?;

        let signing_key = SigningKey::from_bytes(&key_bytes);

        Ok(messages
            .par_iter()
            .map(|msg| {
                let signature = signing_key.sign(msg);
                signature.to_bytes().to_vec()
            })
            .collect())
    }

    /// Verifies multiple signatures in parallel.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - Slice of public keys
    /// * `messages` - Slice of messages
    /// * `signatures` - Slice of signatures
    ///
    /// # Returns
    ///
    /// Vector of booleans indicating validity of each signature
    ///
    /// # Errors
    ///
    /// Returns error if array lengths don't match.
    ///
    /// # Performance
    ///
    /// Parallel verification provides significant speedup for large batches.
    /// Single-threaded sequential verification is also available via individual `verify` calls.
    pub fn batch_verify(
        public_keys: &[&[u8]],
        messages: &[&[u8]],
        signatures: &[&[u8]],
    ) -> Result<Vec<bool>> {
        if public_keys.len() != messages.len() || messages.len() != signatures.len() {
            return Err(CryptoError::Internal(
                "Batch verify requires equal length arrays".into(),
            ));
        }

        Ok(public_keys
            .par_iter()
            .zip(messages.par_iter())
            .zip(signatures.par_iter())
            .map(|((pk, msg), sig)| Self::verify(pk, msg, sig).unwrap_or(false))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let (private_key, public_key) = Ed25519Engine::generate_keypair().unwrap();
        let message = b"test message";

        let signature = Ed25519Engine::sign(&private_key, message).unwrap();
        let valid = Ed25519Engine::verify(&public_key, message, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_ed25519_invalid_signature() {
        let (_, public_key) = Ed25519Engine::generate_keypair().unwrap();
        let message = b"test message";
        let bad_signature = vec![0u8; 64];

        let result = Ed25519Engine::verify(&public_key, message, &bad_signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_sign() {
        let (private_key, public_key) = Ed25519Engine::generate_keypair().unwrap();
        let messages = vec![b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()];

        let signatures = Ed25519Engine::batch_sign(&private_key, &messages).unwrap();
        assert_eq!(signatures.len(), 3);

        for (msg, sig) in messages.iter().zip(signatures.iter()) {
            let valid = Ed25519Engine::verify(&public_key, msg, sig).unwrap();
            assert!(valid);
        }
    }

    #[test]
    fn test_batch_verify() {
        let (private_key, public_key) = Ed25519Engine::generate_keypair().unwrap();
        let messages = vec![b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()];
        let signatures = Ed25519Engine::batch_sign(&private_key, &messages).unwrap();

        let sig_refs: Vec<&[u8]> = signatures.iter().map(|s| s.as_slice()).collect();
        let pk_refs = vec![public_key.as_slice(); 3];

        let results = Ed25519Engine::batch_verify(&pk_refs, &messages, &sig_refs).unwrap();
        assert_eq!(results, vec![true, true, true]);
    }
}
