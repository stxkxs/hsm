//! RSA digital signatures (legacy support).
//!
//! Provides RSA signing and verification with PKCS#1 v1.5 and PSS padding schemes.
//!
//! # Security Warning
//!
//! **RUSTSEC-2023-0071**: The RSA crate is vulnerable to the Marvin Attack, a timing
//! side-channel that can leak private key information. For new deployments, prefer
//! Ed25519 or ECDSA which have constant-time guarantees.
//!
//! # Deprecation Notice
//!
//! RSA usage is deprecated for new applications. All RSA operations emit:
//! - A warning log message recommending Ed25519/ECDSA
//! - Metrics tracking RSA vs modern algorithm usage
//!
//! # Recommendations
//!
//! - **New applications**: Use Ed25519 (fastest, most secure)
//! - **Legacy interop**: Use RSA-PSS if possible (more secure than PKCS#1 v1.5)
//! - **Key size**: Use 2048 bits minimum, 3072+ for long-term security

use crate::{CryptoError, KeyMaterial, Result};
use pkcs1::DecodeRsaPublicKey;
use pkcs8::DecodePrivateKey;
use rand_core::OsRng;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::pss::{SigningKey as PssSigningKey, VerifyingKey as PssVerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::sync::atomic::{AtomicBool, Ordering};

/// Static flag to control deprecation warning frequency (warn once per session)
static RSA_DEPRECATION_WARNED: AtomicBool = AtomicBool::new(false);

/// Log a deprecation warning for RSA usage (once per session)
fn log_rsa_deprecation_warning(operation: &str) {
    // Only warn once per session to avoid log spam
    if !RSA_DEPRECATION_WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            operation = operation,
            advisory = "RUSTSEC-2023-0071",
            "RSA usage is deprecated due to Marvin Attack vulnerability. \
             Consider migrating to Ed25519 or ECDSA for new key generation. \
             See: https://rustsec.org/advisories/RUSTSEC-2023-0071"
        );
    }

    // Always increment metrics for monitoring
    metrics::counter!("crypto.rsa.usage", "operation" => operation.to_string()).increment(1);
    metrics::counter!("crypto.algorithm.legacy").increment(1);
}

/// RSA cryptographic engine.
///
/// Provides RSA key generation, signing, and verification with multiple padding schemes.
///
/// # Security
///
/// - **Marvin Attack**: Timing side-channel vulnerability (RUSTSEC-2023-0071)
/// - **Recommended alternative**: Ed25519 or ECDSA for new applications
/// - **If RSA required**: Use PSS padding over PKCS#1 v1.5
///
/// # Performance
///
/// RSA is significantly slower than elliptic curve alternatives:
/// - RSA-2048 sign: ~1,000 ops/sec
/// - RSA-2048 verify: ~20,000 ops/sec
/// - Compare to Ed25519 sign: ~38,000 ops/sec
pub struct RsaEngine;

impl RsaEngine {
    /// Generates an RSA keypair.
    ///
    /// # Arguments
    ///
    /// * `bits` - Key size in bits (minimum 2048, recommended 3072+)
    ///
    /// # Returns
    ///
    /// Tuple of (private key in PKCS#8 DER, public key in PKCS#1 DER)
    ///
    /// # Errors
    ///
    /// Returns error if key generation fails or serialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use hsm_crypto_engine::asymmetric::rsa::RsaEngine;
    ///
    /// let (private_key, public_key) = RsaEngine::generate_keypair(2048).unwrap();
    /// assert_eq!(private_key.as_bytes().len() > 0, true);
    /// ```
    ///
    /// # Security
    ///
    /// - Minimum 2048 bits for short-term security
    /// - 3072 bits recommended for long-term security (post-2030)
    /// - 4096 bits for maximum security (performance penalty)
    ///
    /// # Performance
    ///
    /// Key generation is expensive:
    /// - 2048-bit: ~100ms
    /// - 3072-bit: ~500ms
    /// - 4096-bit: ~2000ms
    pub fn generate_keypair(bits: usize) -> Result<(KeyMaterial, Vec<u8>)> {
        log_rsa_deprecation_warning("generate_keypair");

        let mut rng = OsRng;
        let private_key =
            RsaPrivateKey::new(&mut rng, bits).map_err(|e| CryptoError::Internal(e.to_string()))?;

        let public_key = private_key.to_public_key();

        let private_der = rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&private_key)
            .map_err(|e| CryptoError::Internal(e.to_string()))?;
        let public_der = rsa::pkcs1::EncodeRsaPublicKey::to_pkcs1_der(&public_key)
            .map_err(|e| CryptoError::Internal(e.to_string()))?;

        Ok((
            KeyMaterial::from_bytes(private_der.as_bytes().to_vec()),
            public_der.as_bytes().to_vec(),
        ))
    }

    /// Signs a message using RSA PKCS#1 v1.5 with SHA-256.
    ///
    /// # Arguments
    ///
    /// * `key` - RSA private key in PKCS#8 DER format
    /// * `message` - Data to sign
    ///
    /// # Returns
    ///
    /// RSA signature bytes
    ///
    /// # Errors
    ///
    /// Returns error if key cannot be parsed or signing fails.
    ///
    /// # Security Warning
    ///
    /// PKCS#1 v1.5 padding is vulnerable to various attacks. Prefer PSS padding
    /// for new applications via `sign_pss_sha256`.
    ///
    /// Additionally, RUSTSEC-2023-0071 affects this implementation.
    pub fn sign_pkcs1v15_sha256(key: &KeyMaterial, message: &[u8]) -> Result<Vec<u8>> {
        log_rsa_deprecation_warning("sign_pkcs1v15");

        let private_key = RsaPrivateKey::from_pkcs8_der(key.as_bytes())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign_with_rng(&mut OsRng, message);

        Ok(signature.to_vec())
    }

    /// Verifies an RSA PKCS#1 v1.5 signature with SHA-256.
    ///
    /// # Arguments
    ///
    /// * `public_key` - RSA public key in PKCS#1 DER format
    /// * `message` - Original data that was signed
    /// * `signature` - Signature bytes to verify
    ///
    /// # Returns
    ///
    /// `true` if signature is valid, error otherwise
    ///
    /// # Errors
    ///
    /// Returns error if key cannot be parsed, signature is invalid, or verification fails.
    pub fn verify_pkcs1v15_sha256(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        log_rsa_deprecation_warning("verify_pkcs1v15");

        let public_key = RsaPublicKey::from_pkcs1_der(public_key)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let verifying_key = VerifyingKey::<Sha256>::new(public_key);

        let sig = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        verifying_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Signs a message using RSA-PSS with SHA-256.
    ///
    /// # Arguments
    ///
    /// * `key` - RSA private key in PKCS#8 DER format
    /// * `message` - Data to sign
    ///
    /// # Returns
    ///
    /// RSA-PSS signature bytes
    ///
    /// # Errors
    ///
    /// Returns error if key cannot be parsed or signing fails.
    ///
    /// # Security
    ///
    /// PSS padding is more secure than PKCS#1 v1.5 and recommended for new applications.
    /// However, RUSTSEC-2023-0071 still applies. Prefer Ed25519 if possible.
    ///
    /// # Performance
    ///
    /// PSS is slightly slower than PKCS#1 v1.5 due to more complex padding.
    pub fn sign_pss_sha256(key: &KeyMaterial, message: &[u8]) -> Result<Vec<u8>> {
        log_rsa_deprecation_warning("sign_pss");

        let private_key = RsaPrivateKey::from_pkcs8_der(key.as_bytes())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let signing_key = PssSigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign_with_rng(&mut OsRng, message);

        Ok(signature.to_vec())
    }

    /// Verifies an RSA-PSS signature with SHA-256.
    ///
    /// # Arguments
    ///
    /// * `public_key` - RSA public key in PKCS#1 DER format
    /// * `message` - Original data that was signed
    /// * `signature` - Signature bytes to verify
    ///
    /// # Returns
    ///
    /// `true` if signature is valid, error otherwise
    ///
    /// # Errors
    ///
    /// Returns error if key cannot be parsed, signature is invalid, or verification fails.
    pub fn verify_pss_sha256(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        log_rsa_deprecation_warning("verify_pss");

        let public_key = RsaPublicKey::from_pkcs1_der(public_key)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let verifying_key = PssVerifyingKey::<Sha256>::new(public_key);

        let sig = rsa::pss::Signature::try_from(signature)
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
    fn test_rsa_pkcs1v15_sign_verify() {
        let (private_key, public_key) = RsaEngine::generate_keypair(2048).unwrap();
        let message = b"test message";

        let signature = RsaEngine::sign_pkcs1v15_sha256(&private_key, message).unwrap();
        let valid = RsaEngine::verify_pkcs1v15_sha256(&public_key, message, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_rsa_pss_sign_verify() {
        let (private_key, public_key) = RsaEngine::generate_keypair(2048).unwrap();
        let message = b"test message";

        let signature = RsaEngine::sign_pss_sha256(&private_key, message).unwrap();
        let valid = RsaEngine::verify_pss_sha256(&public_key, message, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_rsa_invalid_signature() {
        let (_, public_key) = RsaEngine::generate_keypair(2048).unwrap();
        let message = b"test message";
        let bad_signature = vec![0u8; 256];

        let result = RsaEngine::verify_pkcs1v15_sha256(&public_key, message, &bad_signature);
        assert!(result.is_err());
    }
}
