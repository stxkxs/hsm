//! Hybrid cryptography combining classical and post-quantum algorithms.
//!
//! Provides defense-in-depth: if either algorithm is broken, the other
//! still provides security. This is recommended during the transition
//! period to post-quantum cryptography.
//!
//! # Hybrid KEM (X25519 + ML-KEM)
//!
//! Combines X25519 ECDH with ML-KEM key encapsulation. The shared secrets
//! from both algorithms are combined using HKDF to produce the final key.
//!
//! # Hybrid Signatures (Ed25519 + ML-DSA)
//!
//! Combines Ed25519 with ML-DSA signatures. Both algorithms sign the same
//! message, and verification requires both signatures to be valid.
//!
//! # Example (Hybrid KEM)
//!
//! ```rust
//! use hsm_crypto_engine::pqc::hybrid::HybridKemEngine;
//! use hsm_crypto_engine::pqc::mlkem::MlKemSecurityLevel;
//!
//! // Generate a hybrid key pair
//! let keypair = HybridKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
//!
//! // Encapsulate to create shared secret
//! let (shared1, ciphertext) = HybridKemEngine::encapsulate(&keypair).unwrap();
//!
//! // Decapsulate to recover shared secret
//! let shared2 = HybridKemEngine::decapsulate(&keypair, &ciphertext).unwrap();
//!
//! assert_eq!(shared1, shared2);
//! ```
//!
//! # Example (Hybrid Signatures)
//!
//! ```rust
//! use hsm_crypto_engine::pqc::hybrid::HybridSignEngine;
//! use hsm_crypto_engine::pqc::mldsa::MlDsaSecurityLevel;
//!
//! // Generate a hybrid signing key pair
//! let keypair = HybridSignEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
//!
//! // Sign a message
//! let message = b"Hello, hybrid world!";
//! let signature = HybridSignEngine::sign(&keypair, message).unwrap();
//!
//! // Verify the signature
//! let valid = HybridSignEngine::verify(&keypair, message, &signature).unwrap();
//! assert!(valid);
//! ```

use super::mldsa::{MlDsaEngine, MlDsaKeyPair, MlDsaSecurityLevel, MlDsaSignature};
use super::mlkem::{MlKemCiphertext, MlKemEngine, MlKemKeyPair, MlKemSecurityLevel};
use crate::asymmetric::ed25519::Ed25519Engine;
use crate::kdf::hkdf;
use crate::{CryptoError, KeyMaterial, Result};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Hybrid KEM key pair combining X25519 and ML-KEM.
///
/// Both classical and post-quantum key pairs are stored together.
/// The shared secret is derived from both key exchanges.
#[derive(ZeroizeOnDrop)]
pub struct HybridKemKeyPair {
    /// X25519 private key (32 bytes).
    x25519_private: Vec<u8>,

    /// X25519 public key (32 bytes).
    #[zeroize(skip)]
    pub x25519_public: Vec<u8>,

    /// ML-KEM key pair.
    #[zeroize(skip)]
    pub mlkem_keypair: MlKemKeyPair,
}

impl HybridKemKeyPair {
    /// Returns a reference to the X25519 public key.
    pub fn x25519_public_key(&self) -> &[u8] {
        &self.x25519_public
    }

    /// Returns a reference to the ML-KEM public key.
    pub fn mlkem_public_key(&self) -> &[u8] {
        &self.mlkem_keypair.public_key
    }

    /// Returns the ML-KEM security level.
    pub fn mlkem_level(&self) -> MlKemSecurityLevel {
        self.mlkem_keypair.security_level
    }
}

/// Hybrid KEM ciphertext containing both X25519 and ML-KEM components.
#[derive(Clone)]
pub struct HybridKemCiphertext {
    /// X25519 ephemeral public key (32 bytes).
    pub x25519_ephemeral: Vec<u8>,

    /// ML-KEM ciphertext.
    pub mlkem_ciphertext: Vec<u8>,

    /// ML-KEM security level.
    pub mlkem_level: MlKemSecurityLevel,
}

impl HybridKemCiphertext {
    /// Returns the total size of the ciphertext in bytes.
    pub fn size(&self) -> usize {
        self.x25519_ephemeral.len() + self.mlkem_ciphertext.len()
    }
}

/// Hybrid KEM engine combining X25519 and ML-KEM.
///
/// The shared secret is computed as:
/// ```text
/// shared_secret = HKDF(x25519_shared || mlkem_shared, salt="hybrid-kem-v1", info="shared-secret", len=32)
/// ```
pub struct HybridKemEngine;

impl HybridKemEngine {
    /// Generates a hybrid KEM key pair.
    ///
    /// # Arguments
    ///
    /// * `pqc_level` - ML-KEM security level to use
    ///
    /// # Returns
    ///
    /// A hybrid key pair combining X25519 and ML-KEM.
    pub fn generate_keypair(pqc_level: MlKemSecurityLevel) -> Result<HybridKemKeyPair> {
        // Generate X25519 keypair
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Generate ML-KEM keypair
        let mlkem_keypair = MlKemEngine::generate_keypair(pqc_level)?;

        Ok(HybridKemKeyPair {
            x25519_private: x25519_secret.as_bytes().to_vec(),
            x25519_public: x25519_public.as_bytes().to_vec(),
            mlkem_keypair,
        })
    }

    /// Encapsulates a shared secret to a hybrid key pair.
    ///
    /// Performs both X25519 key exchange and ML-KEM encapsulation,
    /// then combines the shared secrets using HKDF.
    ///
    /// # Arguments
    ///
    /// * `keypair` - Recipient's hybrid key pair
    ///
    /// # Returns
    ///
    /// Tuple of (shared_secret, ciphertext).
    pub fn encapsulate(keypair: &HybridKemKeyPair) -> Result<(Vec<u8>, HybridKemCiphertext)> {
        Self::encapsulate_to_public_keys(
            &keypair.x25519_public,
            &keypair.mlkem_keypair.public_key,
            keypair.mlkem_keypair.security_level,
        )
    }

    /// Encapsulates a shared secret using public keys directly.
    ///
    /// # Arguments
    ///
    /// * `x25519_public` - Recipient's X25519 public key
    /// * `mlkem_public` - Recipient's ML-KEM public key
    /// * `pqc_level` - ML-KEM security level
    ///
    /// # Returns
    ///
    /// Tuple of (shared_secret, ciphertext).
    pub fn encapsulate_to_public_keys(
        x25519_public: &[u8],
        mlkem_public: &[u8],
        pqc_level: MlKemSecurityLevel,
    ) -> Result<(Vec<u8>, HybridKemCiphertext)> {
        // Validate X25519 public key size
        if x25519_public.len() != 32 {
            return Err(CryptoError::InvalidKeySize {
                expected: 32,
                actual: x25519_public.len(),
            });
        }

        // X25519 key exchange
        let x25519_ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let x25519_ephemeral_public = X25519PublicKey::from(&x25519_ephemeral_secret);

        let x25519_recipient_public: [u8; 32] =
            x25519_public
                .try_into()
                .map_err(|_| CryptoError::InvalidKeySize {
                    expected: 32,
                    actual: x25519_public.len(),
                })?;
        let x25519_recipient = X25519PublicKey::from(x25519_recipient_public);

        let x25519_shared = x25519_ephemeral_secret.diffie_hellman(&x25519_recipient);

        // ML-KEM encapsulation
        let (mlkem_shared, mlkem_ct) = MlKemEngine::encapsulate(mlkem_public, pqc_level)?;

        // Combine shared secrets using HKDF
        let combined_secret =
            Self::combine_shared_secrets(x25519_shared.as_bytes(), &mlkem_shared)?;

        let ciphertext = HybridKemCiphertext {
            x25519_ephemeral: x25519_ephemeral_public.as_bytes().to_vec(),
            mlkem_ciphertext: mlkem_ct.ciphertext,
            mlkem_level: pqc_level,
        };

        Ok((combined_secret, ciphertext))
    }

    /// Decapsulates a hybrid ciphertext to recover the shared secret.
    ///
    /// # Arguments
    ///
    /// * `keypair` - Recipient's hybrid key pair
    /// * `ciphertext` - Hybrid ciphertext received from sender
    ///
    /// # Returns
    ///
    /// The shared secret (32 bytes).
    pub fn decapsulate(
        keypair: &HybridKemKeyPair,
        ciphertext: &HybridKemCiphertext,
    ) -> Result<Vec<u8>> {
        // Validate X25519 ephemeral public key size
        if ciphertext.x25519_ephemeral.len() != 32 {
            return Err(CryptoError::InvalidKeySize {
                expected: 32,
                actual: ciphertext.x25519_ephemeral.len(),
            });
        }

        // X25519 key exchange
        let x25519_private: [u8; 32] =
            keypair.x25519_private.as_slice().try_into().map_err(|_| {
                CryptoError::InvalidKeySize {
                    expected: 32,
                    actual: keypair.x25519_private.len(),
                }
            })?;
        let x25519_secret = StaticSecret::from(x25519_private);

        let x25519_ephemeral: [u8; 32] = ciphertext
            .x25519_ephemeral
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeySize {
                expected: 32,
                actual: ciphertext.x25519_ephemeral.len(),
            })?;
        let x25519_ephemeral_public = X25519PublicKey::from(x25519_ephemeral);

        let x25519_shared = x25519_secret.diffie_hellman(&x25519_ephemeral_public);

        // ML-KEM decapsulation
        let mlkem_ct =
            MlKemCiphertext::new(ciphertext.mlkem_ciphertext.clone(), ciphertext.mlkem_level);
        let mlkem_shared = MlKemEngine::decapsulate(&keypair.mlkem_keypair, &mlkem_ct)?;

        // Combine shared secrets using HKDF
        let combined_secret =
            Self::combine_shared_secrets(x25519_shared.as_bytes(), &mlkem_shared)?;

        Ok(combined_secret)
    }

    /// Combines X25519 and ML-KEM shared secrets using HKDF.
    fn combine_shared_secrets(x25519_shared: &[u8], mlkem_shared: &[u8]) -> Result<Vec<u8>> {
        let mut combined_input = Vec::with_capacity(x25519_shared.len() + mlkem_shared.len());
        combined_input.extend_from_slice(x25519_shared);
        combined_input.extend_from_slice(mlkem_shared);

        let result = hkdf::derive_key(&combined_input, b"hybrid-kem-v1", b"shared-secret", 32)?;

        // Zeroize the intermediate value
        combined_input.zeroize();

        Ok(result)
    }
}

/// Hybrid signature key pair combining Ed25519 and ML-DSA.
///
/// Both classical and post-quantum key pairs are stored together.
/// Signatures include both Ed25519 and ML-DSA signatures.
#[derive(ZeroizeOnDrop)]
pub struct HybridSignKeyPair {
    /// Ed25519 private key.
    ed25519_private: KeyMaterial,

    /// Ed25519 public key (32 bytes).
    #[zeroize(skip)]
    pub ed25519_public: Vec<u8>,

    /// ML-DSA key pair.
    #[zeroize(skip)]
    pub mldsa_keypair: MlDsaKeyPair,
}

impl HybridSignKeyPair {
    /// Returns a reference to the Ed25519 public key.
    pub fn ed25519_public_key(&self) -> &[u8] {
        &self.ed25519_public
    }

    /// Returns a reference to the ML-DSA public key.
    pub fn mldsa_public_key(&self) -> &[u8] {
        &self.mldsa_keypair.public_key
    }

    /// Returns the ML-DSA security level.
    pub fn mldsa_level(&self) -> MlDsaSecurityLevel {
        self.mldsa_keypair.security_level
    }
}

/// Hybrid signature containing both Ed25519 and ML-DSA signatures.
#[derive(Clone)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes).
    pub ed25519_sig: Vec<u8>,

    /// ML-DSA signature.
    pub mldsa_sig: Vec<u8>,

    /// ML-DSA security level.
    pub mldsa_level: MlDsaSecurityLevel,
}

impl HybridSignature {
    /// Returns the total size of the signature in bytes.
    pub fn size(&self) -> usize {
        self.ed25519_sig.len() + self.mldsa_sig.len()
    }
}

/// Hybrid signature engine combining Ed25519 and ML-DSA.
///
/// Both algorithms sign the same message, and verification requires
/// both signatures to be valid.
pub struct HybridSignEngine;

impl HybridSignEngine {
    /// Generates a hybrid signing key pair.
    ///
    /// # Arguments
    ///
    /// * `pqc_level` - ML-DSA security level to use
    ///
    /// # Returns
    ///
    /// A hybrid key pair combining Ed25519 and ML-DSA.
    pub fn generate_keypair(pqc_level: MlDsaSecurityLevel) -> Result<HybridSignKeyPair> {
        // Generate Ed25519 keypair
        let (ed25519_private, ed25519_public) = Ed25519Engine::generate_keypair()?;

        // Generate ML-DSA keypair
        let mldsa_keypair = MlDsaEngine::generate_keypair(pqc_level)?;

        Ok(HybridSignKeyPair {
            ed25519_private,
            ed25519_public,
            mldsa_keypair,
        })
    }

    /// Signs a message with both Ed25519 and ML-DSA.
    ///
    /// # Arguments
    ///
    /// * `keypair` - Hybrid signing key pair
    /// * `message` - Message to sign
    ///
    /// # Returns
    ///
    /// A hybrid signature containing both Ed25519 and ML-DSA signatures.
    pub fn sign(keypair: &HybridSignKeyPair, message: &[u8]) -> Result<HybridSignature> {
        // Sign with Ed25519
        let ed25519_sig = Ed25519Engine::sign(&keypair.ed25519_private, message)?;

        // Sign with ML-DSA
        let mldsa_sig = MlDsaEngine::sign(&keypair.mldsa_keypair, message)?;

        Ok(HybridSignature {
            ed25519_sig,
            mldsa_sig: mldsa_sig.bytes,
            mldsa_level: keypair.mldsa_keypair.security_level,
        })
    }

    /// Verifies a hybrid signature (both signatures must be valid).
    ///
    /// # Arguments
    ///
    /// * `keypair` - Hybrid signing key pair (only public keys are used)
    /// * `message` - Original message that was signed
    /// * `signature` - Hybrid signature to verify
    ///
    /// # Returns
    ///
    /// `true` if BOTH signatures are valid, `false` otherwise.
    pub fn verify(
        keypair: &HybridSignKeyPair,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<bool> {
        Self::verify_with_public_keys(
            &keypair.ed25519_public,
            &keypair.mldsa_keypair.public_key,
            message,
            signature,
        )
    }

    /// Verifies a hybrid signature using public keys directly.
    ///
    /// # Arguments
    ///
    /// * `ed25519_public` - Ed25519 public key
    /// * `mldsa_public` - ML-DSA public key
    /// * `message` - Original message that was signed
    /// * `signature` - Hybrid signature to verify
    ///
    /// # Returns
    ///
    /// `true` if BOTH signatures are valid, `false` otherwise.
    pub fn verify_with_public_keys(
        ed25519_public: &[u8],
        mldsa_public: &[u8],
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<bool> {
        // Verify Ed25519 signature
        // Ed25519Engine::verify returns Err on invalid signature, so we convert to Ok(false)
        let ed25519_valid =
            match Ed25519Engine::verify(ed25519_public, message, &signature.ed25519_sig) {
                Ok(valid) => valid,
                Err(CryptoError::SignatureVerificationFailed) => false,
                Err(e) => return Err(e),
            };

        if !ed25519_valid {
            return Ok(false);
        }

        // Verify ML-DSA signature
        let mldsa_sig = MlDsaSignature::new(signature.mldsa_sig.clone(), signature.mldsa_level);

        let mldsa_valid =
            MlDsaEngine::verify(mldsa_public, message, &mldsa_sig, signature.mldsa_level)?;

        Ok(mldsa_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_768_roundtrip() {
        let keypair = HybridKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        assert_eq!(keypair.x25519_public.len(), 32);
        assert_eq!(
            keypair.mlkem_keypair.public_key.len(),
            MlKemEngine::public_key_size(MlKemSecurityLevel::MlKem768)
        );

        let (shared1, ct) = HybridKemEngine::encapsulate(&keypair).unwrap();

        assert_eq!(shared1.len(), 32);
        assert_eq!(ct.x25519_ephemeral.len(), 32);
        assert_eq!(
            ct.mlkem_ciphertext.len(),
            MlKemEngine::ciphertext_size(MlKemSecurityLevel::MlKem768)
        );

        let shared2 = HybridKemEngine::decapsulate(&keypair, &ct).unwrap();

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_hybrid_kem_1024_roundtrip() {
        let keypair = HybridKemEngine::generate_keypair(MlKemSecurityLevel::MlKem1024).unwrap();

        let (shared1, ct) = HybridKemEngine::encapsulate(&keypair).unwrap();
        let shared2 = HybridKemEngine::decapsulate(&keypair, &ct).unwrap();

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_hybrid_kem_public_key_encapsulation() {
        let keypair = HybridKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        // Encapsulate using only public keys
        let (shared1, ct) = HybridKemEngine::encapsulate_to_public_keys(
            &keypair.x25519_public,
            &keypair.mlkem_keypair.public_key,
            MlKemSecurityLevel::MlKem768,
        )
        .unwrap();

        // Decapsulate using full keypair
        let shared2 = HybridKemEngine::decapsulate(&keypair, &ct).unwrap();

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_hybrid_kem_different_keys() {
        let keypair1 = HybridKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
        let keypair2 = HybridKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        let (shared1, _ct1) = HybridKemEngine::encapsulate(&keypair1).unwrap();
        let (shared2, _ct2) = HybridKemEngine::encapsulate(&keypair2).unwrap();

        // Different recipients should get different shared secrets
        assert_ne!(shared1, shared2);
    }

    #[test]
    fn test_hybrid_sign_65_roundtrip() {
        let keypair = HybridSignEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();

        assert_eq!(keypair.ed25519_public.len(), 32);
        assert_eq!(
            keypair.mldsa_keypair.public_key.len(),
            MlDsaEngine::public_key_size(MlDsaSecurityLevel::MlDsa65)
        );

        let message = b"test message for hybrid signing";
        let signature = HybridSignEngine::sign(&keypair, message).unwrap();

        assert_eq!(signature.ed25519_sig.len(), 64);
        assert_eq!(
            signature.mldsa_sig.len(),
            MlDsaEngine::signature_size(MlDsaSecurityLevel::MlDsa65)
        );

        let valid = HybridSignEngine::verify(&keypair, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_hybrid_sign_87_roundtrip() {
        let keypair = HybridSignEngine::generate_keypair(MlDsaSecurityLevel::MlDsa87).unwrap();

        let message = b"test message for hybrid signing";
        let signature = HybridSignEngine::sign(&keypair, message).unwrap();

        let valid = HybridSignEngine::verify(&keypair, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_hybrid_sign_wrong_message() {
        let keypair = HybridSignEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();

        let message = b"original message";
        let signature = HybridSignEngine::sign(&keypair, message).unwrap();

        // Verify with wrong message
        let valid = HybridSignEngine::verify(&keypair, b"different message", &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_hybrid_sign_tampered_ed25519() {
        let keypair = HybridSignEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();

        let message = b"test message";
        let mut signature = HybridSignEngine::sign(&keypair, message).unwrap();

        // Tamper with Ed25519 signature
        signature.ed25519_sig[0] ^= 0xFF;

        let valid = HybridSignEngine::verify(&keypair, message, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_hybrid_sign_tampered_mldsa() {
        let keypair = HybridSignEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();

        let message = b"test message";
        let mut signature = HybridSignEngine::sign(&keypair, message).unwrap();

        // Tamper with ML-DSA signature
        signature.mldsa_sig[0] ^= 0xFF;

        let valid = HybridSignEngine::verify(&keypair, message, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_hybrid_sign_public_key_verification() {
        let keypair = HybridSignEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();

        let message = b"test message";
        let signature = HybridSignEngine::sign(&keypair, message).unwrap();

        // Verify using only public keys
        let valid = HybridSignEngine::verify_with_public_keys(
            &keypair.ed25519_public,
            &keypair.mldsa_keypair.public_key,
            message,
            &signature,
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_hybrid_sign_wrong_ed25519_key() {
        let keypair1 = HybridSignEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
        let keypair2 = HybridSignEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();

        let message = b"test message";
        let signature = HybridSignEngine::sign(&keypair1, message).unwrap();

        // Try to verify with keypair2's Ed25519 key but keypair1's ML-DSA key
        let valid = HybridSignEngine::verify_with_public_keys(
            &keypair2.ed25519_public, // Wrong key
            &keypair1.mldsa_keypair.public_key,
            message,
            &signature,
        )
        .unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_hybrid_sign_wrong_mldsa_key() {
        let keypair1 = HybridSignEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
        let keypair2 = HybridSignEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();

        let message = b"test message";
        let signature = HybridSignEngine::sign(&keypair1, message).unwrap();

        // Try to verify with keypair1's Ed25519 key but keypair2's ML-DSA key
        let valid = HybridSignEngine::verify_with_public_keys(
            &keypair1.ed25519_public,
            &keypair2.mldsa_keypair.public_key, // Wrong key
            message,
            &signature,
        )
        .unwrap();

        assert!(!valid);
    }
}
