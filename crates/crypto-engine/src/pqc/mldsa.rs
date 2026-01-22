//! ML-DSA (Module-Lattice Digital Signature Algorithm)
//!
//! Formerly known as Dilithium, standardized in FIPS 204.
//! Provides post-quantum secure digital signatures.
//!
//! # Security Levels
//!
//! - **ML-DSA-65**: ~192-bit classical security (NIST Level 3)
//! - **ML-DSA-87**: ~256-bit classical security (NIST Level 5)
//!
//! # Key and Signature Sizes
//!
//! | Level | Public Key | Secret Key | Signature |
//! |-------|------------|------------|-----------|
//! | 65    | 1952 bytes | 4032 bytes | 3309 bytes|
//! | 87    | 2592 bytes | 4896 bytes | 4627 bytes|
//!
//! # Note on Naming
//!
//! The pqcrypto-dilithium crate uses `mldsa65` for ML-DSA-65 and
//! `mldsa87` for ML-DSA-87. This mapping follows the NIST security
//! level correspondence.
//!
//! # Example
//!
//! ```rust
//! use hsm_crypto_engine::pqc::mldsa::{MlDsaEngine, MlDsaSecurityLevel};
//!
//! // Generate a key pair
//! let keypair = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let signature = MlDsaEngine::sign(&keypair, message).unwrap();
//!
//! // Verify the signature
//! let valid = MlDsaEngine::verify(
//!     &keypair.public_key,
//!     message,
//!     &signature,
//!     MlDsaSecurityLevel::MlDsa65,
//! ).unwrap();
//!
//! assert!(valid);
//! ```

use crate::Result;
use pqcrypto_mldsa::{mldsa65, mldsa87};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use zeroize::ZeroizeOnDrop;

use super::error::PqcError;

/// Security level for ML-DSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaSecurityLevel {
    /// ML-DSA-65: ~192-bit classical security (NIST Level 3)
    ///
    /// Recommended for most applications.
    MlDsa65,

    /// ML-DSA-87: ~256-bit classical security (NIST Level 5)
    ///
    /// Maximum security level with larger keys and signatures.
    MlDsa87,
}

impl MlDsaSecurityLevel {
    /// Returns the algorithm name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            MlDsaSecurityLevel::MlDsa65 => "ML-DSA-65",
            MlDsaSecurityLevel::MlDsa87 => "ML-DSA-87",
        }
    }
}

/// ML-DSA key pair containing public and secret keys.
///
/// The secret key is automatically zeroized when dropped for security.
#[derive(ZeroizeOnDrop)]
pub struct MlDsaKeyPair {
    /// Security level of this key pair.
    #[zeroize(skip)]
    pub security_level: MlDsaSecurityLevel,

    /// Public key bytes (can be shared for signature verification).
    #[zeroize(skip)]
    pub public_key: Vec<u8>,

    /// Secret key bytes (must be kept private for signing).
    secret_key: Vec<u8>,
}

impl MlDsaKeyPair {
    /// Creates a new key pair from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `level` - Security level of the key pair
    /// * `public_key` - Public key bytes
    /// * `secret_key` - Secret key bytes
    pub fn new(level: MlDsaSecurityLevel, public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self {
            security_level: level,
            public_key,
            secret_key,
        }
    }

    /// Returns a reference to the public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns a reference to the secret key bytes.
    ///
    /// # Security
    ///
    /// Use with caution. The secret key should never be exposed outside
    /// of cryptographic operations.
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }
}

/// ML-DSA signature.
#[derive(Clone)]
pub struct MlDsaSignature {
    /// Signature bytes.
    pub bytes: Vec<u8>,

    /// Security level this signature was created with.
    pub security_level: MlDsaSecurityLevel,
}

impl MlDsaSignature {
    /// Creates a new signature from raw bytes.
    pub fn new(bytes: Vec<u8>, level: MlDsaSecurityLevel) -> Self {
        Self {
            bytes,
            security_level: level,
        }
    }

    /// Returns a reference to the signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-DSA cryptographic engine.
///
/// Provides key generation, signing, and verification operations
/// for ML-DSA digital signatures (NIST FIPS 204).
pub struct MlDsaEngine;

impl MlDsaEngine {
    /// Generates a new ML-DSA key pair.
    ///
    /// # Arguments
    ///
    /// * `level` - Security level to use
    ///
    /// # Returns
    ///
    /// A new key pair for the specified security level.
    ///
    /// # Performance
    ///
    /// - ML-DSA-65 keygen: ~100 microseconds
    /// - ML-DSA-87 keygen: ~150 microseconds
    pub fn generate_keypair(level: MlDsaSecurityLevel) -> Result<MlDsaKeyPair> {
        match level {
            MlDsaSecurityLevel::MlDsa65 => {
                let (pk, sk) = mldsa65::keypair();
                Ok(MlDsaKeyPair::new(
                    level,
                    pk.as_bytes().to_vec(),
                    sk.as_bytes().to_vec(),
                ))
            }
            MlDsaSecurityLevel::MlDsa87 => {
                let (pk, sk) = mldsa87::keypair();
                Ok(MlDsaKeyPair::new(
                    level,
                    pk.as_bytes().to_vec(),
                    sk.as_bytes().to_vec(),
                ))
            }
        }
    }

    /// Signs a message using ML-DSA.
    ///
    /// # Arguments
    ///
    /// * `keypair` - Key pair containing the secret key for signing
    /// * `message` - Message bytes to sign
    ///
    /// # Returns
    ///
    /// The signature on success.
    ///
    /// # Performance
    ///
    /// - ML-DSA-65 sign: ~500 microseconds
    /// - ML-DSA-87 sign: ~800 microseconds
    pub fn sign(keypair: &MlDsaKeyPair, message: &[u8]) -> Result<MlDsaSignature> {
        let level = keypair.security_level;

        match level {
            MlDsaSecurityLevel::MlDsa65 => {
                let sk = mldsa65::SecretKey::from_bytes(&keypair.secret_key).map_err(|_| {
                    PqcError::InvalidSecretKey {
                        algorithm: level.as_str(),
                    }
                })?;

                let sig = mldsa65::detached_sign(message, &sk);

                Ok(MlDsaSignature::new(sig.as_bytes().to_vec(), level))
            }
            MlDsaSecurityLevel::MlDsa87 => {
                let sk = mldsa87::SecretKey::from_bytes(&keypair.secret_key).map_err(|_| {
                    PqcError::InvalidSecretKey {
                        algorithm: level.as_str(),
                    }
                })?;

                let sig = mldsa87::detached_sign(message, &sk);

                Ok(MlDsaSignature::new(sig.as_bytes().to_vec(), level))
            }
        }
    }

    /// Verifies an ML-DSA signature.
    ///
    /// # Arguments
    ///
    /// * `public_key` - Public key bytes for verification
    /// * `message` - Original message that was signed
    /// * `signature` - Signature to verify
    /// * `level` - Security level (must match the signature's level)
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise.
    ///
    /// # Performance
    ///
    /// - ML-DSA-65 verify: ~200 microseconds
    /// - ML-DSA-87 verify: ~300 microseconds
    pub fn verify(
        public_key: &[u8],
        message: &[u8],
        signature: &MlDsaSignature,
        level: MlDsaSecurityLevel,
    ) -> Result<bool> {
        match level {
            MlDsaSecurityLevel::MlDsa65 => {
                let expected_pk_size = Self::public_key_size(level);
                if public_key.len() != expected_pk_size {
                    return Err(PqcError::InvalidKeySize {
                        algorithm: level.as_str(),
                        expected: expected_pk_size,
                        actual: public_key.len(),
                    }
                    .into());
                }

                let expected_sig_size = Self::signature_size(level);
                if signature.bytes.len() != expected_sig_size {
                    return Err(PqcError::InvalidSignatureSize {
                        algorithm: level.as_str(),
                        expected: expected_sig_size,
                        actual: signature.bytes.len(),
                    }
                    .into());
                }

                let pk = mldsa65::PublicKey::from_bytes(public_key).map_err(|_| {
                    PqcError::InvalidPublicKey {
                        algorithm: level.as_str(),
                    }
                })?;

                let sig =
                    mldsa65::DetachedSignature::from_bytes(&signature.bytes).map_err(|_| {
                        PqcError::InvalidSignatureSize {
                            algorithm: level.as_str(),
                            expected: expected_sig_size,
                            actual: signature.bytes.len(),
                        }
                    })?;

                match mldsa65::verify_detached_signature(&sig, message, &pk) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            MlDsaSecurityLevel::MlDsa87 => {
                let expected_pk_size = Self::public_key_size(level);
                if public_key.len() != expected_pk_size {
                    return Err(PqcError::InvalidKeySize {
                        algorithm: level.as_str(),
                        expected: expected_pk_size,
                        actual: public_key.len(),
                    }
                    .into());
                }

                let expected_sig_size = Self::signature_size(level);
                if signature.bytes.len() != expected_sig_size {
                    return Err(PqcError::InvalidSignatureSize {
                        algorithm: level.as_str(),
                        expected: expected_sig_size,
                        actual: signature.bytes.len(),
                    }
                    .into());
                }

                let pk = mldsa87::PublicKey::from_bytes(public_key).map_err(|_| {
                    PqcError::InvalidPublicKey {
                        algorithm: level.as_str(),
                    }
                })?;

                let sig =
                    mldsa87::DetachedSignature::from_bytes(&signature.bytes).map_err(|_| {
                        PqcError::InvalidSignatureSize {
                            algorithm: level.as_str(),
                            expected: expected_sig_size,
                            actual: signature.bytes.len(),
                        }
                    })?;

                match mldsa87::verify_detached_signature(&sig, message, &pk) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    /// Returns the public key size in bytes for the given security level.
    pub fn public_key_size(level: MlDsaSecurityLevel) -> usize {
        match level {
            MlDsaSecurityLevel::MlDsa65 => 1952,
            MlDsaSecurityLevel::MlDsa87 => 2592,
        }
    }

    /// Returns the secret key size in bytes for the given security level.
    pub fn secret_key_size(level: MlDsaSecurityLevel) -> usize {
        match level {
            MlDsaSecurityLevel::MlDsa65 => 4032,
            MlDsaSecurityLevel::MlDsa87 => 4896,
        }
    }

    /// Returns the signature size in bytes for the given security level.
    pub fn signature_size(level: MlDsaSecurityLevel) -> usize {
        match level {
            MlDsaSecurityLevel::MlDsa65 => 3309,
            MlDsaSecurityLevel::MlDsa87 => 4627,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa_65_sign_verify() {
        let keypair = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();

        assert_eq!(
            keypair.public_key.len(),
            MlDsaEngine::public_key_size(MlDsaSecurityLevel::MlDsa65)
        );
        assert_eq!(
            keypair.secret_key().len(),
            MlDsaEngine::secret_key_size(MlDsaSecurityLevel::MlDsa65)
        );

        let message = b"test message for signing";
        let signature = MlDsaEngine::sign(&keypair, message).unwrap();

        assert_eq!(
            signature.bytes.len(),
            MlDsaEngine::signature_size(MlDsaSecurityLevel::MlDsa65)
        );

        let valid = MlDsaEngine::verify(
            &keypair.public_key,
            message,
            &signature,
            MlDsaSecurityLevel::MlDsa65,
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_mldsa_87_sign_verify() {
        let keypair = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa87).unwrap();

        assert_eq!(
            keypair.public_key.len(),
            MlDsaEngine::public_key_size(MlDsaSecurityLevel::MlDsa87)
        );
        assert_eq!(
            keypair.secret_key().len(),
            MlDsaEngine::secret_key_size(MlDsaSecurityLevel::MlDsa87)
        );

        let message = b"test message for signing";
        let signature = MlDsaEngine::sign(&keypair, message).unwrap();

        assert_eq!(
            signature.bytes.len(),
            MlDsaEngine::signature_size(MlDsaSecurityLevel::MlDsa87)
        );

        let valid = MlDsaEngine::verify(
            &keypair.public_key,
            message,
            &signature,
            MlDsaSecurityLevel::MlDsa87,
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_mldsa_invalid_signature() {
        let keypair = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
        let message = b"test message";
        let signature = MlDsaEngine::sign(&keypair, message).unwrap();

        // Verify with wrong message
        let valid = MlDsaEngine::verify(
            &keypair.public_key,
            b"different message",
            &signature,
            MlDsaSecurityLevel::MlDsa65,
        )
        .unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_mldsa_wrong_key() {
        let keypair1 = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
        let keypair2 = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();

        let message = b"test message";
        let signature = MlDsaEngine::sign(&keypair1, message).unwrap();

        // Verify with wrong public key
        let valid = MlDsaEngine::verify(
            &keypair2.public_key,
            message,
            &signature,
            MlDsaSecurityLevel::MlDsa65,
        )
        .unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_mldsa_key_sizes() {
        assert_eq!(
            MlDsaEngine::public_key_size(MlDsaSecurityLevel::MlDsa65),
            1952
        );
        assert_eq!(
            MlDsaEngine::secret_key_size(MlDsaSecurityLevel::MlDsa65),
            4032
        );
        assert_eq!(
            MlDsaEngine::signature_size(MlDsaSecurityLevel::MlDsa65),
            3309
        );

        assert_eq!(
            MlDsaEngine::public_key_size(MlDsaSecurityLevel::MlDsa87),
            2592
        );
        assert_eq!(
            MlDsaEngine::secret_key_size(MlDsaSecurityLevel::MlDsa87),
            4896
        );
        assert_eq!(
            MlDsaEngine::signature_size(MlDsaSecurityLevel::MlDsa87),
            4627
        );
    }

    #[test]
    fn test_mldsa_deterministic_signatures() {
        // ML-DSA signatures are NOT deterministic (they use randomness)
        // So the same message signed twice should produce different signatures
        let keypair = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
        let message = b"test message";

        let sig1 = MlDsaEngine::sign(&keypair, message).unwrap();
        let sig2 = MlDsaEngine::sign(&keypair, message).unwrap();

        // Both signatures should be valid
        assert!(MlDsaEngine::verify(
            &keypair.public_key,
            message,
            &sig1,
            MlDsaSecurityLevel::MlDsa65
        )
        .unwrap());
        assert!(MlDsaEngine::verify(
            &keypair.public_key,
            message,
            &sig2,
            MlDsaSecurityLevel::MlDsa65
        )
        .unwrap());

        // Signatures may be different (randomized signing)
        // We don't assert inequality because there's a tiny chance they could be the same
    }
}
