//! ML-KEM (Module-Lattice Key Encapsulation Mechanism)
//!
//! Formerly known as Kyber, standardized in FIPS 203.
//! Provides post-quantum secure key encapsulation for establishing shared secrets.
//!
//! # Security Levels
//!
//! - **ML-KEM-768**: ~192-bit classical security (NIST Level 3)
//! - **ML-KEM-1024**: ~256-bit classical security (NIST Level 5)
//!
//! # Key Sizes
//!
//! | Level | Public Key | Secret Key | Ciphertext | Shared Secret |
//! |-------|------------|------------|------------|---------------|
//! | 768   | 1184 bytes | 2400 bytes | 1088 bytes | 32 bytes      |
//! | 1024  | 1568 bytes | 3168 bytes | 1568 bytes | 32 bytes      |
//!
//! # Example
//!
//! ```rust
//! use hsm_crypto_engine::pqc::mlkem::{MlKemEngine, MlKemSecurityLevel};
//!
//! // Generate a key pair
//! let keypair = MlKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
//!
//! // Encapsulate: sender creates shared secret and ciphertext
//! let (shared_secret_sender, ciphertext) = MlKemEngine::encapsulate(
//!     &keypair.public_key,
//!     MlKemSecurityLevel::MlKem768,
//! ).unwrap();
//!
//! // Decapsulate: receiver recovers the same shared secret
//! let shared_secret_receiver = MlKemEngine::decapsulate(&keypair, &ciphertext).unwrap();
//!
//! assert_eq!(shared_secret_sender, shared_secret_receiver);
//! ```

use crate::Result;
use pqcrypto_mlkem::{mlkem1024, mlkem768};
use pqcrypto_traits::kem::{Ciphertext as CiphertextTrait, PublicKey, SecretKey, SharedSecret};
use zeroize::ZeroizeOnDrop;

use super::error::PqcError;

/// Security level for ML-KEM (Kyber).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemSecurityLevel {
    /// ML-KEM-768: ~192-bit classical security (NIST Level 3)
    ///
    /// Recommended for most applications. Provides a good balance between
    /// security and performance.
    MlKem768,

    /// ML-KEM-1024: ~256-bit classical security (NIST Level 5)
    ///
    /// Maximum security level. Use when highest security is required
    /// and larger key/ciphertext sizes are acceptable.
    MlKem1024,
}

impl MlKemSecurityLevel {
    /// Returns the algorithm name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            MlKemSecurityLevel::MlKem768 => "ML-KEM-768",
            MlKemSecurityLevel::MlKem1024 => "ML-KEM-1024",
        }
    }
}

/// ML-KEM key pair containing public and secret keys.
///
/// The secret key is automatically zeroized when dropped for security.
#[derive(ZeroizeOnDrop)]
pub struct MlKemKeyPair {
    /// Security level of this key pair.
    #[zeroize(skip)]
    pub security_level: MlKemSecurityLevel,

    /// Public key bytes (can be shared).
    #[zeroize(skip)]
    pub public_key: Vec<u8>,

    /// Secret key bytes (must be kept private).
    secret_key: Vec<u8>,
}

impl MlKemKeyPair {
    /// Creates a new key pair from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `level` - Security level of the key pair
    /// * `public_key` - Public key bytes
    /// * `secret_key` - Secret key bytes
    pub fn new(level: MlKemSecurityLevel, public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
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

/// ML-KEM ciphertext (encapsulated shared secret).
#[derive(Clone)]
pub struct MlKemCiphertext {
    /// Ciphertext bytes.
    pub ciphertext: Vec<u8>,

    /// Security level this ciphertext was created with.
    pub security_level: MlKemSecurityLevel,
}

impl MlKemCiphertext {
    /// Creates a new ciphertext from raw bytes.
    pub fn new(ciphertext: Vec<u8>, level: MlKemSecurityLevel) -> Self {
        Self {
            ciphertext,
            security_level: level,
        }
    }

    /// Returns a reference to the ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// ML-KEM cryptographic engine.
///
/// Provides key generation, encapsulation, and decapsulation operations
/// for ML-KEM (Kyber) key encapsulation mechanism.
pub struct MlKemEngine;

impl MlKemEngine {
    /// Generates a new ML-KEM key pair.
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
    /// - ML-KEM-768 keygen: ~50 microseconds
    /// - ML-KEM-1024 keygen: ~80 microseconds
    pub fn generate_keypair(level: MlKemSecurityLevel) -> Result<MlKemKeyPair> {
        match level {
            MlKemSecurityLevel::MlKem768 => {
                let (pk, sk) = mlkem768::keypair();
                Ok(MlKemKeyPair::new(
                    level,
                    pk.as_bytes().to_vec(),
                    sk.as_bytes().to_vec(),
                ))
            }
            MlKemSecurityLevel::MlKem1024 => {
                let (pk, sk) = mlkem1024::keypair();
                Ok(MlKemKeyPair::new(
                    level,
                    pk.as_bytes().to_vec(),
                    sk.as_bytes().to_vec(),
                ))
            }
        }
    }

    /// Encapsulates a shared secret using a public key.
    ///
    /// This operation is performed by the sender to create a shared secret
    /// and ciphertext. The ciphertext is sent to the recipient who can
    /// decapsulate it using their secret key.
    ///
    /// # Arguments
    ///
    /// * `public_key` - Recipient's public key bytes
    /// * `level` - Security level (must match the public key's level)
    ///
    /// # Returns
    ///
    /// A tuple of (shared_secret, ciphertext) on success.
    ///
    /// # Performance
    ///
    /// - ML-KEM-768 encapsulate: ~60 microseconds
    /// - ML-KEM-1024 encapsulate: ~90 microseconds
    pub fn encapsulate(
        public_key: &[u8],
        level: MlKemSecurityLevel,
    ) -> Result<(Vec<u8>, MlKemCiphertext)> {
        match level {
            MlKemSecurityLevel::MlKem768 => {
                let expected_size = Self::public_key_size(level);
                if public_key.len() != expected_size {
                    return Err(PqcError::InvalidKeySize {
                        algorithm: level.as_str(),
                        expected: expected_size,
                        actual: public_key.len(),
                    }
                    .into());
                }

                let pk = mlkem768::PublicKey::from_bytes(public_key).map_err(|_| {
                    PqcError::InvalidPublicKey {
                        algorithm: level.as_str(),
                    }
                })?;

                let (ss, ct) = mlkem768::encapsulate(&pk);

                Ok((
                    ss.as_bytes().to_vec(),
                    MlKemCiphertext::new(ct.as_bytes().to_vec(), level),
                ))
            }
            MlKemSecurityLevel::MlKem1024 => {
                let expected_size = Self::public_key_size(level);
                if public_key.len() != expected_size {
                    return Err(PqcError::InvalidKeySize {
                        algorithm: level.as_str(),
                        expected: expected_size,
                        actual: public_key.len(),
                    }
                    .into());
                }

                let pk = mlkem1024::PublicKey::from_bytes(public_key).map_err(|_| {
                    PqcError::InvalidPublicKey {
                        algorithm: level.as_str(),
                    }
                })?;

                let (ss, ct) = mlkem1024::encapsulate(&pk);

                Ok((
                    ss.as_bytes().to_vec(),
                    MlKemCiphertext::new(ct.as_bytes().to_vec(), level),
                ))
            }
        }
    }

    /// Decapsulates a ciphertext to recover the shared secret.
    ///
    /// This operation is performed by the recipient using their secret key
    /// to recover the shared secret from the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `keypair` - Recipient's key pair (containing the secret key)
    /// * `ciphertext` - Ciphertext received from the sender
    ///
    /// # Returns
    ///
    /// The shared secret bytes (32 bytes).
    ///
    /// # Performance
    ///
    /// - ML-KEM-768 decapsulate: ~50 microseconds
    /// - ML-KEM-1024 decapsulate: ~70 microseconds
    pub fn decapsulate(keypair: &MlKemKeyPair, ciphertext: &MlKemCiphertext) -> Result<Vec<u8>> {
        let level = keypair.security_level;

        match level {
            MlKemSecurityLevel::MlKem768 => {
                let expected_ct_size = Self::ciphertext_size(level);
                if ciphertext.ciphertext.len() != expected_ct_size {
                    return Err(PqcError::InvalidCiphertextSize {
                        algorithm: level.as_str(),
                        expected: expected_ct_size,
                        actual: ciphertext.ciphertext.len(),
                    }
                    .into());
                }

                let sk = mlkem768::SecretKey::from_bytes(&keypair.secret_key).map_err(|_| {
                    PqcError::InvalidSecretKey {
                        algorithm: level.as_str(),
                    }
                })?;

                let ct =
                    mlkem768::Ciphertext::from_bytes(&ciphertext.ciphertext).map_err(|_| {
                        PqcError::InvalidCiphertextSize {
                            algorithm: level.as_str(),
                            expected: expected_ct_size,
                            actual: ciphertext.ciphertext.len(),
                        }
                    })?;

                let ss = mlkem768::decapsulate(&ct, &sk);

                Ok(ss.as_bytes().to_vec())
            }
            MlKemSecurityLevel::MlKem1024 => {
                let expected_ct_size = Self::ciphertext_size(level);
                if ciphertext.ciphertext.len() != expected_ct_size {
                    return Err(PqcError::InvalidCiphertextSize {
                        algorithm: level.as_str(),
                        expected: expected_ct_size,
                        actual: ciphertext.ciphertext.len(),
                    }
                    .into());
                }

                let sk = mlkem1024::SecretKey::from_bytes(&keypair.secret_key).map_err(|_| {
                    PqcError::InvalidSecretKey {
                        algorithm: level.as_str(),
                    }
                })?;

                let ct =
                    mlkem1024::Ciphertext::from_bytes(&ciphertext.ciphertext).map_err(|_| {
                        PqcError::InvalidCiphertextSize {
                            algorithm: level.as_str(),
                            expected: expected_ct_size,
                            actual: ciphertext.ciphertext.len(),
                        }
                    })?;

                let ss = mlkem1024::decapsulate(&ct, &sk);

                Ok(ss.as_bytes().to_vec())
            }
        }
    }

    /// Returns the public key size in bytes for the given security level.
    pub fn public_key_size(level: MlKemSecurityLevel) -> usize {
        match level {
            MlKemSecurityLevel::MlKem768 => 1184,
            MlKemSecurityLevel::MlKem1024 => 1568,
        }
    }

    /// Returns the secret key size in bytes for the given security level.
    pub fn secret_key_size(level: MlKemSecurityLevel) -> usize {
        match level {
            MlKemSecurityLevel::MlKem768 => 2400,
            MlKemSecurityLevel::MlKem1024 => 3168,
        }
    }

    /// Returns the ciphertext size in bytes for the given security level.
    pub fn ciphertext_size(level: MlKemSecurityLevel) -> usize {
        match level {
            MlKemSecurityLevel::MlKem768 => 1088,
            MlKemSecurityLevel::MlKem1024 => 1568,
        }
    }

    /// Returns the shared secret size in bytes (always 32).
    pub fn shared_secret_size() -> usize {
        32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem_768_roundtrip() {
        let keypair = MlKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        assert_eq!(
            keypair.public_key.len(),
            MlKemEngine::public_key_size(MlKemSecurityLevel::MlKem768)
        );
        assert_eq!(
            keypair.secret_key().len(),
            MlKemEngine::secret_key_size(MlKemSecurityLevel::MlKem768)
        );

        let (shared1, ct) =
            MlKemEngine::encapsulate(&keypair.public_key, MlKemSecurityLevel::MlKem768).unwrap();

        assert_eq!(
            ct.ciphertext.len(),
            MlKemEngine::ciphertext_size(MlKemSecurityLevel::MlKem768)
        );
        assert_eq!(shared1.len(), MlKemEngine::shared_secret_size());

        let shared2 = MlKemEngine::decapsulate(&keypair, &ct).unwrap();

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_mlkem_1024_roundtrip() {
        let keypair = MlKemEngine::generate_keypair(MlKemSecurityLevel::MlKem1024).unwrap();

        assert_eq!(
            keypair.public_key.len(),
            MlKemEngine::public_key_size(MlKemSecurityLevel::MlKem1024)
        );
        assert_eq!(
            keypair.secret_key().len(),
            MlKemEngine::secret_key_size(MlKemSecurityLevel::MlKem1024)
        );

        let (shared1, ct) =
            MlKemEngine::encapsulate(&keypair.public_key, MlKemSecurityLevel::MlKem1024).unwrap();

        assert_eq!(
            ct.ciphertext.len(),
            MlKemEngine::ciphertext_size(MlKemSecurityLevel::MlKem1024)
        );
        assert_eq!(shared1.len(), MlKemEngine::shared_secret_size());

        let shared2 = MlKemEngine::decapsulate(&keypair, &ct).unwrap();

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_mlkem_invalid_public_key_size() {
        let invalid_pk = vec![0u8; 100]; // Wrong size
        let result = MlKemEngine::encapsulate(&invalid_pk, MlKemSecurityLevel::MlKem768);
        assert!(result.is_err());
    }

    #[test]
    fn test_mlkem_different_keys_different_secrets() {
        let keypair1 = MlKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
        let keypair2 = MlKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        // Encapsulate to keypair1
        let (shared1, ct1) =
            MlKemEngine::encapsulate(&keypair1.public_key, MlKemSecurityLevel::MlKem768).unwrap();

        // Encapsulate to keypair2
        let (shared2, _ct2) =
            MlKemEngine::encapsulate(&keypair2.public_key, MlKemSecurityLevel::MlKem768).unwrap();

        // Different recipients should get different shared secrets
        assert_ne!(shared1, shared2);

        // keypair1 can decapsulate ct1
        let recovered = MlKemEngine::decapsulate(&keypair1, &ct1).unwrap();
        assert_eq!(shared1, recovered);
    }

    #[test]
    fn test_mlkem_key_sizes() {
        assert_eq!(
            MlKemEngine::public_key_size(MlKemSecurityLevel::MlKem768),
            1184
        );
        assert_eq!(
            MlKemEngine::secret_key_size(MlKemSecurityLevel::MlKem768),
            2400
        );
        assert_eq!(
            MlKemEngine::ciphertext_size(MlKemSecurityLevel::MlKem768),
            1088
        );

        assert_eq!(
            MlKemEngine::public_key_size(MlKemSecurityLevel::MlKem1024),
            1568
        );
        assert_eq!(
            MlKemEngine::secret_key_size(MlKemSecurityLevel::MlKem1024),
            3168
        );
        assert_eq!(
            MlKemEngine::ciphertext_size(MlKemSecurityLevel::MlKem1024),
            1568
        );

        assert_eq!(MlKemEngine::shared_secret_size(), 32);
    }
}
