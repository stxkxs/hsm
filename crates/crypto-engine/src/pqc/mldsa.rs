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
//! | 65    | 1952 bytes | 32 bytes   | 3309 bytes|
//! | 87    | 2592 bytes | 32 bytes   | 4627 bytes|
//!
//! The secret key is the FIPS 204 key-generation seed ξ; the signing key is derived from
//! it for each signature. Signing is the hedged (randomized) ML-DSA.Sign with an empty
//! context string, drawing its randomness from the operating system, and verification
//! is ML-DSA.Verify with the same empty context.
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

use crate::{CryptoError, Result};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, MlDsa87, Seed, Signature, SigningKey,
    VerifyingKey,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::error::PqcError;

/// Length of the FIPS 204 key-generation seed ξ, which is the stored secret key.
const SEED_LEN: usize = 32;

/// ML-DSA.Sign and ML-DSA.Verify context string: empty, as for the plain FIPS 204 API.
const CONTEXT: &[u8] = &[];

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

    /// Secret key bytes: the FIPS 204 seed ξ (must be kept private for signing).
    secret_key: Vec<u8>,
}

impl MlDsaKeyPair {
    /// Creates a new key pair from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `level` - Security level of the key pair
    /// * `public_key` - Encoded verifying key
    /// * `secret_key` - FIPS 204 key-generation seed ξ
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
    /// The seed ξ is drawn from the operating system's CSPRNG.
    ///
    /// # Arguments
    ///
    /// * `level` - Security level to use
    ///
    /// # Returns
    ///
    /// A new key pair for the specified security level.
    pub fn generate_keypair(level: MlDsaSecurityLevel) -> Result<MlDsaKeyPair> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        getrandom::fill(seed.as_mut()).map_err(|_| CryptoError::InsufficientEntropy)?;
        Ok(Self::keypair_from_seed(level, &seed))
    }

    /// Derives the key pair FIPS 204 `ML-DSA.KeyGen_internal` produces from a seed.
    fn keypair_from_seed(level: MlDsaSecurityLevel, seed: &[u8; SEED_LEN]) -> MlDsaKeyPair {
        let xi = Zeroizing::new(Seed::from(*seed));
        let public_key = match level {
            MlDsaSecurityLevel::MlDsa65 => {
                let signing_key = SigningKey::<MlDsa65>::from_seed(&xi);
                signing_key.expanded_key().verifying_key().encode().to_vec()
            }
            MlDsaSecurityLevel::MlDsa87 => {
                let signing_key = SigningKey::<MlDsa87>::from_seed(&xi);
                signing_key.expanded_key().verifying_key().encode().to_vec()
            }
        };
        MlDsaKeyPair::new(level, public_key, seed.to_vec())
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
    pub fn sign(keypair: &MlDsaKeyPair, message: &[u8]) -> Result<MlDsaSignature> {
        let level = keypair.security_level;
        let xi = Zeroizing::new(Seed::try_from(keypair.secret_key.as_slice()).map_err(|_| {
            PqcError::InvalidSecretKey {
                algorithm: level.as_str(),
            }
        })?);
        let signing_failed = |_| PqcError::SigningFailed(level.as_str().to_string());

        let bytes = match level {
            MlDsaSecurityLevel::MlDsa65 => {
                let signing_key = SigningKey::<MlDsa65>::from_seed(&xi);
                signing_key
                    .expanded_key()
                    .sign_randomized(message, CONTEXT, &mut getrandom::SysRng)
                    .map_err(signing_failed)?
                    .encode()
                    .to_vec()
            }
            MlDsaSecurityLevel::MlDsa87 => {
                let signing_key = SigningKey::<MlDsa87>::from_seed(&xi);
                signing_key
                    .expanded_key()
                    .sign_randomized(message, CONTEXT, &mut getrandom::SysRng)
                    .map_err(signing_failed)?
                    .encode()
                    .to_vec()
            }
        };

        Ok(MlDsaSignature::new(bytes, level))
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
    /// `true` if the signature is valid, `false` otherwise, including for a signature
    /// whose encoding does not decode.
    pub fn verify(
        public_key: &[u8],
        message: &[u8],
        signature: &MlDsaSignature,
        level: MlDsaSecurityLevel,
    ) -> Result<bool> {
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

        let invalid_public_key = |_| PqcError::InvalidPublicKey {
            algorithm: level.as_str(),
        };
        let invalid_signature = |_| PqcError::InvalidSignatureSize {
            algorithm: level.as_str(),
            expected: expected_sig_size,
            actual: signature.bytes.len(),
        };

        let valid = match level {
            MlDsaSecurityLevel::MlDsa65 => {
                let vk = VerifyingKey::<MlDsa65>::decode(
                    &EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
                        .map_err(invalid_public_key)?,
                );
                let encoded = EncodedSignature::<MlDsa65>::try_from(signature.bytes.as_slice())
                    .map_err(invalid_signature)?;
                Signature::<MlDsa65>::decode(&encoded)
                    .is_some_and(|sig| vk.verify_with_context(message, CONTEXT, &sig))
            }
            MlDsaSecurityLevel::MlDsa87 => {
                let vk = VerifyingKey::<MlDsa87>::decode(
                    &EncodedVerifyingKey::<MlDsa87>::try_from(public_key)
                        .map_err(invalid_public_key)?,
                );
                let encoded = EncodedSignature::<MlDsa87>::try_from(signature.bytes.as_slice())
                    .map_err(invalid_signature)?;
                Signature::<MlDsa87>::decode(&encoded)
                    .is_some_and(|sig| vk.verify_with_context(message, CONTEXT, &sig))
            }
        };

        Ok(valid)
    }

    /// Returns the public key size in bytes for the given security level.
    pub fn public_key_size(level: MlDsaSecurityLevel) -> usize {
        match level {
            MlDsaSecurityLevel::MlDsa65 => 1952,
            MlDsaSecurityLevel::MlDsa87 => 2592,
        }
    }

    /// Returns the secret key size in bytes: the FIPS 204 seed ξ, at either level.
    pub fn secret_key_size(_level: MlDsaSecurityLevel) -> usize {
        SEED_LEN
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
    use sha2::{Digest, Sha256};

    /// The seed of the IETF LAMPS ML-DSA certificate examples: the bytes 0x00 through 0x1f.
    fn counting_seed() -> [u8; SEED_LEN] {
        core::array::from_fn(|i| i as u8)
    }

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
            32
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
            32
        );
        assert_eq!(
            MlDsaEngine::signature_size(MlDsaSecurityLevel::MlDsa87),
            4627
        );
    }

    #[test]
    fn test_mldsa_hedged_signatures_differ_and_verify() {
        let keypair = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
        let message = b"test message";

        let sig1 = MlDsaEngine::sign(&keypair, message).unwrap();
        let sig2 = MlDsaEngine::sign(&keypair, message).unwrap();

        for sig in [&sig1, &sig2] {
            assert!(MlDsaEngine::verify(
                &keypair.public_key,
                message,
                sig,
                MlDsaSecurityLevel::MlDsa65
            )
            .unwrap());
        }
        // Each signature draws 32 fresh bytes of randomness, so a repeat means the
        // randomness is not being used.
        assert_ne!(sig1.bytes, sig2.bytes);
    }

    /// Known answers: the verifying keys of the IETF LAMPS ML-DSA certificate examples
    /// (ML-DSA-65.pub and ML-DSA-87.pub, seed 0x00..0x1f), as SHA-256 of the raw key.
    #[test]
    fn test_mldsa_keygen_from_seed_matches_known_answers() {
        let cases = [
            (
                MlDsaSecurityLevel::MlDsa65,
                "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9",
            ),
            (
                MlDsaSecurityLevel::MlDsa87,
                "91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd",
            ),
        ];
        for (level, expected) in cases {
            let keypair = MlDsaEngine::keypair_from_seed(level, &counting_seed());
            assert_eq!(
                keypair.public_key.len(),
                MlDsaEngine::public_key_size(level)
            );
            assert_eq!(
                hex::encode(Sha256::digest(&keypair.public_key)),
                expected,
                "{}",
                level.as_str()
            );
        }
    }

    #[test]
    fn test_mldsa_tampered_signature_rejected() {
        for level in [MlDsaSecurityLevel::MlDsa65, MlDsaSecurityLevel::MlDsa87] {
            let keypair = MlDsaEngine::generate_keypair(level).unwrap();
            let message = b"tamper check";
            let mut signature = MlDsaEngine::sign(&keypair, message).unwrap();
            let last = signature.bytes.len() - 1;
            // Flip a bit in the challenge seed c~, then in the encoded hint.
            for index in [0, last] {
                signature.bytes[index] ^= 0x01;
                assert!(
                    !MlDsaEngine::verify(&keypair.public_key, message, &signature, level).unwrap(),
                    "{} accepted a signature altered at byte {index}",
                    level.as_str()
                );
                signature.bytes[index] ^= 0x01;
            }
        }
    }

    #[test]
    fn test_mldsa_rejects_malformed_secret_key() {
        let keypair = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
        let truncated = MlDsaKeyPair::new(
            MlDsaSecurityLevel::MlDsa65,
            keypair.public_key.clone(),
            keypair.secret_key()[..SEED_LEN - 1].to_vec(),
        );
        assert!(MlDsaEngine::sign(&truncated, b"message").is_err());
    }
}
