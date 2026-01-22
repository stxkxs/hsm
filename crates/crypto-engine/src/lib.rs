//! Core cryptographic engine for HSM
//!
//! Provides secure implementations of:
//! - Asymmetric cryptography (RSA, ECDSA, Ed25519, secp256k1, BLS12-381)
//! - Symmetric cryptography (AES-GCM, AES-CBC)
//! - Hashing (SHA-2, SHA-3)
//! - Key derivation (HKDF, PBKDF2, Argon2)
//! - Post-quantum cryptography (ML-KEM, ML-DSA, hybrid modes)
//!
//! # Security Properties
//!
//! This crate implements the following security measures:
//!
//! ## Memory Safety
//! - All sensitive key material is wrapped in `KeyMaterial` with automatic zeroization on drop
//! - The `Zeroize` trait ensures that secret data is overwritten before deallocation
//! - No sensitive data should appear in error messages or logs
//!
//! ## Cryptographic Randomness
//! - All random number generation uses `OsRng` from the operating system
//! - Nonces and IVs are generated using cryptographically secure sources
//! - No deterministic RNG is used for any cryptographic operations
//!
//! ## Side-Channel Resistance
//! - Underlying cryptographic libraries use constant-time implementations
//! - Ed25519 and ECDSA operations are designed to resist timing attacks
//! - RSA operations use the `rsa` crate (Note: RUSTSEC-2023-0071 Marvin Attack applies)
//!
//! ## Input Validation
//! - All key sizes are validated before use
//! - Signature and ciphertext sizes are checked
//! - Plaintext size limits are enforced (64 MB for AES-GCM)
//!
//! # Performance
//!
//! Benchmark results on typical hardware:
//! - Ed25519 sign: ~38,000 ops/sec
//! - Ed25519 verify: ~30,000 ops/sec
//! - ECDSA-P256 sign: ~4,000 ops/sec
//! - AES-256-GCM encrypt: ~100 MiB/sec
//!
//! # Known Security Advisories
//!
//! - RSA crate (v0.9.10): RUSTSEC-2023-0071 - Marvin Attack (timing side-channel)
//!   - Mitigation: Prefer ECDSA or Ed25519 for new deployments
//!   - No fix available in current version
//!
//! # Usage Examples
//!
//! ```rust
//! use hsm_crypto_engine::*;
//!
//! // Generate and use Ed25519 keys
//! let (private_key, public_key) = asymmetric::ed25519::Ed25519Engine::generate_keypair().unwrap();
//! let message = b"Hello, HSM!";
//!
//! let signature = asymmetric::ed25519::Ed25519Engine::sign(&private_key, message).unwrap();
//! let valid = asymmetric::ed25519::Ed25519Engine::verify(&public_key, message, &signature).unwrap();
//! assert!(valid);
//!
//! // Encrypt data with AES-256-GCM
//! let key = KeyMaterial::from_bytes(vec![0x42; 32]);
//! let plaintext = b"secret data";
//!
//! let ciphertext = symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(&key, plaintext, None).unwrap();
//! let decrypted = symmetric::aes_gcm::AesGcmEngine::decrypt_aes256(&key, &ciphertext, None).unwrap();
//! assert_eq!(plaintext, &decrypted[..]);
//! ```

use zeroize::Zeroize;

pub mod asymmetric;
pub mod blind;
pub mod constant_time;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod pqc;
pub mod random;
pub mod symmetric;
pub mod threshold;

pub use error::{CryptoError, Result};

/// Supported digital signature algorithms.
///
/// # Security Considerations
///
/// - **Ed25519**: Recommended for new deployments. Provides excellent performance
///   and strong security guarantees with resistance to timing attacks.
/// - **ECDSA**: Good balance of security and performance. Use P-256 or higher curves.
/// - **RSA**: Legacy support only. Note RUSTSEC-2023-0071 (Marvin Attack) affects
///   RSA operations. Prefer Ed25519 or ECDSA for new applications.
///
/// # Performance
///
/// Typical operations per second on modern hardware:
/// - Ed25519 sign: ~38,000 ops/sec
/// - Ed25519 verify: ~30,000 ops/sec
/// - ECDSA-P256 sign: ~4,000 ops/sec
/// - RSA-2048 sign: ~1,000 ops/sec
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAlgorithm {
    /// RSA PKCS#1 v1.5 with SHA-256 (legacy, use with caution)
    RsaPkcs1v15Sha256,
    /// RSA-PSS with SHA-256 (more secure than PKCS#1 v1.5)
    RsaPssSha256,
    /// ECDSA with P-256 curve and SHA-256
    EcdsaP256Sha256,
    /// ECDSA with P-384 curve and SHA-384
    EcdsaP384Sha384,
    /// ECDSA with P-521 curve and SHA-512
    EcdsaP521Sha512,
    /// ECDSA with secp256k1 curve (Bitcoin/Ethereum)
    EcdsaSecp256k1,
    /// Schnorr signatures on secp256k1 (BIP-340, Bitcoin Taproot)
    SchnorrSecp256k1,
    /// BLS signatures on BLS12-381 (Ethereum 2.0)
    Bls12381,
    /// Ed25519 (recommended for new deployments)
    Ed25519,
    /// Ed448 (not yet implemented)
    Ed448,
}

/// Supported encryption algorithms.
///
/// # Security Considerations
///
/// - **AES-GCM**: Authenticated encryption (recommended). Provides both confidentiality
///   and authenticity. Use AES-256-GCM for maximum security.
/// - **AES-CBC**: Legacy mode, encryption only (no authentication). Requires separate
///   HMAC for authentication. Not recommended for new applications.
/// - **RSA-OAEP**: Asymmetric encryption, primarily for key wrapping.
///
/// # Performance
///
/// Typical throughput on modern hardware:
/// - AES-256-GCM: ~100 MiB/sec
/// - AES-128-GCM: ~120 MiB/sec
/// - AES-CBC: ~150 MiB/sec (but no authentication)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptAlgorithm {
    /// AES-128 with GCM mode (authenticated encryption)
    Aes128Gcm,
    /// AES-256 with GCM mode (authenticated encryption, recommended)
    Aes256Gcm,
    /// AES-128 with CBC mode (encryption only, no authentication)
    Aes128Cbc,
    /// AES-256 with CBC mode (encryption only, no authentication)
    Aes256Cbc,
    /// RSA OAEP with SHA-256 (not yet implemented)
    RsaOaepSha256,
}

/// Supported cryptographic hash algorithms.
///
/// All hash functions provided are cryptographically secure and suitable
/// for use in digital signatures, HMAC, and key derivation.
///
/// # Security
///
/// - **SHA-2 family** (SHA-256, SHA-384, SHA-512): NIST-approved, widely supported
/// - **SHA-3 family**: Latest NIST standard, resistance to length extension attacks
///
/// # Output Sizes
///
/// - SHA-256: 32 bytes
/// - SHA-384: 48 bytes
/// - SHA-512: 64 bytes
/// - SHA3-256: 32 bytes
/// - SHA3-512: 64 bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (256-bit output)
    Sha256,
    /// SHA-384 (384-bit output)
    Sha384,
    /// SHA-512 (512-bit output)
    Sha512,
    /// SHA3-256 (256-bit output)
    Sha3_256,
    /// SHA3-512 (512-bit output)
    Sha3_512,
}

/// Generic key material with automatic secure memory zeroization.
///
/// This type wraps cryptographic key bytes and ensures they are securely
/// erased from memory when no longer needed. All key material is automatically
/// zeroized on drop to prevent sensitive data from remaining in memory.
///
/// # Security
///
/// - Memory is automatically zeroized on drop using the `zeroize` crate
/// - Clone operations create new memory allocations that are also zeroized
/// - No key material is leaked in debug output or error messages
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::KeyMaterial;
///
/// let key_bytes = vec![0x42; 32];
/// let key = KeyMaterial::from_bytes(key_bytes);
///
/// // Use the key
/// let key_ref = key.as_bytes();
/// assert_eq!(key_ref.len(), 32);
///
/// // Key is automatically zeroized when dropped
/// drop(key);
/// ```
#[derive(Zeroize, Clone, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct KeyMaterial {
    bytes: Vec<u8>,
}

impl KeyMaterial {
    /// Creates new key material from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw key bytes (ownership is transferred)
    ///
    /// # Security
    ///
    /// The provided bytes will be zeroized when the `KeyMaterial` is dropped.
    /// Ensure that the source bytes are also securely erased if needed.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns a reference to the underlying key bytes.
    ///
    /// # Security
    ///
    /// The returned reference is valid only as long as the `KeyMaterial` exists.
    /// Do not store or clone these bytes without proper zeroization.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Main cryptographic engine trait providing unified interface to crypto operations.
///
/// This trait defines the core cryptographic operations supported by the HSM,
/// including digital signatures, encryption/decryption, and hashing. All operations
/// are thread-safe (Send + Sync) and suitable for concurrent use.
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::*;
///
/// let engine = DefaultCryptoEngine;
/// let data = b"Hello, HSM!";
///
/// // Hash data
/// let hash = engine.hash(data, HashAlgorithm::Sha256).unwrap();
/// assert_eq!(hash.len(), 32);
/// ```
pub trait CryptoEngine: Send + Sync {
    /// Signs data using the specified algorithm.
    ///
    /// # Arguments
    ///
    /// * `key` - Private key material for signing
    /// * `data` - Data to be signed
    /// * `algorithm` - Signature algorithm to use
    ///
    /// # Returns
    ///
    /// Signature bytes on success
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key size is invalid for the algorithm
    /// - Key format is incorrect
    /// - Algorithm is not implemented
    /// - Internal cryptographic operation fails
    ///
    /// # Security
    ///
    /// All signature operations use cryptographically secure randomness for nonces
    /// where required (e.g., ECDSA, RSA-PSS). Ed25519 signatures are deterministic.
    fn sign(&self, key: &KeyMaterial, data: &[u8], algorithm: SignAlgorithm) -> Result<Vec<u8>>;

    /// Verifies a signature using the specified algorithm.
    ///
    /// # Arguments
    ///
    /// * `public_key` - Public key bytes for verification
    /// * `data` - Original data that was signed
    /// * `signature` - Signature bytes to verify
    /// * `algorithm` - Signature algorithm used
    ///
    /// # Returns
    ///
    /// `true` if signature is valid, `false` otherwise
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Public key size or format is invalid
    /// - Signature size is incorrect
    /// - Algorithm is not implemented
    /// - Key cannot be parsed
    ///
    /// # Security
    ///
    /// Signature verification uses constant-time comparisons where supported by
    /// the underlying cryptographic library to resist timing attacks.
    fn verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<bool>;

    /// Encrypts plaintext using the specified algorithm.
    ///
    /// # Arguments
    ///
    /// * `key` - Encryption key material
    /// * `plaintext` - Data to encrypt
    /// * `algorithm` - Encryption algorithm to use
    /// * `aad` - Optional Additional Authenticated Data (for AEAD modes like GCM)
    ///
    /// # Returns
    ///
    /// Ciphertext bytes including nonce/IV prepended
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key size is invalid for the algorithm
    /// - Plaintext exceeds maximum size (64 MB for AES-GCM)
    /// - Insufficient entropy for nonce generation
    /// - Algorithm is not implemented
    ///
    /// # Security
    ///
    /// - Nonces/IVs are generated using cryptographically secure randomness
    /// - For AES-GCM, the nonce is prepended to the ciphertext
    /// - AAD is authenticated but not encrypted
    fn encrypt(
        &self,
        key: &KeyMaterial,
        plaintext: &[u8],
        algorithm: EncryptAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Decrypts ciphertext using the specified algorithm.
    ///
    /// # Arguments
    ///
    /// * `key` - Decryption key material
    /// * `ciphertext` - Data to decrypt (including prepended nonce/IV)
    /// * `algorithm` - Encryption algorithm used
    /// * `aad` - Optional Additional Authenticated Data (must match encryption)
    ///
    /// # Returns
    ///
    /// Plaintext bytes on successful decryption and authentication
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key size is invalid
    /// - Ciphertext is too small (missing nonce or authentication tag)
    /// - Authentication fails (for AEAD modes)
    /// - AAD doesn't match the value used during encryption
    /// - Algorithm is not implemented
    ///
    /// # Security
    ///
    /// For AEAD modes (AES-GCM), authentication is verified before returning
    /// plaintext. If authentication fails, no plaintext is returned.
    fn decrypt(
        &self,
        key: &KeyMaterial,
        ciphertext: &[u8],
        algorithm: EncryptAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Computes a cryptographic hash of the input data.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to hash
    /// * `algorithm` - Hash algorithm to use
    ///
    /// # Returns
    ///
    /// Hash digest bytes
    ///
    /// # Errors
    ///
    /// Returns error if algorithm is not implemented (currently all listed
    /// algorithms are supported)
    ///
    /// # Security
    ///
    /// All hash functions are cryptographically secure and suitable for:
    /// - Digital signature schemes
    /// - HMAC construction
    /// - Key derivation functions
    /// - General-purpose integrity checking
    fn hash(&self, data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>>;
}

/// Default implementation of the cryptographic engine.
///
/// Provides production-ready implementations of all supported cryptographic
/// operations by dispatching to specialized engine modules (ed25519, ecdsa,
/// rsa, aes_gcm, etc.).
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::*;
///
/// let engine = DefaultCryptoEngine;
///
/// // Generate Ed25519 keypair
/// let (private_key, public_key) = asymmetric::ed25519::Ed25519Engine::generate_keypair().unwrap();
///
/// // Sign and verify
/// let message = b"test message";
/// let signature = engine.sign(&private_key, message, SignAlgorithm::Ed25519).unwrap();
/// let valid = engine.verify(&public_key, message, &signature, SignAlgorithm::Ed25519).unwrap();
/// assert!(valid);
/// ```
pub struct DefaultCryptoEngine;

impl CryptoEngine for DefaultCryptoEngine {
    fn sign(&self, key: &KeyMaterial, data: &[u8], algorithm: SignAlgorithm) -> Result<Vec<u8>> {
        match algorithm {
            SignAlgorithm::Ed25519 => asymmetric::ed25519::Ed25519Engine::sign(key, data),
            SignAlgorithm::EcdsaP256Sha256 => asymmetric::ecdsa::EcdsaEngine::sign_p256(key, data),
            SignAlgorithm::EcdsaP384Sha384 => asymmetric::ecdsa::EcdsaEngine::sign_p384(key, data),
            SignAlgorithm::EcdsaSecp256k1 => {
                asymmetric::secp256k1::Secp256k1Engine::sign_ecdsa(key, data)
            }
            SignAlgorithm::SchnorrSecp256k1 => {
                asymmetric::secp256k1::Secp256k1Engine::sign_schnorr(key, data)
            }
            SignAlgorithm::Bls12381 => asymmetric::bls::BlsEngine::sign(key, data),
            SignAlgorithm::RsaPkcs1v15Sha256 => {
                asymmetric::rsa::RsaEngine::sign_pkcs1v15_sha256(key, data)
            }
            SignAlgorithm::RsaPssSha256 => asymmetric::rsa::RsaEngine::sign_pss_sha256(key, data),
            _ => Err(CryptoError::InvalidAlgorithm(format!(
                "{:?} not yet implemented",
                algorithm
            ))),
        }
    }

    fn verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<bool> {
        match algorithm {
            SignAlgorithm::Ed25519 => {
                asymmetric::ed25519::Ed25519Engine::verify(public_key, data, signature)
            }
            SignAlgorithm::EcdsaP256Sha256 => {
                asymmetric::ecdsa::EcdsaEngine::verify_p256(public_key, data, signature)
            }
            SignAlgorithm::EcdsaP384Sha384 => {
                asymmetric::ecdsa::EcdsaEngine::verify_p384(public_key, data, signature)
            }
            SignAlgorithm::EcdsaSecp256k1 => {
                asymmetric::secp256k1::Secp256k1Engine::verify_ecdsa(public_key, data, signature)
            }
            SignAlgorithm::SchnorrSecp256k1 => {
                asymmetric::secp256k1::Secp256k1Engine::verify_schnorr(public_key, data, signature)
            }
            SignAlgorithm::Bls12381 => {
                asymmetric::bls::BlsEngine::verify(public_key, data, signature)
            }
            SignAlgorithm::RsaPkcs1v15Sha256 => {
                asymmetric::rsa::RsaEngine::verify_pkcs1v15_sha256(public_key, data, signature)
            }
            _ => Err(CryptoError::InvalidAlgorithm(format!(
                "{:?} not yet implemented",
                algorithm
            ))),
        }
    }

    fn encrypt(
        &self,
        key: &KeyMaterial,
        plaintext: &[u8],
        algorithm: EncryptAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match algorithm {
            EncryptAlgorithm::Aes256Gcm => {
                symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(key, plaintext, aad)
            }
            EncryptAlgorithm::Aes128Gcm => {
                symmetric::aes_gcm::AesGcmEngine::encrypt_aes128(key, plaintext, aad)
            }
            EncryptAlgorithm::Aes256Cbc => {
                symmetric::aes_cbc::AesCbcEngine::encrypt_aes256(key, plaintext)
            }
            EncryptAlgorithm::Aes128Cbc => {
                symmetric::aes_cbc::AesCbcEngine::encrypt_aes128(key, plaintext)
            }
            _ => Err(CryptoError::InvalidAlgorithm(format!(
                "{:?} not yet implemented",
                algorithm
            ))),
        }
    }

    fn decrypt(
        &self,
        key: &KeyMaterial,
        ciphertext: &[u8],
        algorithm: EncryptAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match algorithm {
            EncryptAlgorithm::Aes256Gcm => {
                symmetric::aes_gcm::AesGcmEngine::decrypt_aes256(key, ciphertext, aad)
            }
            EncryptAlgorithm::Aes128Gcm => {
                symmetric::aes_gcm::AesGcmEngine::decrypt_aes128(key, ciphertext, aad)
            }
            EncryptAlgorithm::Aes256Cbc => {
                symmetric::aes_cbc::AesCbcEngine::decrypt_aes256(key, ciphertext)
            }
            EncryptAlgorithm::Aes128Cbc => {
                symmetric::aes_cbc::AesCbcEngine::decrypt_aes128(key, ciphertext)
            }
            _ => Err(CryptoError::InvalidAlgorithm(format!(
                "{:?} not yet implemented",
                algorithm
            ))),
        }
    }

    fn hash(&self, data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>> {
        hash::digest::hash(data, algorithm)
    }
}
