  //! Cryptographic hash functions.
//!
//! This module provides implementations of cryptographically secure hash
//! algorithms from the SHA-2 and SHA-3 families.

use crate::{HashAlgorithm, Result};
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_512};

/// Computes a cryptographic hash using the specified algorithm.
///
/// # Arguments
///
/// * `data` - Input data to hash (arbitrary length)
/// * `algorithm` - Hash algorithm to use
///
/// # Returns
///
/// Hash digest as a byte vector. Length depends on the algorithm:
/// - SHA-256 and SHA3-256: 32 bytes
/// - SHA-384: 48 bytes
/// - SHA-512 and SHA3-512: 64 bytes
///
/// # Errors
///
/// This function currently always succeeds for all supported algorithms.
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::hash::digest::hash;
/// use hsm_crypto_engine::HashAlgorithm;
///
/// let data = b"Hello, World!";
/// let digest = hash(data, HashAlgorithm::Sha256).unwrap();
/// assert_eq!(digest.len(), 32); // SHA-256 produces 32 bytes
/// ```
///
/// # Security
///
/// All hash functions provided are collision-resistant and suitable for:
/// - Message integrity verification
/// - Digital signature schemes
/// - HMAC construction
/// - Password hashing (with proper key derivation)
/// - Merkle trees and hash chains
///
/// # Performance
///
/// Hash performance is primarily determined by input size. Typical throughput:
/// - SHA-256: ~300 MiB/sec
/// - SHA-512: ~400 MiB/sec (faster on 64-bit systems)
/// - SHA3-256: ~150 MiB/sec
/// - SHA3-512: ~100 MiB/sec
pub fn hash(data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        HashAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        HashAlgorithm::Sha3_256 => {
            let mut hasher = Sha3_256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        HashAlgorithm::Sha3_512 => {
            let mut hasher = Sha3_512::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let result = hash(data, HashAlgorithm::Sha256).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha384() {
        let data = b"hello world";
        let result = hash(data, HashAlgorithm::Sha384).unwrap();
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_sha512() {
        let data = b"hello world";
        let result = hash(data, HashAlgorithm::Sha512).unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_sha3_256() {
        let data = b"hello world";
        let result = hash(data, HashAlgorithm::Sha3_256).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha3_512() {
        let data = b"hello world";
        let result = hash(data, HashAlgorithm::Sha3_512).unwrap();
        assert_eq!(result.len(), 64);
    }
}
