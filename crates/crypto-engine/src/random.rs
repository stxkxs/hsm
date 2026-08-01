//! Cryptographically secure random number generation.
//!
//! Provides functions for generating random bytes using the operating
//! system's cryptographically secure random number generator.

use crate::{CryptoError, Result};
use getrandom::fill;

/// Generates cryptographically secure random bytes.
///
/// # Arguments
///
/// * `length` - Number of random bytes to generate
///
/// # Returns
///
/// Vector of cryptographically secure random bytes
///
/// # Errors
///
/// Returns error if insufficient system entropy is available.
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::random::generate_random_bytes;
///
/// let random_key = generate_random_bytes(32).unwrap();
/// assert_eq!(random_key.len(), 32);
///
/// // Two calls produce different values
/// let random_key2 = generate_random_bytes(32).unwrap();
/// assert_ne!(random_key, random_key2);
/// ```
///
/// # Security
///
/// Uses `getrandom` which provides cryptographically secure randomness from:
/// - Linux: `/dev/urandom` or `getrandom()` syscall
/// - macOS/iOS: `getentropy()` or `/dev/random`
/// - Windows: `BCryptGenRandom()`
///
/// # Performance
///
/// Random generation is very fast (~1 microsecond per 32 bytes).
pub fn generate_random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; length];
    fill(&mut buffer).map_err(|_| CryptoError::InsufficientEntropy)?;
    Ok(buffer)
}

/// Generates a cryptographically secure random u64.
///
/// # Returns
///
/// Random 64-bit unsigned integer
///
/// # Errors
///
/// Returns error if insufficient system entropy is available.
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::random::generate_random_u64;
///
/// let random_id = generate_random_u64().unwrap();
/// let random_id2 = generate_random_u64().unwrap();
/// assert_ne!(random_id, random_id2); // Very high probability
/// ```
///
/// # Use Cases
///
/// - Generating unique IDs
/// - Random session identifiers
/// - Nonce generation
/// - Sampling from ranges
pub fn generate_random_u64() -> Result<u64> {
    let mut buffer = [0u8; 8];
    fill(&mut buffer).map_err(|_| CryptoError::InsufficientEntropy)?;
    Ok(u64::from_le_bytes(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_bytes() {
        let bytes = generate_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);

        let bytes2 = generate_random_bytes(32).unwrap();
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_generate_random_u64() {
        let value1 = generate_random_u64().unwrap();
        let value2 = generate_random_u64().unwrap();

        assert_ne!(value1, value2);
    }

    #[test]
    fn test_generate_zero_length() {
        let bytes = generate_random_bytes(0).unwrap();
        assert_eq!(bytes.len(), 0);
    }
}
