//! PBKDF2 (Password-Based Key Derivation Function 2).
//!
//! PBKDF2 is a widely-supported password-based key derivation function.
//! For new applications, consider using Argon2 instead, which provides
//! better resistance to GPU-based attacks.
//!
//! # Use Cases
//!
//! - Legacy systems requiring PBKDF2
//! - Compliance with older standards (e.g., NIST SP 800-132)
//! - Systems where Argon2 is not available

use crate::Result;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// Derives a key from a password using PBKDF2-HMAC-SHA256.
///
/// # Arguments
///
/// * `password` - Password bytes to derive from
/// * `salt` - Salt value (recommended: 16+ bytes random)
/// * `iterations` - Number of PBKDF2 iterations (higher = slower but more secure)
/// * `output_len` - Desired output length in bytes
///
/// # Returns
///
/// Derived key of `output_len` bytes
///
/// # Errors
///
/// This function always succeeds.
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::kdf::pbkdf2::derive_key;
///
/// let password = b"user password";
/// let salt = b"random salt value 123";
///
/// // 100,000 iterations (NIST minimum for 2024)
/// let key = derive_key(password, salt, 100_000, 32).unwrap();
/// assert_eq!(key.len(), 32);
/// ```
///
/// # Security
///
/// **Iteration Guidelines**:
/// - **Minimum (2024)**: 100,000 iterations
/// - **Recommended**: 600,000 iterations
/// - **High security**: 1,000,000+ iterations
///
/// **Note**: PBKDF2 is vulnerable to GPU cracking. For new applications,
/// use Argon2 which provides memory-hardness.
///
/// # Performance
///
/// PBKDF2 is intentionally slow:
/// - 100,000 iterations: ~10ms
/// - 600,000 iterations: ~60ms
/// - 1,000,000 iterations: ~100ms
///
/// Adjust iterations based on acceptable authentication time vs. security requirements.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Result<Vec<u8>> {
    let mut output = vec![0u8; output_len];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_derive() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 10000;

        let key = derive_key(password, salt, iterations, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_pbkdf2_deterministic() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 10000;

        let key1 = derive_key(password, salt, iterations, 32).unwrap();
        let key2 = derive_key(password, salt, iterations, 32).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_pbkdf2_different_iterations() {
        let password = b"password";
        let salt = b"salt";

        let key1 = derive_key(password, salt, 1000, 32).unwrap();
        let key2 = derive_key(password, salt, 2000, 32).unwrap();
        assert_ne!(key1, key2);
    }
}
