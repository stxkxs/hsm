//! Argon2 password hashing and key derivation.
//!
//! Argon2 is the winner of the Password Hashing Competition (2015) and is
//! the recommended algorithm for password hashing and key derivation from
//! passwords. It provides strong resistance to GPU cracking attacks.
//!
//! # Advantages
//!
//! - **Memory-hard**: Resistant to GPU/ASIC attacks
//! - **Configurable**: Tune memory, time, and parallelism
//! - **Modern**: Specifically designed for password hashing

use crate::Result;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::OsRng;

/// Derives a key from a password using Argon2id.
///
/// # Arguments
///
/// * `password` - Password bytes to derive from
/// * `salt` - Optional salt (minimum 16 bytes if provided, random if None)
/// * `m_cost` - Memory cost in KiB (e.g., 4096 = 4 MiB)
/// * `t_cost` - Time cost (iterations, e.g., 3)
/// * `p_cost` - Parallelism factor (e.g., 1)
/// * `output_len` - Desired output length in bytes
///
/// # Returns
///
/// Derived key of `output_len` bytes
///
/// # Errors
///
/// Returns error if:
/// - Salt is provided but less than 16 bytes
/// - Parameters are invalid
/// - Derivation fails
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::kdf::argon2::derive_key;
///
/// let password = b"my secure password";
/// let salt = b"sixteen byte salt here!"; // Min 16 bytes
///
/// // Moderate security: 4 MiB memory, 3 iterations, single-threaded
/// let key = derive_key(password, Some(salt), 4096, 3, 1, 32).unwrap();
/// assert_eq!(key.len(), 32);
/// ```
///
/// # Security
///
/// **Parameter Guidelines**:
/// - **Low security**: m_cost=4096, t_cost=1, p_cost=1 (~10ms)
/// - **Moderate**: m_cost=4096, t_cost=3, p_cost=1 (~30ms, recommended)
/// - **High**: m_cost=65536, t_cost=4, p_cost=1 (~500ms)
///
/// Higher parameters = slower but more secure against brute force.
///
/// # Performance
///
/// Argon2 is intentionally slow to resist brute-force attacks:
/// - With recommended parameters: ~30ms per derivation
/// - Adjust based on acceptable login time vs. security requirements
pub fn derive_key(
    password: &[u8],
    salt: Option<&[u8]>,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: usize,
) -> Result<Vec<u8>> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(output_len))
        .map_err(|e| crate::CryptoError::Internal(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let salt_string = if let Some(s) = salt {
        if s.len() < 16 {
            return Err(crate::CryptoError::Internal(
                "Salt must be at least 16 bytes".into(),
            ));
        }
        SaltString::encode_b64(s).map_err(|e| crate::CryptoError::Internal(e.to_string()))?
    } else {
        SaltString::generate(&mut OsRng)
    };

    let mut output = vec![0u8; output_len];
    argon2
        .hash_password_into(password, salt_string.as_str().as_bytes(), &mut output)
        .map_err(|e| crate::CryptoError::Internal(e.to_string()))?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_derive() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt"; // 16 bytes minimum

        let key = derive_key(password, Some(salt), 4096, 3, 1, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_argon2_deterministic() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";

        let key1 = derive_key(password, Some(salt), 4096, 3, 1, 32).unwrap();
        let key2 = derive_key(password, Some(salt), 4096, 3, 1, 32).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_argon2_random_salt() {
        let password = b"password";

        let key = derive_key(password, None, 4096, 3, 1, 32).unwrap();
        assert_eq!(key.len(), 32);
    }
}
