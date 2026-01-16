//! HKDF (HMAC-based Key Derivation Function).
//!
//! HKDF is a simple and well-studied key derivation function based on HMAC.
//! It's suitable for deriving multiple cryptographic keys from a single
//! shared secret.
//!
//! # Use Cases
//!
//! - Deriving encryption and MAC keys from a master key
//! - Key expansion in key agreement protocols (e.g., TLS)
//! - Deriving session keys from a long-term secret

use crate::Result;
use hkdf::Hkdf;
use sha2::Sha256;

/// Derives a key using HKDF-SHA256.
///
/// # Arguments
///
/// * `input_key` - Input key material (IKM), the source secret
/// * `salt` - Optional salt value (use empty slice for no salt)
/// * `info` - Context and application-specific information
/// * `output_len` - Desired output length in bytes
///
/// # Returns
///
/// Derived key of `output_len` bytes
///
/// # Errors
///
/// Returns error if output length exceeds 255 * 32 bytes (HKDF limit).
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::kdf::hkdf::derive_key;
///
/// let master_key = b"my master secret key material";
/// let salt = b"optional salt value";
/// let info = b"encryption key v1";
///
/// let enc_key = derive_key(master_key, salt, info, 32).unwrap();
/// assert_eq!(enc_key.len(), 32);
///
/// // Derive a different key from same master with different info
/// let mac_key = derive_key(master_key, salt, b"mac key v1", 32).unwrap();
/// assert_ne!(enc_key, mac_key);
/// ```
///
/// # Security
///
/// - **Deterministic**: Same inputs always produce same output
/// - **Domain separation**: Use different `info` values for different purposes
/// - **Salt optional**: Improves security if source key has low entropy
///
/// # Performance
///
/// HKDF is very fast (~1-2 microseconds) and suitable for deriving many keys.
pub fn derive_key(
    input_key: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), input_key);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .map_err(|e| crate::CryptoError::Internal(e.to_string()))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derive() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let key = derive_key(ikm, salt, info, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let key1 = derive_key(ikm, salt, info, 32).unwrap();
        let key2 = derive_key(ikm, salt, info, 32).unwrap();
        assert_eq!(key1, key2);
    }
}
