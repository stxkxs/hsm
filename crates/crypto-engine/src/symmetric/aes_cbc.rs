//! AES-CBC encryption (legacy mode).
//!
//! Provides AES encryption in Cipher Block Chaining (CBC) mode with PKCS#7 padding.
//! **Note**: CBC mode provides encryption only, not authentication. For new applications,
//! use AES-GCM instead which provides authenticated encryption.

use crate::{CryptoError, KeyMaterial, Result};
use aes::{Aes128, Aes256};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use getrandom::fill;

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// AES-CBC encryption engine.
///
/// Implements AES in Cipher Block Chaining (CBC) mode with PKCS#7 padding.
/// This is a legacy encryption mode that provides confidentiality only.
///
/// # Security Warning
///
/// CBC mode does NOT provide authentication. For secure applications, you should:
/// - Use AES-GCM instead (provides both encryption and authentication)
/// - Or combine CBC with HMAC for authentication
///
/// # Performance
///
/// CBC mode is faster than GCM on hardware without AES-NI, but lacks authentication:
/// - AES-256-CBC: ~150 MiB/sec
/// - AES-128-CBC: ~180 MiB/sec
pub struct AesCbcEngine;

impl AesCbcEngine {
    /// Encrypts plaintext using AES-256-CBC.
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit (32-byte) encryption key
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// Ciphertext with 16-byte IV prepended and PKCS#7 padding applied.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key size is not exactly 32 bytes
    /// - Insufficient system entropy for IV generation
    /// - Encryption operation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use hsm_crypto_engine::{KeyMaterial, symmetric::aes_cbc::AesCbcEngine};
    ///
    /// let key = KeyMaterial::from_bytes(vec![0x42; 32]);
    /// let plaintext = b"secret message";
    ///
    /// let ciphertext = AesCbcEngine::encrypt_aes256(&key, plaintext).unwrap();
    /// let decrypted = AesCbcEngine::decrypt_aes256(&key, &ciphertext).unwrap();
    /// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    /// ```
    ///
    /// # Security
    ///
    /// - IV is generated using cryptographically secure randomness
    /// - PKCS#7 padding is applied automatically
    /// - **No authentication** - vulnerable to padding oracle attacks if used incorrectly
    ///
    /// # Format
    ///
    /// Output format: `[IV (16 bytes)] || [ciphertext + padding]`
    pub fn encrypt_aes256(key: &KeyMaterial, plaintext: &[u8]) -> Result<Vec<u8>> {
        if key.as_bytes().len() != 32 {
            return Err(CryptoError::InvalidKey(
                "AES-256 requires 32-byte key".into(),
            ));
        }

        let mut iv = [0u8; 16];
        fill(&mut iv).map_err(|_| CryptoError::InsufficientEntropy)?;

        let mut buffer = vec![0u8; plaintext.len() + 16];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let cipher = Aes256CbcEnc::new(key.as_bytes().into(), &iv.into());
        let ciphertext_len = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?
            .len();

        let mut result = iv.to_vec();
        result.extend_from_slice(&buffer[..ciphertext_len]);

        Ok(result)
    }

    /// Decrypts ciphertext using AES-256-CBC.
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit (32-byte) decryption key
    /// * `ciphertext_with_iv` - Ciphertext with prepended IV
    ///
    /// # Returns
    ///
    /// Original plaintext with padding removed.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key size is not exactly 32 bytes
    /// - Ciphertext is smaller than 16 bytes (missing IV)
    /// - Padding is invalid
    /// - Decryption operation fails
    ///
    /// # Security
    ///
    /// No authentication is performed. Use AES-GCM for authenticated encryption.
    pub fn decrypt_aes256(key: &KeyMaterial, ciphertext_with_iv: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_iv.len() < 16 {
            return Err(CryptoError::DecryptionFailed("Invalid ciphertext".into()));
        }

        if key.as_bytes().len() != 32 {
            return Err(CryptoError::InvalidKey(
                "AES-256 requires 32-byte key".into(),
            ));
        }

        let (iv, ciphertext) = ciphertext_with_iv.split_at(16);

        let mut buffer = ciphertext.to_vec();
        let plaintext = Aes256CbcDec::new(key.as_bytes().into(), iv.into())
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext.to_vec())
    }

    /// Encrypts plaintext using AES-128-CBC.
    ///
    /// # Arguments
    ///
    /// * `key` - 128-bit (16-byte) encryption key
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// Ciphertext with 16-byte IV prepended and PKCS#7 padding applied.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key size is not exactly 16 bytes
    /// - Insufficient system entropy for IV generation
    ///
    /// # Security
    ///
    /// Same security considerations as AES-256-CBC. Use AES-GCM for new applications.
    pub fn encrypt_aes128(key: &KeyMaterial, plaintext: &[u8]) -> Result<Vec<u8>> {
        if key.as_bytes().len() != 16 {
            return Err(CryptoError::InvalidKey(
                "AES-128 requires 16-byte key".into(),
            ));
        }

        let mut iv = [0u8; 16];
        fill(&mut iv).map_err(|_| CryptoError::InsufficientEntropy)?;

        let mut buffer = vec![0u8; plaintext.len() + 16];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let cipher = Aes128CbcEnc::new(key.as_bytes().into(), &iv.into());
        let ciphertext_len = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?
            .len();

        let mut result = iv.to_vec();
        result.extend_from_slice(&buffer[..ciphertext_len]);

        Ok(result)
    }

    /// Decrypts ciphertext using AES-128-CBC.
    ///
    /// # Arguments
    ///
    /// * `key` - 128-bit (16-byte) decryption key
    /// * `ciphertext_with_iv` - Ciphertext with prepended IV
    ///
    /// # Returns
    ///
    /// Original plaintext with padding removed.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key size is not exactly 16 bytes
    /// - Ciphertext is smaller than 16 bytes
    /// - Padding is invalid
    pub fn decrypt_aes128(key: &KeyMaterial, ciphertext_with_iv: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_iv.len() < 16 {
            return Err(CryptoError::DecryptionFailed("Invalid ciphertext".into()));
        }

        if key.as_bytes().len() != 16 {
            return Err(CryptoError::InvalidKey(
                "AES-128 requires 16-byte key".into(),
            ));
        }

        let (iv, ciphertext) = ciphertext_with_iv.split_at(16);

        let mut buffer = ciphertext.to_vec();
        let plaintext = Aes128CbcDec::new(key.as_bytes().into(), iv.into())
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_cbc_roundtrip() {
        let key = KeyMaterial::from_bytes(vec![0x42; 32]);
        let plaintext = b"secret message that needs padding";

        let ciphertext = AesCbcEngine::encrypt_aes256(&key, plaintext).unwrap();
        let decrypted = AesCbcEngine::decrypt_aes256(&key, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aes128_cbc_roundtrip() {
        let key = KeyMaterial::from_bytes(vec![0x42; 16]);
        let plaintext = b"secret message that needs padding";

        let ciphertext = AesCbcEngine::encrypt_aes128(&key, plaintext).unwrap();
        let decrypted = AesCbcEngine::decrypt_aes128(&key, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aes256_cbc_invalid_key() {
        let key = KeyMaterial::from_bytes(vec![0x42; 16]); // Wrong size
        let plaintext = b"secret message";

        let result = AesCbcEngine::encrypt_aes256(&key, plaintext);
        assert!(result.is_err());
    }
}
