//! RSA Blind Signatures (Chaum's Scheme)
//!
//! Based on David Chaum's 1983 paper "Blind Signatures for Untraceable Payments"
//!
//! # Protocol
//!
//! 1. **Blind**: Requester computes `m' = m * r^e mod n` where r is random
//! 2. **Sign**: Signer computes `s' = (m')^d mod n`
//! 3. **Unblind**: Requester computes `s = s' / r mod n`
//! 4. **Verify**: Anyone can verify `s^e = m mod n`
//!
//! # Security Properties
//!
//! - **Blindness**: The signer cannot link the unblinded signature to the blinding session
//! - **Unforgeability**: Valid signatures cannot be created without the signer's participation
//!
//! # Example
//!
//! ```rust,ignore
//! use hsm_crypto_engine::blind::{RsaBlindEngine, RsaBlindPublicKey, RsaBlindPrivateKey};
//!
//! // Generate keypair
//! let (private_key, public_key) = RsaBlindEngine::generate_keypair(2048)?;
//!
//! // Requester blinds the message
//! let message = b"secret ballot vote";
//! let (blinded_message, unblinding_factor) = RsaBlindEngine::blind(&public_key, message)?;
//!
//! // Signer signs the blinded message (learns nothing about original)
//! let blind_signature = RsaBlindEngine::sign_blinded(&private_key, &blinded_message)?;
//!
//! // Requester unblinds to get valid signature
//! let signature = RsaBlindEngine::unblind(&public_key, &blind_signature, &unblinding_factor)?;
//!
//! // Anyone can verify
//! assert!(RsaBlindEngine::verify(&public_key, message, &signature)?);
//! ```

use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::{One, Signed, Zero};
use rand::thread_rng;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::types::*;
use crate::hash::digest::hash;
use crate::HashAlgorithm;

/// RSA blind signature engine.
///
/// Implements Chaum's blind signature scheme for RSA keys.
pub struct RsaBlindEngine;

impl RsaBlindEngine {
    /// Generates an RSA keypair suitable for blind signatures.
    ///
    /// # Arguments
    ///
    /// * `bits` - Key size in bits (minimum 2048, recommended 3072+)
    ///
    /// # Returns
    ///
    /// Tuple of (private key, public key)
    ///
    /// # Errors
    ///
    /// Returns error if key generation fails.
    pub fn generate_keypair(
        bits: usize,
    ) -> Result<(RsaBlindPrivateKey, RsaBlindPublicKey), BlindError> {
        use rand_core::OsRng;
        use rsa::RsaPrivateKey;

        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| BlindError::KeyError(e.to_string()))?;

        // Extract components from private key (n, e are public parts, d is private)
        let n = private_key.n().to_bytes_be();
        let e = private_key.e().to_bytes_be();
        let d = private_key.d().to_bytes_be();

        Ok((
            RsaBlindPrivateKey {
                n: n.clone(),
                e: e.clone(),
                d,
            },
            RsaBlindPublicKey { n, e },
        ))
    }

    /// Blinds a message for signing.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The signer's public key
    /// * `message` - The message to be signed
    ///
    /// # Returns
    ///
    /// Tuple of (blinded message, unblinding factor)
    ///
    /// The unblinding factor must be kept secret and used to unblind the signature.
    ///
    /// # Errors
    ///
    /// Returns error if the message is too long for the key size.
    pub fn blind(
        public_key: &RsaBlindPublicKey,
        message: &[u8],
    ) -> Result<(BlindedMessage, UnblindingFactor), BlindError> {
        let n = BigUint::from_bytes_be(&public_key.n);
        let e = BigUint::from_bytes_be(&public_key.e);

        // Encode message using PKCS#1 v1.5 padding
        let m = Self::encode_message(message, public_key.bit_size())?;
        let m_int = BigUint::from_bytes_be(&m);

        // Generate random blinding factor r where gcd(r, n) = 1
        let mut rng = thread_rng();
        let r = loop {
            let candidate = rng.gen_biguint(public_key.bit_size() as u64);
            if candidate > BigUint::zero() && candidate < n && gcd(&candidate, &n) == BigUint::one()
            {
                break candidate;
            }
        };

        // Compute r^e mod n
        let r_e = r.modpow(&e, &n);

        // Compute blinded message: m' = m * r^e mod n
        let m_blinded = (&m_int * &r_e) % &n;

        // Pad the blinded message to the full key size
        let blinded_bytes = pad_to_key_size(m_blinded.to_bytes_be(), public_key.byte_size());

        Ok((
            BlindedMessage {
                bytes: blinded_bytes,
            },
            UnblindingFactor {
                bytes: r.to_bytes_be(),
            },
        ))
    }

    /// Signs a blinded message.
    ///
    /// The signer learns nothing about the original message.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The signer's private key
    /// * `blinded_message` - The blinded message from the requester
    ///
    /// # Returns
    ///
    /// A blind signature that must be unblinded by the requester.
    pub fn sign_blinded(
        private_key: &RsaBlindPrivateKey,
        blinded_message: &BlindedMessage,
    ) -> Result<BlindSignature, BlindError> {
        let n = BigUint::from_bytes_be(&private_key.n);
        let d = BigUint::from_bytes_be(&private_key.d);

        let m_blinded = BigUint::from_bytes_be(&blinded_message.bytes);

        // Verify blinded message is in valid range
        if m_blinded >= n {
            return Err(BlindError::BlindingFailed(
                "Blinded message >= modulus".into(),
            ));
        }

        // Compute s' = (m')^d mod n
        let s_blinded = m_blinded.modpow(&d, &n);

        // Pad to key size
        let byte_size = (private_key.n.len() * 8).div_ceil(8);
        let sig_bytes = pad_to_key_size(s_blinded.to_bytes_be(), byte_size);

        Ok(BlindSignature { bytes: sig_bytes })
    }

    /// Unblinds a signature to get the final valid signature.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The signer's public key
    /// * `blind_signature` - The blind signature from the signer
    /// * `unblinding_factor` - The secret unblinding factor from the blind operation
    ///
    /// # Returns
    ///
    /// The final signature that can be verified by anyone.
    pub fn unblind(
        public_key: &RsaBlindPublicKey,
        blind_signature: &BlindSignature,
        unblinding_factor: &UnblindingFactor,
    ) -> Result<Vec<u8>, BlindError> {
        let n = BigUint::from_bytes_be(&public_key.n);

        let s_blinded = BigUint::from_bytes_be(&blind_signature.bytes);
        let r = BigUint::from_bytes_be(&unblinding_factor.bytes);

        // Compute r_inv = r^(-1) mod n
        let r_inv = mod_inverse(&r, &n).ok_or(BlindError::InvalidBlindingFactor)?;

        // Compute s = s' * r^(-1) mod n
        let s = (&s_blinded * &r_inv) % &n;

        // Pad to key size
        Ok(pad_to_key_size(s.to_bytes_be(), public_key.byte_size()))
    }

    /// Verifies an unblinded signature.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The signer's public key
    /// * `message` - The original message
    /// * `signature` - The unblinded signature
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise.
    pub fn verify(
        public_key: &RsaBlindPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, BlindError> {
        let n = BigUint::from_bytes_be(&public_key.n);
        let e = BigUint::from_bytes_be(&public_key.e);

        let s = BigUint::from_bytes_be(signature);

        // Verify signature is in valid range
        if s >= n {
            return Ok(false);
        }

        // Compute s^e mod n
        let m_recovered = s.modpow(&e, &n);

        // Encode expected message
        let m_expected = Self::encode_message(message, public_key.bit_size())?;
        let m_expected_int = BigUint::from_bytes_be(&m_expected);

        // Constant-time comparison to prevent timing attacks
        let key_bytes = public_key.byte_size();
        let recovered_bytes = pad_to_key_size(m_recovered.to_bytes_be(), key_bytes);
        let expected_bytes = pad_to_key_size(m_expected_int.to_bytes_be(), key_bytes);
        use subtle::ConstantTimeEq;
        Ok(recovered_bytes.ct_eq(&expected_bytes).into())
    }

    /// Encodes a message using PKCS#1 v1.5 signature padding.
    ///
    /// Format: 0x00 || 0x01 || PS || 0x00 || DigestInfo
    /// where PS is padding bytes (0xFF) and DigestInfo contains the hash OID and hash value.
    fn encode_message(message: &[u8], key_bits: usize) -> Result<Vec<u8>, BlindError> {
        let key_bytes = key_bits.div_ceil(8);

        // Hash the message using SHA-256
        let hash_bytes = hash(message, HashAlgorithm::Sha256)
            .map_err(|e| BlindError::BlindingFailed(e.to_string()))?;

        // PKCS#1 v1.5 DigestInfo for SHA-256:
        // SEQUENCE {
        //   SEQUENCE {
        //     OBJECT IDENTIFIER sha256 (2.16.840.1.101.3.4.2.1)
        //     NULL
        //   }
        //   OCTET STRING <hash>
        // }
        let digest_info_prefix: &[u8] = &[
            0x30, 0x31, // SEQUENCE, length 49
            0x30, 0x0d, // SEQUENCE, length 13
            0x06, 0x09, // OID, length 9
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // sha256 OID
            0x05, 0x00, // NULL
            0x04, 0x20, // OCTET STRING, length 32
        ];

        let t_len = digest_info_prefix.len() + hash_bytes.len();

        if key_bytes < t_len + 11 {
            return Err(BlindError::MessageTooLong);
        }

        // Build: 0x00 || 0x01 || PS || 0x00 || T
        let ps_len = key_bytes - t_len - 3;
        let mut encoded = Vec::with_capacity(key_bytes);
        encoded.push(0x00);
        encoded.push(0x01);
        encoded.extend(std::iter::repeat_n(0xff, ps_len));
        encoded.push(0x00);
        encoded.extend_from_slice(digest_info_prefix);
        encoded.extend_from_slice(&hash_bytes);

        Ok(encoded)
    }
}

/// RSA public key components for blind signatures.
#[derive(Debug, Clone)]
pub struct RsaBlindPublicKey {
    /// RSA modulus n = p * q
    pub n: Vec<u8>,
    /// Public exponent e (typically 65537)
    pub e: Vec<u8>,
}

impl RsaBlindPublicKey {
    /// Returns the key size in bits.
    pub fn bit_size(&self) -> usize {
        self.n.len() * 8
    }

    /// Returns the key size in bytes.
    pub fn byte_size(&self) -> usize {
        self.n.len()
    }
}

/// RSA private key components for blind signatures.
///
/// # Security
///
/// Private key material is automatically zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RsaBlindPrivateKey {
    /// RSA modulus n = p * q
    pub n: Vec<u8>,
    /// Public exponent e (not zeroized as it's public)
    #[zeroize(skip)]
    pub e: Vec<u8>,
    /// Private exponent d
    pub d: Vec<u8>,
}

/// Computes the GCD of two BigUint values using Euclidean algorithm.
fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let mut a = a.clone();
    let mut b = b.clone();
    while !b.is_zero() {
        let t = b.clone();
        b = &a % &b;
        a = t;
    }
    a
}

/// Computes the modular inverse using extended Euclidean algorithm.
///
/// Returns `Some(a^(-1) mod n)` if gcd(a, n) = 1, `None` otherwise.
fn mod_inverse(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    let a = BigInt::from(a.clone());
    let n = BigInt::from(n.clone());

    let (mut old_r, mut r) = (n.clone(), a);
    let (mut old_s, mut s) = (BigInt::zero(), BigInt::one());

    while !r.is_zero() {
        let quotient = &old_r / &r;
        let temp_r = r.clone();
        r = &old_r - &quotient * &r;
        old_r = temp_r;

        let temp_s = s.clone();
        s = &old_s - &quotient * &s;
        old_s = temp_s;
    }

    if old_r != BigInt::one() {
        return None;
    }

    // Ensure positive result
    let result = if old_s.is_negative() {
        old_s + &n
    } else {
        old_s
    };

    Some(result.to_biguint().unwrap())
}

/// Pads a byte vector to the specified size with leading zeros.
fn pad_to_key_size(bytes: Vec<u8>, size: usize) -> Vec<u8> {
    if bytes.len() >= size {
        return bytes;
    }
    let mut padded = vec![0u8; size - bytes.len()];
    padded.extend(bytes);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_keypair() -> (RsaBlindPrivateKey, RsaBlindPublicKey) {
        RsaBlindEngine::generate_keypair(2048).unwrap()
    }

    #[test]
    fn test_blind_sign_unblind_verify() {
        let (private_key, public_key) = generate_test_keypair();
        let message = b"secret ballot vote";

        // Requester blinds
        let (blinded, factor) = RsaBlindEngine::blind(&public_key, message).unwrap();

        // Signer signs (doesn't see message)
        let blind_sig = RsaBlindEngine::sign_blinded(&private_key, &blinded).unwrap();

        // Requester unblinds
        let signature = RsaBlindEngine::unblind(&public_key, &blind_sig, &factor).unwrap();

        // Anyone can verify
        assert!(RsaBlindEngine::verify(&public_key, message, &signature).unwrap());
    }

    #[test]
    fn test_blind_signature_unlinkability() {
        let (private_key, public_key) = generate_test_keypair();

        // Sign same message twice with different blinding factors
        let message = b"same message";

        let (blinded1, factor1) = RsaBlindEngine::blind(&public_key, message).unwrap();
        let (blinded2, factor2) = RsaBlindEngine::blind(&public_key, message).unwrap();

        // Blinded messages should be different (different random r)
        assert_ne!(blinded1.bytes, blinded2.bytes);

        // Both should produce valid signatures
        let blind_sig1 = RsaBlindEngine::sign_blinded(&private_key, &blinded1).unwrap();
        let blind_sig2 = RsaBlindEngine::sign_blinded(&private_key, &blinded2).unwrap();

        let sig1 = RsaBlindEngine::unblind(&public_key, &blind_sig1, &factor1).unwrap();
        let sig2 = RsaBlindEngine::unblind(&public_key, &blind_sig2, &factor2).unwrap();

        // Signatures should be IDENTICAL (same message = same final signature)
        // This is a key property: the signer cannot link blinding sessions
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_wrong_message_fails_verification() {
        let (private_key, public_key) = generate_test_keypair();
        let message = b"original message";
        let wrong_message = b"wrong message";

        let (blinded, factor) = RsaBlindEngine::blind(&public_key, message).unwrap();
        let blind_sig = RsaBlindEngine::sign_blinded(&private_key, &blinded).unwrap();
        let signature = RsaBlindEngine::unblind(&public_key, &blind_sig, &factor).unwrap();

        // Verification with wrong message should fail
        assert!(!RsaBlindEngine::verify(&public_key, wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let (private_key1, public_key1) = generate_test_keypair();
        let (_, public_key2) = generate_test_keypair();
        let message = b"test message";

        let (blinded, factor) = RsaBlindEngine::blind(&public_key1, message).unwrap();
        let blind_sig = RsaBlindEngine::sign_blinded(&private_key1, &blinded).unwrap();
        let signature = RsaBlindEngine::unblind(&public_key1, &blind_sig, &factor).unwrap();

        // Verification with different key should fail
        assert!(!RsaBlindEngine::verify(&public_key2, message, &signature).unwrap());
    }

    #[test]
    fn test_gcd_function() {
        let a = BigUint::from(48u32);
        let b = BigUint::from(18u32);
        assert_eq!(gcd(&a, &b), BigUint::from(6u32));

        let a = BigUint::from(17u32);
        let b = BigUint::from(13u32);
        assert_eq!(gcd(&a, &b), BigUint::one());
    }

    #[test]
    fn test_mod_inverse() {
        // 3 * 5 = 15 = 1 mod 7
        let a = BigUint::from(3u32);
        let n = BigUint::from(7u32);
        let inv = mod_inverse(&a, &n).unwrap();
        assert_eq!((&a * &inv) % &n, BigUint::one());

        // No inverse when gcd != 1
        let a = BigUint::from(6u32);
        let n = BigUint::from(9u32);
        assert!(mod_inverse(&a, &n).is_none());
    }

    #[test]
    fn test_empty_message() {
        let (private_key, public_key) = generate_test_keypair();
        let message = b"";

        let (blinded, factor) = RsaBlindEngine::blind(&public_key, message).unwrap();
        let blind_sig = RsaBlindEngine::sign_blinded(&private_key, &blinded).unwrap();
        let signature = RsaBlindEngine::unblind(&public_key, &blind_sig, &factor).unwrap();

        assert!(RsaBlindEngine::verify(&public_key, message, &signature).unwrap());
    }

    #[test]
    fn test_large_message() {
        let (private_key, public_key) = generate_test_keypair();
        // Large message (will be hashed)
        let message = vec![0x42u8; 10000];

        let (blinded, factor) = RsaBlindEngine::blind(&public_key, &message).unwrap();
        let blind_sig = RsaBlindEngine::sign_blinded(&private_key, &blinded).unwrap();
        let signature = RsaBlindEngine::unblind(&public_key, &blind_sig, &factor).unwrap();

        assert!(RsaBlindEngine::verify(&public_key, &message, &signature).unwrap());
    }
}
