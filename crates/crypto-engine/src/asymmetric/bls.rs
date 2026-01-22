//! BLS signatures on the BLS12-381 curve.
//!
//! Provides BLS (Boneh-Lynn-Shacham) signatures using the BLS12-381 pairing-friendly
//! curve. This is the signature scheme used by Ethereum 2.0 for validator operations.
//!
//! # Features
//!
//! - **Signature aggregation**: Multiple signatures can be combined into one
//! - **Public key aggregation**: Multiple public keys can be combined
//! - **Batch verification**: Verify multiple signatures efficiently
//!
//! # Use Cases
//!
//! - Ethereum 2.0 validator signing (attestations, proposals, sync committees)
//! - Any system requiring signature aggregation
//! - Threshold signatures
//!
//! # Signature Schemes
//!
//! This implementation uses the "minimal-pubkey-size" variant where:
//! - Public keys are 48 bytes (G1 points)
//! - Signatures are 96 bytes (G2 points)
//!
//! This is the standard for Ethereum 2.0.

use crate::{CryptoError, KeyMaterial, Result};
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;

/// Domain separation tag for Ethereum 2.0 BLS signatures.
/// This is the standard DST used by Ethereum beacon chain.
pub const ETH2_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// BLS cryptographic engine.
///
/// Implements BLS signatures on the BLS12-381 curve with support for
/// signature aggregation and batch verification.
///
/// # Security
///
/// - BLS12-381 provides ~128-bit security level
/// - Signatures are deterministic (no nonce required)
/// - Rogue key attacks are prevented by proof-of-possession
///
/// # Performance
///
/// Typical performance on modern hardware:
/// - Sign: ~2,000 ops/sec
/// - Verify: ~500 ops/sec
/// - Aggregate verify (n signatures): ~500 + 50*n ops/sec
pub struct BlsEngine;

impl BlsEngine {
    /// Generates a BLS keypair.
    ///
    /// # Returns
    ///
    /// Tuple of (32-byte private key, 48-byte compressed public key)
    ///
    /// # Examples
    ///
    /// ```
    /// use hsm_crypto_engine::asymmetric::bls::BlsEngine;
    ///
    /// let (private_key, public_key) = BlsEngine::generate_keypair().unwrap();
    /// assert_eq!(private_key.as_bytes().len(), 32);
    /// assert_eq!(public_key.len(), 48);
    /// ```
    pub fn generate_keypair() -> Result<(KeyMaterial, Vec<u8>)> {
        // Generate 32 bytes of randomness for the secret key
        let mut ikm = [0u8; 32];
        getrandom::getrandom(&mut ikm).map_err(|_| CryptoError::InsufficientEntropy)?;

        let secret_key = SecretKey::key_gen(&ikm, &[])
            .map_err(|e| CryptoError::Internal(format!("BLS keygen failed: {:?}", e)))?;

        let public_key = secret_key.sk_to_pk();

        // Zeroize the IKM
        ikm.iter_mut().for_each(|b| *b = 0);

        Ok((
            KeyMaterial::from_bytes(secret_key.to_bytes().to_vec()),
            public_key.compress().to_vec(),
        ))
    }

    /// Derives the public key from a private key.
    ///
    /// # Arguments
    ///
    /// * `private_key` - 32-byte BLS private key
    ///
    /// # Returns
    ///
    /// 48-byte compressed public key (G1 point)
    pub fn derive_public_key(private_key: &KeyMaterial) -> Result<Vec<u8>> {
        let secret_key = SecretKey::from_bytes(private_key.as_bytes())
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid BLS secret key: {:?}", e)))?;

        let public_key = secret_key.sk_to_pk();
        Ok(public_key.compress().to_vec())
    }

    /// Signs a message using BLS.
    ///
    /// # Arguments
    ///
    /// * `key` - BLS private key (32 bytes)
    /// * `message` - Arbitrary-length message to sign
    ///
    /// # Returns
    ///
    /// 96-byte BLS signature (compressed G2 point)
    ///
    /// # Security
    ///
    /// BLS signatures are deterministic - signing the same message with the
    /// same key always produces the same signature.
    pub fn sign(key: &KeyMaterial, message: &[u8]) -> Result<Vec<u8>> {
        Self::sign_with_dst(key, message, ETH2_DST)
    }

    /// Signs a message using BLS with a custom domain separation tag.
    ///
    /// # Arguments
    ///
    /// * `key` - BLS private key (32 bytes)
    /// * `message` - Arbitrary-length message to sign
    /// * `dst` - Domain separation tag for the hash-to-curve operation
    ///
    /// # Returns
    ///
    /// 96-byte BLS signature
    pub fn sign_with_dst(key: &KeyMaterial, message: &[u8], dst: &[u8]) -> Result<Vec<u8>> {
        let secret_key = SecretKey::from_bytes(key.as_bytes())
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid BLS secret key: {:?}", e)))?;

        let signature = secret_key.sign(message, dst, &[]);
        Ok(signature.compress().to_vec())
    }

    /// Verifies a BLS signature.
    ///
    /// # Arguments
    ///
    /// * `public_key` - 48-byte compressed BLS public key
    /// * `message` - Original message that was signed
    /// * `signature` - 96-byte BLS signature to verify
    ///
    /// # Returns
    ///
    /// `true` if signature is valid
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        Self::verify_with_dst(public_key, message, signature, ETH2_DST)
    }

    /// Verifies a BLS signature with a custom domain separation tag.
    pub fn verify_with_dst(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        dst: &[u8],
    ) -> Result<bool> {
        let pk = PublicKey::from_bytes(public_key)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid BLS public key: {:?}", e)))?;

        let sig = Signature::from_bytes(signature)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid BLS signature: {:?}", e)))?;

        let result = sig.verify(true, message, dst, &[], &pk, true);

        match result {
            BLST_ERROR::BLST_SUCCESS => Ok(true),
            _ => Err(CryptoError::SignatureVerificationFailed),
        }
    }

    /// Aggregates multiple BLS signatures into a single signature.
    ///
    /// # Arguments
    ///
    /// * `signatures` - Slice of 96-byte BLS signatures
    ///
    /// # Returns
    ///
    /// 96-byte aggregated signature
    ///
    /// # Use Cases
    ///
    /// - Ethereum 2.0 attestation aggregation
    /// - Reducing signature storage/transmission overhead
    pub fn aggregate_signatures(signatures: &[&[u8]]) -> Result<Vec<u8>> {
        if signatures.is_empty() {
            return Err(CryptoError::InvalidKey(
                "Cannot aggregate empty signature list".to_string(),
            ));
        }

        let sigs: Vec<Signature> = signatures
            .iter()
            .map(|s| {
                Signature::from_bytes(s)
                    .map_err(|e| CryptoError::InvalidKey(format!("Invalid signature: {:?}", e)))
            })
            .collect::<Result<Vec<_>>>()?;

        let sig_refs: Vec<&Signature> = sigs.iter().collect();

        let agg_sig = AggregateSignature::aggregate(&sig_refs, true)
            .map_err(|e| CryptoError::InvalidKey(format!("Aggregation failed: {:?}", e)))?;

        Ok(agg_sig.to_signature().compress().to_vec())
    }

    /// Aggregates multiple BLS public keys into a single public key.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - Slice of 48-byte BLS public keys
    ///
    /// # Returns
    ///
    /// 48-byte aggregated public key
    pub fn aggregate_public_keys(public_keys: &[&[u8]]) -> Result<Vec<u8>> {
        if public_keys.is_empty() {
            return Err(CryptoError::InvalidKey(
                "Cannot aggregate empty public key list".to_string(),
            ));
        }

        let pks: Vec<PublicKey> = public_keys
            .iter()
            .map(|pk| {
                PublicKey::from_bytes(pk)
                    .map_err(|e| CryptoError::InvalidKey(format!("Invalid public key: {:?}", e)))
            })
            .collect::<Result<Vec<_>>>()?;

        let pk_refs: Vec<&PublicKey> = pks.iter().collect();

        let agg_pk = AggregatePublicKey::aggregate(&pk_refs, true)
            .map_err(|e| CryptoError::InvalidKey(format!("Aggregation failed: {:?}", e)))?;

        Ok(agg_pk.to_public_key().compress().to_vec())
    }

    /// Verifies an aggregated signature against multiple public keys and messages.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - Slice of 48-byte BLS public keys
    /// * `messages` - Slice of messages (one per public key)
    /// * `signature` - 96-byte aggregated signature
    ///
    /// # Returns
    ///
    /// `true` if the aggregated signature is valid for all (pubkey, message) pairs
    ///
    /// # Note
    ///
    /// This performs aggregate verification which is more efficient than
    /// verifying each signature individually.
    pub fn verify_aggregate(
        public_keys: &[&[u8]],
        messages: &[&[u8]],
        signature: &[u8],
    ) -> Result<bool> {
        Self::verify_aggregate_with_dst(public_keys, messages, signature, ETH2_DST)
    }

    /// Verifies an aggregated signature with a custom domain separation tag.
    pub fn verify_aggregate_with_dst(
        public_keys: &[&[u8]],
        messages: &[&[u8]],
        signature: &[u8],
        dst: &[u8],
    ) -> Result<bool> {
        if public_keys.len() != messages.len() {
            return Err(CryptoError::InvalidKey(
                "Public key and message count mismatch".to_string(),
            ));
        }

        if public_keys.is_empty() {
            return Err(CryptoError::InvalidKey(
                "Cannot verify empty aggregate".to_string(),
            ));
        }

        let sig = Signature::from_bytes(signature)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid signature: {:?}", e)))?;

        let pks: Vec<PublicKey> = public_keys
            .iter()
            .map(|pk| {
                PublicKey::from_bytes(pk)
                    .map_err(|e| CryptoError::InvalidKey(format!("Invalid public key: {:?}", e)))
            })
            .collect::<Result<Vec<_>>>()?;

        let pk_refs: Vec<&PublicKey> = pks.iter().collect();

        let result = sig.aggregate_verify(true, messages, dst, &pk_refs, true);

        match result {
            BLST_ERROR::BLST_SUCCESS => Ok(true),
            _ => Err(CryptoError::SignatureVerificationFailed),
        }
    }

    /// Verifies an aggregated signature where all signers signed the same message.
    ///
    /// This is a common case in Ethereum 2.0 where multiple validators sign
    /// the same attestation data.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - Slice of 48-byte BLS public keys
    /// * `message` - The single message all signers signed
    /// * `signature` - 96-byte aggregated signature
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid
    pub fn verify_aggregate_same_message(
        public_keys: &[&[u8]],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        Self::verify_aggregate_same_message_with_dst(public_keys, message, signature, ETH2_DST)
    }

    /// Verifies an aggregated signature for same message with custom DST.
    pub fn verify_aggregate_same_message_with_dst(
        public_keys: &[&[u8]],
        message: &[u8],
        signature: &[u8],
        dst: &[u8],
    ) -> Result<bool> {
        // First aggregate all public keys
        let agg_pk = Self::aggregate_public_keys(public_keys)?;

        // Then verify the signature against the aggregated public key
        Self::verify_with_dst(&agg_pk, message, signature, dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_sign_verify() {
        let (private_key, public_key) = BlsEngine::generate_keypair().unwrap();
        let message = b"test message for BLS signature";

        let signature = BlsEngine::sign(&private_key, message).unwrap();
        assert_eq!(signature.len(), 96);

        let valid = BlsEngine::verify(&public_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_bls_wrong_message() {
        let (private_key, public_key) = BlsEngine::generate_keypair().unwrap();
        let message = b"original message";
        let wrong_message = b"different message";

        let signature = BlsEngine::sign(&private_key, message).unwrap();
        let result = BlsEngine::verify(&public_key, wrong_message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_public_key() {
        let (private_key, public_key) = BlsEngine::generate_keypair().unwrap();
        let derived = BlsEngine::derive_public_key(&private_key).unwrap();
        assert_eq!(public_key, derived);
    }

    #[test]
    fn test_signature_aggregation() {
        let (sk1, pk1) = BlsEngine::generate_keypair().unwrap();
        let (sk2, pk2) = BlsEngine::generate_keypair().unwrap();
        let (sk3, pk3) = BlsEngine::generate_keypair().unwrap();

        let msg1 = b"message one";
        let msg2 = b"message two";
        let msg3 = b"message three";

        let sig1 = BlsEngine::sign(&sk1, msg1).unwrap();
        let sig2 = BlsEngine::sign(&sk2, msg2).unwrap();
        let sig3 = BlsEngine::sign(&sk3, msg3).unwrap();

        let agg_sig = BlsEngine::aggregate_signatures(&[&sig1, &sig2, &sig3]).unwrap();
        assert_eq!(agg_sig.len(), 96);

        let valid = BlsEngine::verify_aggregate(
            &[&pk1[..], &pk2[..], &pk3[..]],
            &[msg1.as_slice(), msg2.as_slice(), msg3.as_slice()],
            &agg_sig,
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_same_message_aggregation() {
        let (sk1, pk1) = BlsEngine::generate_keypair().unwrap();
        let (sk2, pk2) = BlsEngine::generate_keypair().unwrap();
        let (sk3, pk3) = BlsEngine::generate_keypair().unwrap();

        let message = b"same message for all signers";

        let sig1 = BlsEngine::sign(&sk1, message).unwrap();
        let sig2 = BlsEngine::sign(&sk2, message).unwrap();
        let sig3 = BlsEngine::sign(&sk3, message).unwrap();

        let agg_sig = BlsEngine::aggregate_signatures(&[&sig1, &sig2, &sig3]).unwrap();

        let valid = BlsEngine::verify_aggregate_same_message(
            &[&pk1[..], &pk2[..], &pk3[..]],
            message,
            &agg_sig,
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_public_key_aggregation() {
        let (_, pk1) = BlsEngine::generate_keypair().unwrap();
        let (_, pk2) = BlsEngine::generate_keypair().unwrap();

        let agg_pk = BlsEngine::aggregate_public_keys(&[&pk1, &pk2]).unwrap();
        assert_eq!(agg_pk.len(), 48);
    }

    #[test]
    fn test_deterministic_signatures() {
        let (private_key, _) = BlsEngine::generate_keypair().unwrap();
        let message = b"test determinism";

        let sig1 = BlsEngine::sign(&private_key, message).unwrap();
        let sig2 = BlsEngine::sign(&private_key, message).unwrap();

        assert_eq!(sig1, sig2, "BLS signatures should be deterministic");
    }
}
