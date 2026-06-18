//! Stark Curve Key Types
//!
//! Provides key types for StarkNet ECDSA operations.

use crate::error::{BlockchainError, Result};
use starknet_crypto::{get_public_key, rfc6979_generate_k, sign, verify, Felt};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A Stark curve private key.
///
/// This type automatically zeroizes the key material on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StarkPrivateKey {
    /// The raw private key as a field element
    scalar: [u8; 32],
}

impl StarkPrivateKey {
    /// Create a new private key from raw bytes.
    ///
    /// The bytes should represent a valid scalar for the Stark curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(BlockchainError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(bytes);

        // Validate it's a valid scalar
        let _ = Felt::from_bytes_be_slice(&scalar);

        Ok(Self { scalar })
    }

    /// Generate a new random private key.
    pub fn generate() -> Self {
        let mut scalar = [0u8; 32];
        getrandom::getrandom(&mut scalar).expect("Failed to generate random bytes");

        // Ensure it's in valid range by masking top bits if needed
        // The Stark curve order is approximately 2^251, so we mask the top bits
        scalar[0] &= 0x07; // Ensure < 2^251

        Self { scalar }
    }

    /// Get the raw bytes of the private key.
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.scalar
    }

    /// Derive the public key from this private key.
    pub fn public_key(&self) -> StarkPublicKey {
        let private_felt = Felt::from_bytes_be_slice(&self.scalar);
        let public_felt = get_public_key(&private_felt);

        let bytes = public_felt.to_bytes_be();
        StarkPublicKey { point: bytes }
    }

    /// Sign a message hash with this private key.
    ///
    /// The message should already be hashed (typically with Pedersen or Poseidon).
    pub fn sign(&self, message_hash: &[u8; 32]) -> Result<super::StarkSignature> {
        let private_felt = Felt::from_bytes_be_slice(&self.scalar);
        let message_felt = Felt::from_bytes_be_slice(message_hash);

        // Generate random k for signature
        let mut k_bytes = [0u8; 32];
        getrandom::getrandom(&mut k_bytes).expect("Failed to generate random k");
        k_bytes[0] &= 0x07; // Ensure k < curve order
        let k = Felt::from_bytes_be_slice(&k_bytes);

        let extended_sig = sign(&private_felt, &message_felt, &k)
            .map_err(|e| BlockchainError::SigningFailed(e.to_string()))?;

        // Convert ExtendedSignature to our StarkSignature (r, s only)
        Ok(super::StarkSignature::new(
            extended_sig.r.to_bytes_be(),
            extended_sig.s.to_bytes_be(),
        ))
    }

    /// Sign a message hash with a deterministic nonce per RFC 6979,
    /// specialised for the Stark curve.
    ///
    /// This uses `starknet-crypto`'s `rfc6979_generate_k`, the same nonce
    /// derivation used by starknet-rs / starknet.js, so signatures are
    /// interoperable and reproducible. The previous implementation derived the
    /// nonce as `SHA256(scalar || hash)` masked to 251 bits, which is neither
    /// RFC 6979 nor curve-safe (LOW #27).
    pub fn sign_deterministic(&self, message_hash: &[u8; 32]) -> Result<super::StarkSignature> {
        let private_felt = Felt::from_bytes_be_slice(&self.scalar);
        let message_felt = Felt::from_bytes_be_slice(message_hash);

        // RFC 6979 deterministic nonce over the Stark curve.
        let k = rfc6979_generate_k(&message_felt, &private_felt, None);

        let extended_sig = sign(&private_felt, &message_felt, &k)
            .map_err(|e| BlockchainError::SigningFailed(e.to_string()))?;

        // Convert ExtendedSignature to our StarkSignature (r, s only)
        Ok(super::StarkSignature::new(
            extended_sig.r.to_bytes_be(),
            extended_sig.s.to_bytes_be(),
        ))
    }

    /// Derive a child key using a derivation path component.
    ///
    /// This uses a simple HMAC-based derivation scheme.
    pub fn derive_child(&self, index: u32) -> Result<Self> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&self.scalar)
            .map_err(|e| BlockchainError::DerivationFailed(e.to_string()))?;
        mac.update(&index.to_be_bytes());
        let result = mac.finalize();
        let mut child_bytes: [u8; 32] = result.into_bytes().into();

        // Ensure in valid range
        child_bytes[0] &= 0x07;

        Ok(Self {
            scalar: child_bytes,
        })
    }
}

impl std::fmt::Debug for StarkPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StarkPrivateKey")
            .field("scalar", &"<redacted>")
            .finish()
    }
}

/// A Stark curve public key.
#[derive(Clone, PartialEq, Eq)]
pub struct StarkPublicKey {
    /// The compressed public key (x-coordinate only for Stark curve)
    point: [u8; 32],
}

impl StarkPublicKey {
    /// Create a public key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(BlockchainError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut point = [0u8; 32];
        point.copy_from_slice(bytes);

        Ok(Self { point })
    }

    /// Get the raw bytes of the public key.
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.point
    }

    /// Convert to hex string (with 0x prefix).
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.point))
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| BlockchainError::InvalidHex(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Verify a signature against this public key.
    pub fn verify(&self, message_hash: &[u8; 32], signature: &super::StarkSignature) -> bool {
        let public_felt = Felt::from_bytes_be_slice(&self.point);
        let message_felt = Felt::from_bytes_be_slice(message_hash);
        let r_felt = Felt::from_bytes_be_slice(signature.r());
        let s_felt = Felt::from_bytes_be_slice(signature.s());

        // verify takes (public_key, message, r, s)
        verify(&public_felt, &message_felt, &r_felt, &s_felt).unwrap_or(false)
    }

    /// Derive the StarkNet address from this public key.
    pub fn to_address(&self) -> super::StarknetAddress {
        super::StarknetAddress::from_public_key(self)
    }
}

impl std::fmt::Debug for StarkPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StarkPublicKey")
            .field("point", &self.to_hex())
            .finish()
    }
}

impl std::fmt::Display for StarkPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let private_key = StarkPrivateKey::generate();
        let public_key = private_key.public_key();

        assert_eq!(private_key.to_bytes().len(), 32);
        assert_eq!(public_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_key_from_bytes() {
        let bytes = [0x01; 32];
        let private_key = StarkPrivateKey::from_bytes(&bytes).unwrap();

        assert_eq!(private_key.to_bytes(), &bytes);
    }

    #[test]
    fn test_invalid_key_length() {
        let bytes = [0x01; 31];
        let result = StarkPrivateKey::from_bytes(&bytes);

        assert!(result.is_err());
    }

    #[test]
    fn test_sign_and_verify() {
        let private_key = StarkPrivateKey::generate();
        let public_key = private_key.public_key();

        let message_hash = [0xab; 32];
        let signature = private_key.sign_deterministic(&message_hash).unwrap();

        assert!(public_key.verify(&message_hash, &signature));
    }

    #[test]
    fn test_sign_deterministic_is_deterministic() {
        let private_key = StarkPrivateKey::generate();
        let message_hash = [0xcd; 32];

        let sig1 = private_key.sign_deterministic(&message_hash).unwrap();
        let sig2 = private_key.sign_deterministic(&message_hash).unwrap();

        assert_eq!(sig1.r(), sig2.r());
        assert_eq!(sig1.s(), sig2.s());
    }

    #[test]
    fn test_invalid_signature_fails_verification() {
        let private_key = StarkPrivateKey::generate();
        let public_key = private_key.public_key();

        let message_hash = [0xef; 32];
        let signature = private_key.sign_deterministic(&message_hash).unwrap();

        let wrong_message = [0x00; 32];
        assert!(!public_key.verify(&wrong_message, &signature));
    }

    #[test]
    fn test_public_key_hex_roundtrip() {
        let private_key = StarkPrivateKey::generate();
        let public_key = private_key.public_key();

        let hex = public_key.to_hex();
        let parsed = StarkPublicKey::from_hex(&hex).unwrap();

        assert_eq!(public_key, parsed);
    }

    #[test]
    fn test_child_key_derivation() {
        let parent = StarkPrivateKey::generate();
        let child1 = parent.derive_child(0).unwrap();
        let child2 = parent.derive_child(1).unwrap();

        // Children should be different from parent and each other
        assert_ne!(parent.to_bytes(), child1.to_bytes());
        assert_ne!(parent.to_bytes(), child2.to_bytes());
        assert_ne!(child1.to_bytes(), child2.to_bytes());
    }

    #[test]
    fn test_child_derivation_is_deterministic() {
        let parent = StarkPrivateKey::generate();
        let child1 = parent.derive_child(42).unwrap();
        let child2 = parent.derive_child(42).unwrap();

        assert_eq!(child1.to_bytes(), child2.to_bytes());
    }

    /// Deterministic-nonce KAT for the Stark-curve RFC 6979 signer.
    ///
    /// The signature (r, s) is the canonical output of `starknet-crypto`'s
    /// `rfc6979_generate_k` + `sign` for a fixed private key and message hash
    /// (matching starknet-rs / starknet.js). This pins the exact nonce
    /// derivation so a regression to the old ad-hoc `SHA256(scalar || hash)`
    /// scheme — which produced an entirely different signature — is caught
    /// (LOW #27). The result is also checked to verify against the public key.
    #[test]
    fn test_sign_deterministic_rfc6979_kat() {
        let sk = StarkPrivateKey::from_bytes(&[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1u8,
        ])
        .unwrap();
        let mut h = [0u8; 32];
        h[31] = 0x09;
        h[30] = 0x02;

        let sig = sk.sign_deterministic(&h).unwrap();
        let (r, s) = sig.to_hex();
        assert_eq!(
            r,
            "0x0449cef352fbb21479b63383ac6e41ca540190fb1b00fc7d5551f25b3b9bda23"
        );
        assert_eq!(
            s,
            "0x073cc5b622e8adb809ddf1c6c904c28ac07d152170785164f927da7e170c9ad5"
        );

        // The deterministic signature must verify under the derived public key.
        let pk = sk.public_key();
        assert!(pk.verify(&h, &sig));

        // The old ad-hoc nonce scheme (SHA256(scalar || hash), masked) produced
        // a different r; ensure we are not reproducing it.
        let old_r = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(sk.to_bytes());
            hasher.update(h);
            let mut k_bytes: [u8; 32] = hasher.finalize().into();
            k_bytes[0] &= 0x07;
            let k = starknet_crypto::Felt::from_bytes_be_slice(&k_bytes);
            let ms = starknet_crypto::Felt::from_bytes_be_slice(&h);
            let pf = starknet_crypto::Felt::from_bytes_be_slice(sk.to_bytes());
            starknet_crypto::sign(&pf, &ms, &k).unwrap().r.to_bytes_be()
        };
        assert_ne!(hex::encode(old_r), r.trim_start_matches("0x"));
    }
}
