# Plan 3.3: Blind Signatures

## Overview

Implement blind signature schemes that allow signing messages without the signer seeing the content. The signer learns nothing about the message, but produces a signature that can be verified by anyone.

## Goals

- RSA blind signatures (Chaum's scheme)
- BLS blind signatures (optional, if BLS is added)
- Partially blind signatures (signer sees some metadata)
- Audit-compatible modes (log that signing occurred without message)
- Privacy-preserving credential issuance

## Use Cases

- **Anonymous voting**: Sign ballot without seeing vote
- **Digital cash**: Issue tokens without tracking spending
- **Privacy credentials**: Issue attributes without linking to identity
- **Certificate transparency**: Prove signing occurred without revealing content

## Dependencies

Add to `crates/crypto-engine/Cargo.toml`:

```toml
[dependencies]
# For RSA blind signatures (already have RSA support)
num-bigint = "0.4"
num-traits = "0.2"

# Optional: BLS signatures
# blst = "0.3"  # BLS12-381
```

## File Structure

```
crates/crypto-engine/src/
├── blind/
│   ├── mod.rs              # Module exports
│   ├── rsa_blind.rs        # RSA blind signatures
│   ├── partially_blind.rs  # Partially blind signatures
│   └── types.rs            # Shared types
├── lib.rs                  # Add: pub mod blind;
└── ...
```

## Implementation Steps

### Step 1: Create Blind Module

Create `crates/crypto-engine/src/blind/mod.rs`:

```rust
//! Blind Signature module
//!
//! Blind signatures allow a signer to sign a message without seeing its content.
//! The signer learns nothing about the message, but the resulting signature
//! can be verified by anyone with the public key.
//!
//! # Schemes
//!
//! - **RSA Blind Signatures**: Based on Chaum's original scheme
//! - **Partially Blind Signatures**: Signer sees some metadata but not the message
//!
//! # Security Properties
//!
//! - **Blindness**: Signer cannot link unblinded signatures to blinding sessions
//! - **Unforgeability**: Cannot create valid signatures without signer participation
//!
//! # Example
//!
//! ```rust,ignore
//! // Requester blinds the message
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

pub mod rsa_blind;
pub mod partially_blind;
pub mod types;

pub use rsa_blind::RsaBlindEngine;
pub use partially_blind::PartiallyBlindEngine;
pub use types::*;
```

### Step 2: Define Types

Create `crates/crypto-engine/src/blind/types.rs`:

```rust
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A blinded message ready for signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedMessage {
    pub bytes: Vec<u8>,
}

/// Factor used to unblind the signature
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnblindingFactor {
    pub(crate) bytes: Vec<u8>,
}

/// A blind signature (before unblinding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSignature {
    pub bytes: Vec<u8>,
}

/// Metadata visible to signer in partially blind signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindMetadata {
    /// Visible info (e.g., expiration date, issuer)
    pub info: Vec<u8>,
}

/// Errors specific to blind signatures
#[derive(Debug, thiserror::Error)]
pub enum BlindError {
    #[error("Message too long for key size")]
    MessageTooLong,

    #[error("Invalid blinding factor")]
    InvalidBlindingFactor,

    #[error("Blinding failed: {0}")]
    BlindingFailed(String),

    #[error("Unblinding failed: {0}")]
    UnblindingFailed(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Key error: {0}")]
    KeyError(String),
}
```

### Step 3: Implement RSA Blind Signatures

Create `crates/crypto-engine/src/blind/rsa_blind.rs`:

```rust
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

use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;

use super::types::*;
use crate::{CryptoError, KeyMaterial};

/// RSA blind signature engine
pub struct RsaBlindEngine;

impl RsaBlindEngine {
    /// Blind a message for signing
    ///
    /// Returns (blinded_message, unblinding_factor)
    pub fn blind(
        public_key: &RsaPublicKey,
        message: &[u8],
    ) -> Result<(BlindedMessage, UnblindingFactor), BlindError> {
        let n = BigUint::from_bytes_be(&public_key.n);
        let e = BigUint::from_bytes_be(&public_key.e);

        // Hash message to get m (PKCS#1 v1.5 padding or PSS)
        let m = Self::encode_message(message, public_key.bit_size())?;
        let m_int = BigUint::from_bytes_be(&m);

        // Generate random blinding factor r where gcd(r, n) = 1
        let mut rng = thread_rng();
        let r = loop {
            let candidate = rng.gen_biguint(public_key.bit_size() as u64);
            if candidate > BigUint::zero() && candidate < n && gcd(&candidate, &n) == BigUint::one() {
                break candidate;
            }
        };

        // Compute r^e mod n
        let r_e = r.modpow(&e, &n);

        // Compute blinded message: m' = m * r^e mod n
        let m_blinded = (&m_int * &r_e) % &n;

        Ok((
            BlindedMessage {
                bytes: m_blinded.to_bytes_be(),
            },
            UnblindingFactor {
                bytes: r.to_bytes_be(),
            },
        ))
    }

    /// Sign a blinded message
    ///
    /// The signer learns nothing about the original message.
    pub fn sign_blinded(
        private_key: &RsaPrivateKey,
        blinded_message: &BlindedMessage,
    ) -> Result<BlindSignature, BlindError> {
        let n = BigUint::from_bytes_be(&private_key.n);
        let d = BigUint::from_bytes_be(&private_key.d);

        let m_blinded = BigUint::from_bytes_be(&blinded_message.bytes);

        // Compute s' = (m')^d mod n
        let s_blinded = m_blinded.modpow(&d, &n);

        Ok(BlindSignature {
            bytes: s_blinded.to_bytes_be(),
        })
    }

    /// Unblind a signature to get the final signature
    pub fn unblind(
        public_key: &RsaPublicKey,
        blind_signature: &BlindSignature,
        unblinding_factor: &UnblindingFactor,
    ) -> Result<Vec<u8>, BlindError> {
        let n = BigUint::from_bytes_be(&public_key.n);

        let s_blinded = BigUint::from_bytes_be(&blind_signature.bytes);
        let r = BigUint::from_bytes_be(&unblinding_factor.bytes);

        // Compute r_inv = r^(-1) mod n
        let r_inv = mod_inverse(&r, &n)
            .ok_or(BlindError::InvalidBlindingFactor)?;

        // Compute s = s' * r^(-1) mod n
        let s = (&s_blinded * &r_inv) % &n;

        Ok(s.to_bytes_be())
    }

    /// Verify an unblinded signature
    pub fn verify(
        public_key: &RsaPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, BlindError> {
        let n = BigUint::from_bytes_be(&public_key.n);
        let e = BigUint::from_bytes_be(&public_key.e);

        let s = BigUint::from_bytes_be(signature);

        // Compute s^e mod n
        let m_recovered = s.modpow(&e, &n);

        // Encode expected message
        let m_expected = Self::encode_message(message, public_key.bit_size())?;
        let m_expected_int = BigUint::from_bytes_be(&m_expected);

        // Compare (constant-time in production)
        Ok(m_recovered == m_expected_int)
    }

    /// Encode message using PKCS#1 v1.5 padding
    fn encode_message(message: &[u8], key_bits: usize) -> Result<Vec<u8>, BlindError> {
        let key_bytes = (key_bits + 7) / 8;

        // Hash the message first (using SHA-256)
        let hash = crate::hash::digest::hash(message, crate::HashAlgorithm::Sha256)
            .map_err(|e| BlindError::BlindingFailed(e.to_string()))?;

        // PKCS#1 v1.5 signature padding for SHA-256
        // DigestInfo for SHA-256:
        let digest_info_prefix: &[u8] = &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
        ];

        let t_len = digest_info_prefix.len() + hash.len();

        if key_bytes < t_len + 11 {
            return Err(BlindError::MessageTooLong);
        }

        // Build: 0x00 || 0x01 || PS || 0x00 || T
        let ps_len = key_bytes - t_len - 3;
        let mut encoded = Vec::with_capacity(key_bytes);
        encoded.push(0x00);
        encoded.push(0x01);
        encoded.extend(std::iter::repeat(0xff).take(ps_len));
        encoded.push(0x00);
        encoded.extend_from_slice(digest_info_prefix);
        encoded.extend_from_slice(&hash);

        Ok(encoded)
    }
}

/// RSA public key components for blind signatures
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    pub n: Vec<u8>,  // modulus
    pub e: Vec<u8>,  // public exponent
}

impl RsaPublicKey {
    pub fn bit_size(&self) -> usize {
        self.n.len() * 8
    }
}

/// RSA private key components for blind signatures
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RsaPrivateKey {
    pub n: Vec<u8>,
    #[zeroize(skip)]
    pub e: Vec<u8>,
    pub d: Vec<u8>,  // private exponent
}

/// Compute GCD of two BigUints
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

/// Compute modular inverse using extended Euclidean algorithm
fn mod_inverse(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    use num_traits::Signed;

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
```

### Step 4: Implement Partially Blind Signatures

Create `crates/crypto-engine/src/blind/partially_blind.rs`:

```rust
//! Partially Blind Signatures
//!
//! A variant where the signer can see some agreed-upon metadata (like
//! expiration date) but not the main message content.

use super::types::*;
use super::rsa_blind::{RsaPublicKey, RsaPrivateKey};
use crate::hash::digest::hash;
use crate::HashAlgorithm;

/// Partially blind signature engine
pub struct PartiallyBlindEngine;

impl PartiallyBlindEngine {
    /// Blind a message with visible metadata
    ///
    /// The metadata (e.g., expiration date) is visible to the signer.
    /// The message content remains hidden.
    pub fn blind_with_metadata(
        public_key: &RsaPublicKey,
        message: &[u8],
        metadata: &BlindMetadata,
    ) -> Result<(BlindedMessage, UnblindingFactor), BlindError> {
        // Combine message with metadata hash for binding
        let metadata_hash = hash(&metadata.info, HashAlgorithm::Sha256)
            .map_err(|e| BlindError::BlindingFailed(e.to_string()))?;

        // Create binding: H(message || metadata_hash)
        let mut combined = message.to_vec();
        combined.extend_from_slice(&metadata_hash);

        // Proceed with normal blinding
        super::rsa_blind::RsaBlindEngine::blind(public_key, &combined)
    }

    /// Sign a blinded message with visible metadata
    ///
    /// The signer verifies the metadata is acceptable before signing.
    pub fn sign_blinded_with_metadata(
        private_key: &RsaPrivateKey,
        blinded_message: &BlindedMessage,
        metadata: &BlindMetadata,
        validator: impl Fn(&BlindMetadata) -> bool,
    ) -> Result<BlindSignature, BlindError> {
        // Validate metadata (e.g., check expiration is within allowed range)
        if !validator(metadata) {
            return Err(BlindError::BlindingFailed("Metadata validation failed".into()));
        }

        // Sign the blinded message
        super::rsa_blind::RsaBlindEngine::sign_blinded(private_key, blinded_message)
    }

    /// Verify a partially blind signature
    pub fn verify_with_metadata(
        public_key: &RsaPublicKey,
        message: &[u8],
        metadata: &BlindMetadata,
        signature: &[u8],
    ) -> Result<bool, BlindError> {
        // Reconstruct the combined message
        let metadata_hash = hash(&metadata.info, HashAlgorithm::Sha256)
            .map_err(|e| BlindError::BlindingFailed(e.to_string()))?;

        let mut combined = message.to_vec();
        combined.extend_from_slice(&metadata_hash);

        super::rsa_blind::RsaBlindEngine::verify(public_key, &combined, signature)
    }
}

/// Common metadata for credentials
#[derive(Debug, Clone)]
pub struct CredentialMetadata {
    /// Issue timestamp
    pub issued_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Credential type/scope
    pub credential_type: String,
}

impl CredentialMetadata {
    /// Serialize to bytes for inclusion in signature
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(self.credential_type.as_bytes());
        bytes
    }

    /// Create BlindMetadata from this
    pub fn to_blind_metadata(&self) -> BlindMetadata {
        BlindMetadata {
            info: self.to_bytes(),
        }
    }
}
```

### Step 5: Add gRPC Endpoints

Add to `proto/hsm.proto`:

```protobuf
// Blind signature operations
message BlindSignRequest {
    string key_id = 1;
    bytes blinded_message = 2;
    optional bytes metadata = 3;  // For partially blind signatures
}

message BlindSignResponse {
    bytes blind_signature = 1;
}

// For audit logging (signer doesn't see message but logs signing)
message BlindSignAuditInfo {
    string session_id = 1;
    google.protobuf.Timestamp timestamp = 2;
    string key_id = 3;
    bytes metadata_hash = 4;  // Hash of metadata (if any)
}
```

### Step 6: Add REST Endpoints

Add to `crates/rest-api/src/routes/`:

```rust
/// POST /keys/:id/blind-sign
/// Sign a blinded message
pub async fn blind_sign(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(request): Json<BlindSignRequest>,
) -> Result<Json<BlindSignResponse>, ApiError> {
    // Validate key exists and is RSA
    // Sign the blinded message
    // Log audit event (signing occurred, but not what was signed)
    todo!()
}
```

## Testing Requirements

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_keypair() -> (RsaPublicKey, RsaPrivateKey) {
        // Generate RSA keypair for testing
        // In real implementation, use existing RSA keygen
        todo!()
    }

    #[test]
    fn test_blind_sign_unblind_verify() {
        let (public_key, private_key) = generate_test_keypair();
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
        let (public_key, private_key) = generate_test_keypair();

        // Sign same message twice with different blinding factors
        let message = b"same message";

        let (blinded1, factor1) = RsaBlindEngine::blind(&public_key, message).unwrap();
        let (blinded2, factor2) = RsaBlindEngine::blind(&public_key, message).unwrap();

        // Blinded messages should be different
        assert_ne!(blinded1.bytes, blinded2.bytes);

        // Both should produce valid signatures
        let blind_sig1 = RsaBlindEngine::sign_blinded(&private_key, &blinded1).unwrap();
        let blind_sig2 = RsaBlindEngine::sign_blinded(&private_key, &blinded2).unwrap();

        let sig1 = RsaBlindEngine::unblind(&public_key, &blind_sig1, &factor1).unwrap();
        let sig2 = RsaBlindEngine::unblind(&public_key, &blind_sig2, &factor2).unwrap();

        // Signatures should be IDENTICAL (same message = same final signature)
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_partially_blind_metadata_validation() {
        let (public_key, private_key) = generate_test_keypair();
        let message = b"credential content";

        let valid_metadata = BlindMetadata {
            info: b"expires:2025-12-31".to_vec(),
        };

        let (blinded, factor) = PartiallyBlindEngine::blind_with_metadata(
            &public_key,
            message,
            &valid_metadata,
        ).unwrap();

        // Signer validates metadata before signing
        let blind_sig = PartiallyBlindEngine::sign_blinded_with_metadata(
            &private_key,
            &blinded,
            &valid_metadata,
            |meta| {
                // Check expiration is within allowed range
                meta.info.starts_with(b"expires:")
            },
        ).unwrap();

        let signature = RsaBlindEngine::unblind(&public_key, &blind_sig, &factor).unwrap();

        // Verify with metadata
        assert!(PartiallyBlindEngine::verify_with_metadata(
            &public_key,
            message,
            &valid_metadata,
            &signature,
        ).unwrap());
    }
}
```

### Property Tests

```rust
proptest! {
    #[test]
    fn prop_blind_signature_roundtrip(message in prop::collection::vec(any::<u8>(), 1..256)) {
        let (public_key, private_key) = generate_test_keypair();

        let (blinded, factor) = RsaBlindEngine::blind(&public_key, &message).unwrap();
        let blind_sig = RsaBlindEngine::sign_blinded(&private_key, &blinded).unwrap();
        let signature = RsaBlindEngine::unblind(&public_key, &blind_sig, &factor).unwrap();

        prop_assert!(RsaBlindEngine::verify(&public_key, &message, &signature).unwrap());
    }

    #[test]
    fn prop_different_messages_different_blind_signatures(
        msg1 in prop::collection::vec(any::<u8>(), 1..256),
        msg2 in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(msg1 != msg2);

        let (public_key, private_key) = generate_test_keypair();

        let (blinded1, factor1) = RsaBlindEngine::blind(&public_key, &msg1).unwrap();
        let (blinded2, factor2) = RsaBlindEngine::blind(&public_key, &msg2).unwrap();

        let blind_sig1 = RsaBlindEngine::sign_blinded(&private_key, &blinded1).unwrap();
        let blind_sig2 = RsaBlindEngine::sign_blinded(&private_key, &blinded2).unwrap();

        let sig1 = RsaBlindEngine::unblind(&public_key, &blind_sig1, &factor1).unwrap();
        let sig2 = RsaBlindEngine::unblind(&public_key, &blind_sig2, &factor2).unwrap();

        // Different messages should have different signatures
        prop_assert_ne!(sig1, sig2);
    }
}
```

## Success Metrics

- [ ] RSA blind signatures work with 2048 and 4096 bit keys
- [ ] Same message produces same final signature (unlinkability)
- [ ] Different blinding factors produce different blinded messages
- [ ] Partially blind signatures validate metadata correctly
- [ ] Invalid metadata is rejected
- [ ] Unblinding factors are zeroized on drop
- [ ] Audit logging records signing without message content

## Security Considerations

- **RSA key size**: Use ≥2048 bits for security
- **Blinding factor**: Must be cryptographically random
- **Timing attacks**: Use constant-time operations where possible
- **Message encoding**: Must use proper padding (PKCS#1 or PSS)
- **Metadata binding**: Partially blind signatures must cryptographically bind metadata
- **Audit trail**: Log that signing occurred without revealing message
