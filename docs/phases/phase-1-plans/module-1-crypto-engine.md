# Module 1: Core Cryptographic Engine - Implementation Plan

## Agent Mission
Build a secure, high-performance cryptographic engine that provides all cryptographic primitives for the HSM including RSA, ECDSA, Ed25519/Ed448, AES, and hashing operations.

## Critical Success Factors
1. All cryptographic operations must be constant-time where possible
2. Memory containing sensitive data must be properly zeroized
3. All algorithms must pass NIST Known Answer Tests (KAT)
4. Performance targets must be met (1000+ Ed25519 ops/sec)
5. Zero unsafe code unless absolutely necessary and documented

## File Structure
```
crates/crypto-engine/
├── Cargo.toml
├── src/
│   ├── lib.rs                 # Public API and traits
│   ├── error.rs               # Error types
│   ├── asymmetric/
│   │   ├── mod.rs
│   │   ├── rsa.rs             # RSA operations
│   │   ├── ecdsa.rs           # ECDSA P-256/384/521
│   │   └── ed25519.rs         # Ed25519/Ed448
│   ├── symmetric/
│   │   ├── mod.rs
│   │   ├── aes_gcm.rs         # AES-GCM
│   │   └── aes_cbc.rs         # AES-CBC
│   ├── hash/
│   │   ├── mod.rs
│   │   └── digest.rs          # SHA-2, SHA-3
│   ├── kdf/
│   │   ├── mod.rs
│   │   ├── hkdf.rs            # HKDF
│   │   ├── pbkdf2.rs          # PBKDF2
│   │   └── argon2.rs          # Argon2
│   └── random.rs              # CSRNG
├── tests/
│   ├── integration_tests.rs
│   ├── kat_tests.rs           # Known Answer Tests
│   └── test_vectors/          # NIST test vectors
└── benches/
    └── crypto_benches.rs
```

## Dependencies (Cargo.toml)
```toml
[package]
name = "hsm-crypto-engine"
version = "0.1.0"
edition = "2021"

[dependencies]
# Core crypto
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
curve25519-dalek = "4.1"
p256 = { version = "0.13", features = ["ecdsa"] }
p384 = { version = "0.13", features = ["ecdsa"] }
rsa = { version = "0.9", features = ["sha2"] }
aes-gcm = "0.10"
aes = "0.8"
cbc = "0.1"

# Hashing
sha2 = "0.10"
sha3 = "0.10"

# KDF
hkdf = "0.12"
pbkdf2 = { version = "0.12", features = ["simple"] }
argon2 = "0.5"

# Security
zeroize = { version = "1.7", features = ["derive"] }
secrecy = "0.8"
getrandom = "0.2"
subtle = "2.5"

# Error handling
thiserror = "1.0"

# Serialization (for key formats)
serde = { version = "1.0", features = ["derive"] }

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
hex = "0.4"
serde_json = "1.0"
proptest = "1.4"

[[bench]]
name = "crypto_benches"
harness = false
```

## Implementation Steps

### Phase 1: Project Setup & Core Traits (Day 1)

**Step 1.1: Initialize Cargo Workspace**
```bash
cd /Users/bs/codes/hsm
mkdir -p crates/crypto-engine
cd crates/crypto-engine
cargo init --lib
```

**Step 1.2: Define Core Types and Traits (src/lib.rs)**
```rust
//! Core cryptographic engine for HSM
//!
//! Provides secure implementations of:
//! - Asymmetric cryptography (RSA, ECDSA, Ed25519)
//! - Symmetric cryptography (AES-GCM, AES-CBC)
//! - Hashing (SHA-2, SHA-3)
//! - Key derivation (HKDF, PBKDF2, Argon2)

use secrecy::SecretVec;
use zeroize::Zeroize;

pub mod asymmetric;
pub mod symmetric;
pub mod hash;
pub mod kdf;
pub mod random;
pub mod error;

pub use error::{CryptoError, Result};

/// Supported signing algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAlgorithm {
    RsaPkcs1v15Sha256,
    RsaPssSha256,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    EcdsaP521Sha512,
    Ed25519,
    Ed448,
}

/// Supported encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    Aes128Cbc,
    Aes256Cbc,
    RsaOaepSha256,
}

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
}

/// Generic key material (zeroized on drop)
#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct KeyMaterial {
    bytes: Vec<u8>,
}

impl KeyMaterial {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Main cryptographic engine trait
pub trait CryptoEngine: Send + Sync {
    // Signing operations
    fn sign(
        &self,
        key: &KeyMaterial,
        data: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<Vec<u8>>;

    fn verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<bool>;

    // Encryption operations
    fn encrypt(
        &self,
        key: &KeyMaterial,
        plaintext: &[u8],
        algorithm: EncryptAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    fn decrypt(
        &self,
        key: &KeyMaterial,
        ciphertext: &[u8],
        algorithm: EncryptAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    // Hashing
    fn hash(&self, data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>>;
}
```

**Step 1.3: Define Error Types (src/error.rs)**
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key format: {0}")]
    InvalidKey(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),

    #[error("Insufficient entropy")]
    InsufficientEntropy,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
```

### Phase 2: Ed25519 Implementation (Day 1-2)

**Step 2.1: Implement Ed25519 Operations (src/asymmetric/ed25519.rs)**
```rust
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use crate::{KeyMaterial, CryptoError, Result};
use zeroize::Zeroizing;

pub struct Ed25519Engine;

impl Ed25519Engine {
    pub fn generate_keypair() -> Result<(KeyMaterial, Vec<u8>)> {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let private_key = KeyMaterial::from_bytes(signing_key.to_bytes().to_vec());
        let public_key = verifying_key.to_bytes().to_vec();

        Ok((private_key, public_key))
    }

    pub fn sign(key: &KeyMaterial, message: &[u8]) -> Result<Vec<u8>> {
        let key_bytes: [u8; 32] = key.as_bytes()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("Ed25519 key must be 32 bytes".into()))?;

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(message);

        Ok(signature.to_bytes().to_vec())
    }

    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        let pub_bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("Ed25519 public key must be 32 bytes".into()))?;

        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("Ed25519 signature must be 64 bytes".into()))?;

        let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let sig = Signature::from_bytes(&sig_bytes);

        verifying_key.verify(message, &sig)
            .map(|_| true)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let (private_key, public_key) = Ed25519Engine::generate_keypair().unwrap();
        let message = b"test message";

        let signature = Ed25519Engine::sign(&private_key, message).unwrap();
        let valid = Ed25519Engine::verify(&public_key, message, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_ed25519_invalid_signature() {
        let (_, public_key) = Ed25519Engine::generate_keypair().unwrap();
        let message = b"test message";
        let bad_signature = vec![0u8; 64];

        let result = Ed25519Engine::verify(&public_key, message, &bad_signature);
        assert!(result.is_err());
    }
}
```

### Phase 3: ECDSA Implementation (Day 2-3)

**Step 3.1: Implement ECDSA P-256 (src/asymmetric/ecdsa.rs)**
```rust
use p256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer, signature::Verifier};
use p384::ecdsa::{SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey, Signature as P384Signature};
use crate::{KeyMaterial, CryptoError, Result};
use rand_core::OsRng;

pub struct EcdsaEngine;

impl EcdsaEngine {
    pub fn generate_p256_keypair() -> Result<(KeyMaterial, Vec<u8>)> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let private_bytes = signing_key.to_bytes();
        let public_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        Ok((KeyMaterial::from_bytes(private_bytes.to_vec()), public_bytes))
    }

    pub fn sign_p256(key: &KeyMaterial, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::from_bytes(key.as_bytes().into())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let signature: Signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    pub fn verify_p256(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let sig = Signature::from_bytes(signature.into())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        verifying_key.verify(message, &sig)
            .map(|_| true)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    // Similar implementations for P-384 and P-521
}
```

### Phase 4: RSA Implementation (Day 3-4)

**Step 4.1: Implement RSA Operations (src/asymmetric/rsa.rs)**
```rust
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Sign, Pss};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, Verifier};
use sha2::{Sha256, Digest};
use crate::{KeyMaterial, CryptoError, Result};
use rand_core::OsRng;

pub struct RsaEngine;

impl RsaEngine {
    pub fn generate_keypair(bits: usize) -> Result<(KeyMaterial, Vec<u8>)> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| CryptoError::Internal(e.to_string()))?;

        let public_key = private_key.to_public_key();

        // Serialize keys (using PKCS#8 for private, PKCS#1 for public)
        let private_der = rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&private_key)
            .map_err(|e| CryptoError::Internal(e.to_string()))?;
        let public_der = rsa::pkcs1::EncodeRsaPublicKey::to_pkcs1_der(&public_key)
            .map_err(|e| CryptoError::Internal(e.to_string()))?;

        Ok((
            KeyMaterial::from_bytes(private_der.as_bytes().to_vec()),
            public_der.as_bytes().to_vec()
        ))
    }

    pub fn sign_pkcs1v15_sha256(key: &KeyMaterial, message: &[u8]) -> Result<Vec<u8>> {
        let private_key = RsaPrivateKey::from_pkcs8_der(key.as_bytes())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign_with_rng(&mut OsRng, message);

        Ok(signature.to_vec())
    }

    pub fn verify_pkcs1v15_sha256(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8]
    ) -> Result<bool> {
        let public_key = RsaPublicKey::from_pkcs1_der(public_key)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let verifying_key = VerifyingKey::<Sha256>::new(public_key);

        verifying_key.verify(message, &signature.try_into().unwrap())
            .map(|_| true)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    // PSS variants
    pub fn sign_pss_sha256(key: &KeyMaterial, message: &[u8]) -> Result<Vec<u8>> {
        // Similar to PKCS1v15 but using PSS padding
        todo!()
    }
}
```

### Phase 5: AES Implementation (Day 4-5)

**Step 5.1: Implement AES-GCM (src/symmetric/aes_gcm.rs)**
```rust
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Aes128Gcm, Nonce
};
use crate::{KeyMaterial, CryptoError, Result};
use getrandom::getrandom;

pub struct AesGcmEngine;

impl AesGcmEngine {
    pub fn encrypt_aes256(
        key: &KeyMaterial,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if key.as_bytes().len() != 32 {
            return Err(CryptoError::InvalidKey("AES-256 requires 32-byte key".into()));
        }

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::Internal(e.to_string()))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom(&mut nonce_bytes)
            .map_err(|_| CryptoError::InsufficientEntropy)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad: aad.unwrap_or(&[]),
        };

        let ciphertext = cipher.encrypt(nonce, payload)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt_aes256(
        key: &KeyMaterial,
        ciphertext_with_nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if ciphertext_with_nonce.len() < 12 {
            return Err(CryptoError::DecryptionFailed("Invalid ciphertext".into()));
        }

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::Internal(e.to_string()))?;

        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = Payload {
            msg: ciphertext,
            aad: aad.unwrap_or(&[]),
        };

        cipher.decrypt(nonce, payload)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = KeyMaterial::from_bytes(vec![0x42; 32]);
        let plaintext = b"secret message";
        let aad = Some(&b"additional data"[..]);

        let ciphertext = AesGcmEngine::encrypt_aes256(&key, plaintext, aad).unwrap();
        let decrypted = AesGcmEngine::decrypt_aes256(&key, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
```

### Phase 6: Hashing & KDF (Day 5)

**Step 6.1: Implement Hashing (src/hash/digest.rs)**
```rust
use sha2::{Sha256, Sha384, Sha512, Digest};
use sha3::{Sha3_256, Sha3_512};
use crate::{HashAlgorithm, Result};

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
```

**Step 6.2: Implement KDFs (src/kdf/hkdf.rs)**
```rust
use hkdf::Hkdf;
use sha2::Sha256;
use crate::Result;

pub fn derive_key(input_key: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), input_key);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .map_err(|e| crate::CryptoError::Internal(e.to_string()))?;
    Ok(okm)
}
```

### Phase 7: Integration & Main Engine (Day 6)

**Step 7.1: Implement Main CryptoEngine (src/lib.rs continued)**
```rust
pub struct DefaultCryptoEngine;

impl CryptoEngine for DefaultCryptoEngine {
    fn sign(
        &self,
        key: &KeyMaterial,
        data: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<Vec<u8>> {
        match algorithm {
            SignAlgorithm::Ed25519 => asymmetric::ed25519::Ed25519Engine::sign(key, data),
            SignAlgorithm::EcdsaP256Sha256 => asymmetric::ecdsa::EcdsaEngine::sign_p256(key, data),
            SignAlgorithm::RsaPkcs1v15Sha256 => asymmetric::rsa::RsaEngine::sign_pkcs1v15_sha256(key, data),
            _ => Err(CryptoError::InvalidAlgorithm(format!("{:?} not yet implemented", algorithm))),
        }
    }

    fn verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<bool> {
        match algorithm {
            SignAlgorithm::Ed25519 => asymmetric::ed25519::Ed25519Engine::verify(public_key, data, signature),
            SignAlgorithm::EcdsaP256Sha256 => asymmetric::ecdsa::EcdsaEngine::verify_p256(public_key, data, signature),
            _ => Err(CryptoError::InvalidAlgorithm(format!("{:?} not yet implemented", algorithm))),
        }
    }

    fn encrypt(
        &self,
        key: &KeyMaterial,
        plaintext: &[u8],
        algorithm: EncryptAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match algorithm {
            EncryptAlgorithm::Aes256Gcm => symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(key, plaintext, aad),
            _ => Err(CryptoError::InvalidAlgorithm(format!("{:?} not yet implemented", algorithm))),
        }
    }

    fn decrypt(
        &self,
        key: &KeyMaterial,
        ciphertext: &[u8],
        algorithm: EncryptAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match algorithm {
            EncryptAlgorithm::Aes256Gcm => symmetric::aes_gcm::AesGcmEngine::decrypt_aes256(key, ciphertext, aad),
            _ => Err(CryptoError::InvalidAlgorithm(format!("{:?} not yet implemented", algorithm))),
        }
    }

    fn hash(&self, data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>> {
        hash::digest::hash(data, algorithm)
    }
}
```

### Phase 8: Testing (Day 6-7)

**Step 8.1: Known Answer Tests (tests/kat_tests.rs)**
```rust
// Load NIST test vectors and validate all algorithms
use hsm_crypto_engine::*;

#[test]
fn test_ed25519_kat() {
    // Use RFC 8032 test vectors
    let test_vectors = load_ed25519_test_vectors();

    for vector in test_vectors {
        let sig = asymmetric::ed25519::Ed25519Engine::sign(&vector.private_key, &vector.message).unwrap();
        assert_eq!(sig, vector.expected_signature);
    }
}
```

**Step 8.2: Performance Benchmarks (benches/crypto_benches.rs)**
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use hsm_crypto_engine::*;

fn bench_ed25519_sign(c: &mut Criterion) {
    let (private_key, _) = asymmetric::ed25519::Ed25519Engine::generate_keypair().unwrap();
    let message = b"benchmark message";

    let mut group = c.benchmark_group("ed25519");
    group.throughput(Throughput::Elements(1));

    group.bench_function("sign", |b| {
        b.iter(|| {
            asymmetric::ed25519::Ed25519Engine::sign(black_box(&private_key), black_box(message))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_ed25519_sign);
criterion_main!(benches);
```

### Phase 9: Documentation & Validation (Day 7)

**Step 9.1: Add Documentation**
- Add comprehensive rustdoc comments to all public APIs
- Create examples directory with usage examples
- Document security considerations

**Step 9.2: Security Audit Checklist**
- [ ] All sensitive data properly zeroized
- [ ] Constant-time operations where applicable
- [ ] No unsafe code (or documented and justified)
- [ ] All dependencies up to date
- [ ] cargo-audit passes
- [ ] All tests pass
- [ ] Benchmarks meet performance targets

## Testing Commands
```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_tests

# KAT tests
cargo test --test kat_tests

# Benchmarks
cargo bench

# Security audit
cargo audit

# Coverage
cargo tarpaulin --out Html
```

## Performance Validation
```bash
# Must achieve:
# Ed25519 signing: > 1000 ops/sec
# ECDSA P-256 signing: > 500 ops/sec
# AES-256-GCM encrypt: > 5000 ops/sec

cargo bench --bench crypto_benches
```

## Integration Points

### Exports for Other Modules
```rust
// Key management will need:
pub use KeyMaterial;
pub use {SignAlgorithm, EncryptAlgorithm, HashAlgorithm};
pub use CryptoEngine;
pub use asymmetric::{ed25519, ecdsa, rsa}; // For key generation

// Storage will need:
pub use symmetric::aes_gcm; // For encrypting keys at rest

// Audit logging will need:
pub use hash::digest; // For hash chains
```

## Success Criteria
1. ✅ All cryptographic algorithms implemented
2. ✅ All NIST KAT tests pass
3. ✅ Performance targets met (benchmark results)
4. ✅ Zero memory leaks (valgrind/miri)
5. ✅ All sensitive data zeroized
6. ✅ Code coverage > 80%
7. ✅ No cargo-audit warnings
8. ✅ Documentation complete

## Timeline
- Day 1: Setup + Core traits + Ed25519
- Day 2: ECDSA
- Day 3-4: RSA
- Day 4-5: AES-GCM
- Day 5: Hashing & KDF
- Day 6: Integration + Main engine
- Day 6-7: Testing + KAT
- Day 7: Documentation + Validation
