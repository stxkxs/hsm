# Plan 3.1: Post-Quantum Cryptography

## Overview

Add post-quantum cryptographic algorithms to protect against future quantum computer attacks. Implements NIST-standardized algorithms ML-KEM (Kyber) and ML-DSA (Dilithium), plus hybrid modes combining classical and PQC algorithms.

## Goals

- Support ML-KEM-768 and ML-KEM-1024 for key encapsulation
- Support ML-DSA-65 and ML-DSA-87 for digital signatures
- Provide hybrid modes (e.g., X25519 + ML-KEM, Ed25519 + ML-DSA)
- Maintain API consistency with existing algorithms
- Enable gradual migration path for users

## Dependencies

Add to `crates/crypto-engine/Cargo.toml`:

```toml
[dependencies]
pqcrypto-mlkem = "0.1"        # ML-KEM (Kyber)
pqcrypto-mldsa = "0.1"        # ML-DSA (Dilithium)
pqcrypto-traits = "0.3"       # Common traits
# Note: Check crates.io for latest pqcrypto versions
# Alternative: use `pqcrypto` meta-crate
```

## File Structure

```
crates/crypto-engine/src/
├── pqc/
│   ├── mod.rs              # PQC module exports
│   ├── mlkem.rs            # ML-KEM implementation
│   ├── mldsa.rs            # ML-DSA implementation
│   ├── hybrid.rs           # Hybrid encryption/signing
│   └── error.rs            # PQC-specific errors
├── lib.rs                  # Add: pub mod pqc;
└── ...
```

## Implementation Steps

### Step 1: Create PQC Module Structure

Create `crates/crypto-engine/src/pqc/mod.rs`:

```rust
//! Post-Quantum Cryptography module
//!
//! Provides NIST-standardized post-quantum algorithms:
//! - ML-KEM (Kyber) for key encapsulation
//! - ML-DSA (Dilithium) for digital signatures
//! - Hybrid modes combining classical + PQC

pub mod mlkem;
pub mod mldsa;
pub mod hybrid;
mod error;

pub use error::PqcError;
pub use mlkem::{MlKemEngine, MlKemKeyPair, MlKemCiphertext, MlKemSecurityLevel};
pub use mldsa::{MlDsaEngine, MlDsaKeyPair, MlDsaSignature, MlDsaSecurityLevel};
pub use hybrid::{HybridKemEngine, HybridSignEngine};
```

### Step 2: Implement ML-KEM (Key Encapsulation)

Create `crates/crypto-engine/src/pqc/mlkem.rs`:

```rust
//! ML-KEM (Module-Lattice Key Encapsulation Mechanism)
//!
//! Formerly known as Kyber, standardized in FIPS 203.

use crate::{CryptoError, KeyMaterial};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Security level for ML-KEM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemSecurityLevel {
    /// ML-KEM-768: ~192-bit classical security
    MlKem768,
    /// ML-KEM-1024: ~256-bit classical security
    MlKem1024,
}

/// ML-KEM key pair
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKemKeyPair {
    #[zeroize(skip)]
    pub security_level: MlKemSecurityLevel,
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

/// Encapsulated ciphertext and shared secret
pub struct MlKemCiphertext {
    pub ciphertext: Vec<u8>,
}

/// ML-KEM operations
pub struct MlKemEngine;

impl MlKemEngine {
    /// Generate a new ML-KEM key pair
    pub fn generate_keypair(level: MlKemSecurityLevel) -> Result<MlKemKeyPair, CryptoError> {
        match level {
            MlKemSecurityLevel::MlKem768 => {
                // Use pqcrypto_mlkem::mlkem768
                todo!("Implement ML-KEM-768 keygen")
            }
            MlKemSecurityLevel::MlKem1024 => {
                // Use pqcrypto_mlkem::mlkem1024
                todo!("Implement ML-KEM-1024 keygen")
            }
        }
    }

    /// Encapsulate: generate shared secret and ciphertext
    pub fn encapsulate(
        public_key: &[u8],
        level: MlKemSecurityLevel,
    ) -> Result<(Vec<u8>, MlKemCiphertext), CryptoError> {
        // Returns (shared_secret, ciphertext)
        todo!("Implement encapsulation")
    }

    /// Decapsulate: recover shared secret from ciphertext
    pub fn decapsulate(
        keypair: &MlKemKeyPair,
        ciphertext: &MlKemCiphertext,
    ) -> Result<Vec<u8>, CryptoError> {
        // Returns shared_secret
        todo!("Implement decapsulation")
    }

    /// Get public key size in bytes
    pub fn public_key_size(level: MlKemSecurityLevel) -> usize {
        match level {
            MlKemSecurityLevel::MlKem768 => 1184,
            MlKemSecurityLevel::MlKem1024 => 1568,
        }
    }

    /// Get ciphertext size in bytes
    pub fn ciphertext_size(level: MlKemSecurityLevel) -> usize {
        match level {
            MlKemSecurityLevel::MlKem768 => 1088,
            MlKemSecurityLevel::MlKem1024 => 1568,
        }
    }

    /// Get shared secret size in bytes (always 32)
    pub fn shared_secret_size() -> usize {
        32
    }
}

impl MlKemKeyPair {
    /// Export public key
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Export secret key (use with caution)
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }
}
```

### Step 3: Implement ML-DSA (Digital Signatures)

Create `crates/crypto-engine/src/pqc/mldsa.rs`:

```rust
//! ML-DSA (Module-Lattice Digital Signature Algorithm)
//!
//! Formerly known as Dilithium, standardized in FIPS 204.

use crate::{CryptoError, KeyMaterial};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Security level for ML-DSA
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaSecurityLevel {
    /// ML-DSA-65: ~192-bit classical security (NIST Level 3)
    MlDsa65,
    /// ML-DSA-87: ~256-bit classical security (NIST Level 5)
    MlDsa87,
}

/// ML-DSA key pair
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlDsaKeyPair {
    #[zeroize(skip)]
    pub security_level: MlDsaSecurityLevel,
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

/// ML-DSA signature
pub struct MlDsaSignature {
    pub bytes: Vec<u8>,
}

/// ML-DSA operations
pub struct MlDsaEngine;

impl MlDsaEngine {
    /// Generate a new ML-DSA key pair
    pub fn generate_keypair(level: MlDsaSecurityLevel) -> Result<MlDsaKeyPair, CryptoError> {
        match level {
            MlDsaSecurityLevel::MlDsa65 => {
                // Use pqcrypto_mldsa::mldsa65
                todo!("Implement ML-DSA-65 keygen")
            }
            MlDsaSecurityLevel::MlDsa87 => {
                // Use pqcrypto_mldsa::mldsa87
                todo!("Implement ML-DSA-87 keygen")
            }
        }
    }

    /// Sign a message
    pub fn sign(keypair: &MlDsaKeyPair, message: &[u8]) -> Result<MlDsaSignature, CryptoError> {
        todo!("Implement signing")
    }

    /// Verify a signature
    pub fn verify(
        public_key: &[u8],
        message: &[u8],
        signature: &MlDsaSignature,
        level: MlDsaSecurityLevel,
    ) -> Result<bool, CryptoError> {
        todo!("Implement verification")
    }

    /// Get public key size in bytes
    pub fn public_key_size(level: MlDsaSecurityLevel) -> usize {
        match level {
            MlDsaSecurityLevel::MlDsa65 => 1952,
            MlDsaSecurityLevel::MlDsa87 => 2592,
        }
    }

    /// Get signature size in bytes
    pub fn signature_size(level: MlDsaSecurityLevel) -> usize {
        match level {
            MlDsaSecurityLevel::MlDsa65 => 3309,
            MlDsaSecurityLevel::MlDsa87 => 4627,
        }
    }
}
```

### Step 4: Implement Hybrid Modes

Create `crates/crypto-engine/src/pqc/hybrid.rs`:

```rust
//! Hybrid cryptography combining classical and post-quantum algorithms
//!
//! Provides defense-in-depth: if either algorithm is broken, the other
//! still provides security.

use crate::{CryptoError, KeyMaterial};
use crate::asymmetric::x25519::X25519Engine;
use crate::asymmetric::ed25519::Ed25519Engine;
use super::mlkem::{MlKemEngine, MlKemKeyPair, MlKemSecurityLevel};
use super::mldsa::{MlDsaEngine, MlDsaKeyPair, MlDsaSecurityLevel};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Hybrid KEM key pair (X25519 + ML-KEM)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridKemKeyPair {
    x25519_private: KeyMaterial,
    #[zeroize(skip)]
    x25519_public: Vec<u8>,
    mlkem_keypair: MlKemKeyPair,
}

/// Hybrid KEM ciphertext
pub struct HybridKemCiphertext {
    pub x25519_ephemeral: Vec<u8>,
    pub mlkem_ciphertext: Vec<u8>,
}

/// Hybrid KEM engine
pub struct HybridKemEngine;

impl HybridKemEngine {
    /// Generate hybrid key pair
    pub fn generate_keypair(
        pqc_level: MlKemSecurityLevel,
    ) -> Result<HybridKemKeyPair, CryptoError> {
        // Generate X25519 keypair
        let (x25519_private, x25519_public) = X25519Engine::generate_keypair()?;

        // Generate ML-KEM keypair
        let mlkem_keypair = MlKemEngine::generate_keypair(pqc_level)?;

        Ok(HybridKemKeyPair {
            x25519_private,
            x25519_public,
            mlkem_keypair,
        })
    }

    /// Encapsulate to hybrid key pair
    /// Returns combined shared secret: HKDF(x25519_shared || mlkem_shared)
    pub fn encapsulate(
        x25519_public: &[u8],
        mlkem_public: &[u8],
        pqc_level: MlKemSecurityLevel,
    ) -> Result<(Vec<u8>, HybridKemCiphertext), CryptoError> {
        // X25519 key exchange
        let (x25519_ephemeral_private, x25519_ephemeral_public) =
            X25519Engine::generate_keypair()?;
        let x25519_shared = X25519Engine::diffie_hellman(
            &x25519_ephemeral_private,
            x25519_public,
        )?;

        // ML-KEM encapsulation
        let (mlkem_shared, mlkem_ct) = MlKemEngine::encapsulate(mlkem_public, pqc_level)?;

        // Combine shared secrets with HKDF
        let mut combined_input = Vec::new();
        combined_input.extend_from_slice(&x25519_shared);
        combined_input.extend_from_slice(&mlkem_shared);

        let combined_secret = crate::kdf::hkdf::derive_key(
            &combined_input,
            b"hybrid-kem-v1",
            b"shared-secret",
            32,
        )?;

        let ciphertext = HybridKemCiphertext {
            x25519_ephemeral: x25519_ephemeral_public,
            mlkem_ciphertext: mlkem_ct.ciphertext,
        };

        Ok((combined_secret, ciphertext))
    }

    /// Decapsulate from hybrid ciphertext
    pub fn decapsulate(
        keypair: &HybridKemKeyPair,
        ciphertext: &HybridKemCiphertext,
    ) -> Result<Vec<u8>, CryptoError> {
        // X25519 key exchange
        let x25519_shared = X25519Engine::diffie_hellman(
            &keypair.x25519_private,
            &ciphertext.x25519_ephemeral,
        )?;

        // ML-KEM decapsulation
        let mlkem_ct = super::mlkem::MlKemCiphertext {
            ciphertext: ciphertext.mlkem_ciphertext.clone(),
        };
        let mlkem_shared = MlKemEngine::decapsulate(&keypair.mlkem_keypair, &mlkem_ct)?;

        // Combine shared secrets
        let mut combined_input = Vec::new();
        combined_input.extend_from_slice(&x25519_shared);
        combined_input.extend_from_slice(&mlkem_shared);

        let combined_secret = crate::kdf::hkdf::derive_key(
            &combined_input,
            b"hybrid-kem-v1",
            b"shared-secret",
            32,
        )?;

        Ok(combined_secret)
    }
}

/// Hybrid signature key pair (Ed25519 + ML-DSA)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSignKeyPair {
    ed25519_private: KeyMaterial,
    #[zeroize(skip)]
    ed25519_public: Vec<u8>,
    mldsa_keypair: MlDsaKeyPair,
}

/// Hybrid signature (concatenation of both signatures)
pub struct HybridSignature {
    pub ed25519_sig: Vec<u8>,
    pub mldsa_sig: Vec<u8>,
}

/// Hybrid signing engine
pub struct HybridSignEngine;

impl HybridSignEngine {
    /// Generate hybrid signing key pair
    pub fn generate_keypair(
        pqc_level: MlDsaSecurityLevel,
    ) -> Result<HybridSignKeyPair, CryptoError> {
        let (ed25519_private, ed25519_public) = Ed25519Engine::generate_keypair()?;
        let mldsa_keypair = MlDsaEngine::generate_keypair(pqc_level)?;

        Ok(HybridSignKeyPair {
            ed25519_private,
            ed25519_public,
            mldsa_keypair,
        })
    }

    /// Sign with both algorithms
    pub fn sign(
        keypair: &HybridSignKeyPair,
        message: &[u8],
    ) -> Result<HybridSignature, CryptoError> {
        let ed25519_sig = Ed25519Engine::sign(&keypair.ed25519_private, message)?;
        let mldsa_sig = MlDsaEngine::sign(&keypair.mldsa_keypair, message)?;

        Ok(HybridSignature {
            ed25519_sig,
            mldsa_sig: mldsa_sig.bytes,
        })
    }

    /// Verify both signatures (both must be valid)
    pub fn verify(
        ed25519_public: &[u8],
        mldsa_public: &[u8],
        message: &[u8],
        signature: &HybridSignature,
        pqc_level: MlDsaSecurityLevel,
    ) -> Result<bool, CryptoError> {
        // Verify Ed25519
        let ed25519_valid = Ed25519Engine::verify(
            ed25519_public,
            message,
            &signature.ed25519_sig,
        )?;

        if !ed25519_valid {
            return Ok(false);
        }

        // Verify ML-DSA
        let mldsa_sig = super::mldsa::MlDsaSignature {
            bytes: signature.mldsa_sig.clone(),
        };
        let mldsa_valid = MlDsaEngine::verify(
            mldsa_public,
            message,
            &mldsa_sig,
            pqc_level,
        )?;

        Ok(mldsa_valid)
    }
}
```

### Step 5: Add Error Types

Create `crates/crypto-engine/src/pqc/error.rs`:

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PqcError {
    #[error("Invalid key size for {algorithm}: expected {expected}, got {actual}")]
    InvalidKeySize {
        algorithm: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("Invalid ciphertext size for {algorithm}")]
    InvalidCiphertextSize { algorithm: &'static str },

    #[error("Decapsulation failed")]
    DecapsulationFailed,

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
}
```

### Step 6: Update KeyAlgorithm Enum

In `crates/key-manager/src/types.rs`, add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    // Existing...
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa4096,
    Aes128,
    Aes256,

    // Post-quantum
    MlKem768,
    MlKem1024,
    MlDsa65,
    MlDsa87,

    // Hybrid
    HybridKemX25519MlKem768,
    HybridKemX25519MlKem1024,
    HybridSignEd25519MlDsa65,
    HybridSignEd25519MlDsa87,
}
```

### Step 7: Add gRPC Endpoints

Add to `proto/hsm.proto`:

```protobuf
// Post-quantum key generation
message GeneratePqcKeyRequest {
    string key_id = 1;
    PqcAlgorithm algorithm = 2;
    string namespace = 3;
}

enum PqcAlgorithm {
    ML_KEM_768 = 0;
    ML_KEM_1024 = 1;
    ML_DSA_65 = 2;
    ML_DSA_87 = 3;
    HYBRID_KEM_X25519_ML_KEM_768 = 4;
    HYBRID_KEM_X25519_ML_KEM_1024 = 5;
    HYBRID_SIGN_ED25519_ML_DSA_65 = 6;
    HYBRID_SIGN_ED25519_ML_DSA_87 = 7;
}

// KEM operations
message EncapsulateRequest {
    string key_id = 1;
}

message EncapsulateResponse {
    bytes shared_secret = 1;
    bytes ciphertext = 2;
}

message DecapsulateRequest {
    string key_id = 1;
    bytes ciphertext = 2;
}

message DecapsulateResponse {
    bytes shared_secret = 1;
}
```

## Testing Requirements

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem_768_roundtrip() {
        let keypair = MlKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
        let (shared1, ct) = MlKemEngine::encapsulate(
            &keypair.public_key,
            MlKemSecurityLevel::MlKem768,
        ).unwrap();
        let shared2 = MlKemEngine::decapsulate(&keypair, &ct).unwrap();
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_mldsa_65_sign_verify() {
        let keypair = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
        let message = b"test message";
        let sig = MlDsaEngine::sign(&keypair, message).unwrap();
        let valid = MlDsaEngine::verify(
            &keypair.public_key,
            message,
            &sig,
            MlDsaSecurityLevel::MlDsa65,
        ).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let keypair = HybridKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
        let (shared1, ct) = HybridKemEngine::encapsulate(
            &keypair.x25519_public,
            &keypair.mlkem_keypair.public_key,
            MlKemSecurityLevel::MlKem768,
        ).unwrap();
        let shared2 = HybridKemEngine::decapsulate(&keypair, &ct).unwrap();
        assert_eq!(shared1, shared2);
    }
}
```

### Property Tests

```rust
proptest! {
    #[test]
    fn prop_mlkem_encapsulate_decapsulate_roundtrip(_seed in any::<u64>()) {
        let keypair = MlKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
        let (shared1, ct) = MlKemEngine::encapsulate(
            &keypair.public_key,
            MlKemSecurityLevel::MlKem768,
        ).unwrap();
        let shared2 = MlKemEngine::decapsulate(&keypair, &ct).unwrap();
        prop_assert_eq!(shared1, shared2);
    }

    #[test]
    fn prop_mldsa_sign_verify_roundtrip(message in prop::collection::vec(any::<u8>(), 0..1024)) {
        let keypair = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
        let sig = MlDsaEngine::sign(&keypair, &message).unwrap();
        let valid = MlDsaEngine::verify(
            &keypair.public_key,
            &message,
            &sig,
            MlDsaSecurityLevel::MlDsa65,
        ).unwrap();
        prop_assert!(valid);
    }
}
```

### Benchmarks

```rust
fn bench_pqc(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc");

    group.bench_function("mlkem768_keygen", |b| {
        b.iter(|| MlKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768))
    });

    let keypair = MlKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
    group.bench_function("mlkem768_encapsulate", |b| {
        b.iter(|| MlKemEngine::encapsulate(&keypair.public_key, MlKemSecurityLevel::MlKem768))
    });

    group.bench_function("mldsa65_keygen", |b| {
        b.iter(|| MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65))
    });

    let sign_keypair = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
    let message = b"benchmark message";
    group.bench_function("mldsa65_sign", |b| {
        b.iter(|| MlDsaEngine::sign(&sign_keypair, message))
    });

    group.finish();
}
```

## Success Metrics

- [ ] ML-KEM-768 keygen: <10ms
- [ ] ML-KEM-768 encapsulate: <1ms
- [ ] ML-KEM-768 decapsulate: <1ms
- [ ] ML-DSA-65 keygen: <50ms
- [ ] ML-DSA-65 sign: <5ms
- [ ] ML-DSA-65 verify: <3ms
- [ ] All roundtrip tests pass
- [ ] Hybrid modes combine secrets correctly
- [ ] Memory zeroization on key drop

## Notes

- PQC key sizes are much larger than classical (ML-KEM-768 public key: 1184 bytes vs X25519: 32 bytes)
- Signature sizes are also larger (ML-DSA-65: 3309 bytes vs Ed25519: 64 bytes)
- Consider storage implications when enabling PQC
- Hybrid modes provide migration path and defense-in-depth
