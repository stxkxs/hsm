//! Post-Quantum Cryptography module.
//!
//! Provides NIST-standardized post-quantum algorithms:
//! - **ML-KEM** (Kyber): Key Encapsulation Mechanism for establishing shared secrets
//! - **ML-DSA** (Dilithium): Digital Signature Algorithm for signing and verification
//! - **Hybrid modes**: Combining classical (X25519, Ed25519) with PQC for defense-in-depth
//!
//! # Quantum Threat
//!
//! Large-scale quantum computers could break current public-key cryptography:
//! - RSA, ECDSA, and ECDH are vulnerable to Shor's algorithm
//! - AES and SHA remain secure (with doubled key sizes for AES)
//!
//! Post-quantum algorithms are designed to resist attacks from both classical
//! and quantum computers.
//!
//! # NIST Standardization
//!
//! - **FIPS 203**: ML-KEM (Module-Lattice Key Encapsulation Mechanism)
//! - **FIPS 204**: ML-DSA (Module-Lattice Digital Signature Algorithm)
//!
//! # Recommended Approach
//!
//! During the transition period, use hybrid modes that combine classical and
//! post-quantum algorithms. This provides:
//! - **Defense-in-depth**: Security even if one algorithm is broken
//! - **Compliance**: Meets current standards while preparing for quantum threats
//! - **Gradual migration**: Allows incremental adoption
//!
//! # Security Levels
//!
//! | Algorithm | NIST Level | Classical Security |
//! |-----------|------------|-------------------|
//! | ML-KEM-768 | 3 | ~192-bit |
//! | ML-KEM-1024 | 5 | ~256-bit |
//! | ML-DSA-65 | 3 | ~192-bit |
//! | ML-DSA-87 | 5 | ~256-bit |
//!
//! # Key Size Comparison
//!
//! Post-quantum keys and signatures are significantly larger:
//!
//! | Algorithm | Public Key | Signature/Ciphertext |
//! |-----------|------------|---------------------|
//! | Ed25519 | 32 bytes | 64 bytes |
//! | ML-DSA-65 | 1952 bytes | 3309 bytes |
//! | X25519 | 32 bytes | N/A |
//! | ML-KEM-768 | 1184 bytes | 1088 bytes |
//!
//! # Example: Post-Quantum Key Encapsulation
//!
//! ```rust
//! use hsm_crypto_engine::pqc::{MlKemEngine, MlKemSecurityLevel};
//!
//! // Generate key pair
//! let keypair = MlKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
//!
//! // Encapsulate (sender creates shared secret)
//! let (shared_sender, ciphertext) = MlKemEngine::encapsulate(
//!     &keypair.public_key,
//!     MlKemSecurityLevel::MlKem768,
//! ).unwrap();
//!
//! // Decapsulate (receiver recovers shared secret)
//! let shared_receiver = MlKemEngine::decapsulate(&keypair, &ciphertext).unwrap();
//!
//! assert_eq!(shared_sender, shared_receiver);
//! ```
//!
//! # Example: Post-Quantum Digital Signatures
//!
//! ```rust
//! use hsm_crypto_engine::pqc::{MlDsaEngine, MlDsaSecurityLevel};
//!
//! // Generate key pair
//! let keypair = MlDsaEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
//!
//! // Sign message
//! let message = b"Important document";
//! let signature = MlDsaEngine::sign(&keypair, message).unwrap();
//!
//! // Verify signature
//! let valid = MlDsaEngine::verify(
//!     &keypair.public_key,
//!     message,
//!     &signature,
//!     MlDsaSecurityLevel::MlDsa65,
//! ).unwrap();
//!
//! assert!(valid);
//! ```
//!
//! # Example: Hybrid Mode (Recommended)
//!
//! ```rust
//! use hsm_crypto_engine::pqc::{HybridKemEngine, HybridSignEngine, MlKemSecurityLevel, MlDsaSecurityLevel};
//!
//! // Hybrid KEM (X25519 + ML-KEM)
//! let kem_keypair = HybridKemEngine::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
//! let (shared1, ciphertext) = HybridKemEngine::encapsulate(&kem_keypair).unwrap();
//! let shared2 = HybridKemEngine::decapsulate(&kem_keypair, &ciphertext).unwrap();
//! assert_eq!(shared1, shared2);
//!
//! // Hybrid Signatures (Ed25519 + ML-DSA)
//! let sign_keypair = HybridSignEngine::generate_keypair(MlDsaSecurityLevel::MlDsa65).unwrap();
//! let message = b"Important document";
//! let signature = HybridSignEngine::sign(&sign_keypair, message).unwrap();
//! let valid = HybridSignEngine::verify(&sign_keypair, message, &signature).unwrap();
//! assert!(valid);
//! ```

mod error;
pub mod hybrid;
pub mod mldsa;
pub mod mlkem;

// Re-export error types
pub use error::PqcError;

// Re-export ML-KEM types
pub use mlkem::{MlKemCiphertext, MlKemEngine, MlKemKeyPair, MlKemSecurityLevel};

// Re-export ML-DSA types
pub use mldsa::{MlDsaEngine, MlDsaKeyPair, MlDsaSecurityLevel, MlDsaSignature};

// Re-export Hybrid types
pub use hybrid::{
    HybridKemCiphertext, HybridKemEngine, HybridKemKeyPair, HybridSignEngine, HybridSignKeyPair,
    HybridSignature,
};
