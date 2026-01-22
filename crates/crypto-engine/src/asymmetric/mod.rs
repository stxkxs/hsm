//! Asymmetric cryptography (digital signatures).
//!
//! Provides digital signature algorithms:
//! - **Ed25519**: Recommended for new applications (fastest, most secure)
//! - **ECDSA**: NIST P-256 and P-384 curves (FIPS compliant)
//! - **secp256k1**: Bitcoin/Ethereum curve (ECDSA and Schnorr)
//! - **BLS**: BLS12-381 signatures with aggregation (Ethereum 2.0)
//! - **RSA**: Legacy support (RUSTSEC-2023-0071 applies)

pub mod bls;
pub mod ecdsa;
pub mod ed25519;
pub mod rsa;
pub mod secp256k1;
