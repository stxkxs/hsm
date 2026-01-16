//! Asymmetric cryptography (digital signatures).
//!
//! Provides digital signature algorithms:
//! - **Ed25519**: Recommended for new applications (fastest, most secure)
//! - **ECDSA**: NIST P-256 and P-384 curves (FIPS compliant)
//! - **RSA**: Legacy support (RUSTSEC-2023-0071 applies)

pub mod ecdsa;
pub mod ed25519;
pub mod rsa;
