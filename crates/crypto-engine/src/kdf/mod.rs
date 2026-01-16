//! Key derivation functions (KDF).
//!
//! Provides cryptographic key derivation:
//! - **Argon2**: Password hashing (recommended for new applications)
//! - **HKDF**: Extract-and-expand for deriving multiple keys from one secret
//! - **PBKDF2**: Password-based key derivation (legacy, slower than Argon2)

pub mod argon2;
pub mod hkdf;
pub mod pbkdf2;
