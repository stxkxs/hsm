//! Symmetric encryption algorithms.
//!
//! Provides AES encryption in multiple modes:
//! - **AES-GCM**: Authenticated encryption (recommended for new applications)
//! - **AES-CBC**: Legacy encryption-only mode (requires separate authentication)

pub mod aes_cbc;
pub mod aes_gcm;
