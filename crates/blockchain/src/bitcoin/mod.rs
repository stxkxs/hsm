//! Bitcoin-specific cryptographic operations
//!
//! Provides support for:
//! - Bitcoin address generation
//! - Transaction parsing
//! - PSBT support (future)

pub mod address;
pub mod transaction;

pub use address::{BitcoinAddress, BitcoinNetwork};
