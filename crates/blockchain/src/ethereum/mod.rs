//! Ethereum-specific cryptographic operations
//!
//! Provides support for:
//! - EIP-191: Personal message signing
//! - EIP-712: Typed data signing
//! - Ethereum address generation
//! - Transaction signing

pub mod address;
pub mod eip191;
pub mod eip712;
pub mod transaction;

pub use address::EthereumAddress;
pub use eip191::{Eip191Message, PersonalMessage};
pub use eip712::{Eip712Domain, Eip712TypedData, TypedDataHasher};
