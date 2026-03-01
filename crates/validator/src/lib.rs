#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
//! HSM Validator Module - Anti-Slashing Protection for Blockchain Validators
//!
//! This crate provides validator key management with **always-on, unforgeable**
//! anti-slashing protection for Ethereum and Babylon validators.
//!
//! # Security Model
//!
//! - **Anti-slashing cannot be disabled** - Protection is hardcoded and enforced
//! - **Atomic check-and-sign** - Prevents TOCTOU race conditions
//! - **Persistent storage** - Slashing protection survives restarts
//! - **Multi-client safe** - Works with any validator client
//!
//! # Supported Protocols
//!
//! - **Ethereum 2.0**: BLS signatures with attestation and block slashing protection
//! - **Babylon**: EOTS (Extractable One-Time Signatures) for Bitcoin staking
//! - **Cosmos**: Tendermint double-sign protection
//!
//! # Example
//!
//! ```rust,ignore
//! use hsm_validator::{ValidatorService, ForkInfo};
//!
//! // Create validator service with persistent anti-slashing database
//! let service = ValidatorService::new("/path/to/slashing-db").await?;
//!
//! // Configure fork info for mainnet
//! let fork_info = ForkInfo::new([0; 4], [0; 32]);
//!
//! // Create a validator with a secret key
//! let validator = service.create_ethereum_validator(&secret_key_bytes, fork_info)?;
//!
//! // Sign attestation - automatically protected against slashing
//! let signature = validator.sign_attestation(&attestation_data)?;
//! ```
//!
//! # EIP-3076 Interchange
//!
//! Import/export slashing protection data for migration between clients:
//!
//! ```rust,ignore
//! use hsm_validator::interchange::Eip3076Interchange;
//!
//! // Export for migration
//! let interchange = service.export_ethereum_slashing_protection("0x...", None)?;
//! let json = interchange.to_json()?;
//!
//! // Import from another client
//! let interchange = Eip3076Interchange::from_json(&json)?;
//! service.import_ethereum_slashing_protection(&interchange)?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "babylon")]
pub mod babylon;
pub mod error;
pub mod ethereum;
pub mod interchange;
pub mod service;
pub mod slashing_db;
pub mod types;

// Re-exports
#[cfg(feature = "babylon")]
pub use babylon::{BabylonValidator, EotsKey};
pub use error::{SlashingError, ValidatorError};
pub use ethereum::{AttestationData, BeaconBlockHeader, EthereumValidator};
pub use interchange::Eip3076Interchange;
pub use service::ValidatorService;
pub use slashing_db::SlashingProtectionDb;
pub use types::*;
