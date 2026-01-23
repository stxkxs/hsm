//! BIP (Bitcoin Improvement Proposals) implementations
//!
//! This module provides implementations of key BIPs for HD wallet functionality:
//! - BIP-32: Hierarchical Deterministic Wallets
//! - BIP-39: Mnemonic code for generating deterministic keys
//! - BIP-44: Multi-Account Hierarchy for Deterministic Wallets

pub mod bip32;
pub mod bip39;
pub mod bip44;

pub use self::bip32::{DerivationPath, ExtendedPrivateKey, ExtendedPublicKey};
pub use self::bip39::{Language, Mnemonic, MnemonicType};
pub use self::bip44::{AccountPath, CoinType};
