#![allow(clippy::wrong_self_convention)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::inherent_to_string)]
#![allow(clippy::inherent_to_string_shadow_display)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::manual_strip)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_div_ceil)]

//! HSM Blockchain Module
//!
//! Provides blockchain-specific cryptographic operations including:
//! - HD key derivation (BIP-32/39/44)
//! - Ethereum message signing (EIP-191/712)
//! - Bitcoin transaction support
//! - Solana transaction support
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                      HSM Blockchain Module                           │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                       │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │
//! │  │   BIP-32    │  │   BIP-39    │  │   BIP-44    │                  │
//! │  │ HD Derive   │  │  Mnemonic   │  │  Accounts   │                  │
//! │  └─────────────┘  └─────────────┘  └─────────────┘                  │
//! │          │                │                │                          │
//! │          └────────────────┴────────────────┘                          │
//! │                          │                                            │
//! │                    Master Seed                                        │
//! │                          │                                            │
//! │    ┌─────────────┬───────┼───────┬─────────────┐                     │
//! │    ▼             ▼       ▼       ▼             ▼                     │
//! │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐                    │
//! │  │Ethereum │ │ Bitcoin │ │ Solana  │ │StarkNet │                    │
//! │  │EIP-191/ │ │ BIP-341 │ │ Ed25519 │ │SNIP-12  │                    │
//! │  │  712    │ │         │ │         │ │         │                    │
//! │  └─────────┘ └─────────┘ └─────────┘ └─────────┘                    │
//! │                                                                       │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```

pub mod bip;
pub mod bitcoin;
pub mod error;
pub mod ethereum;
pub mod solana;
pub mod starknet;

// New chain modules (HSM v2)
pub mod aptos;
pub mod cosmos;
pub mod l2;
pub mod near;
pub mod polkadot;
pub mod sui;
pub mod ton;

pub use bip::{
    bip32::{DerivationPath, ExtendedPrivateKey, ExtendedPublicKey},
    bip39::{Language, Mnemonic, MnemonicType},
    bip44::{AccountPath, CoinType},
};
pub use error::{BlockchainError, Result};
pub use ethereum::{
    address::EthereumAddress,
    eip191::{Eip191Message, PersonalMessage},
    eip712::{Eip712Domain, Eip712TypedData, TypedDataHasher},
};
pub use starknet::{
    address::{StarknetAddress, WalletType},
    key::{StarkPrivateKey, StarkPublicKey},
    signing::{StarkSignature, StarknetDomain, TypedData as StarknetTypedData},
};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
