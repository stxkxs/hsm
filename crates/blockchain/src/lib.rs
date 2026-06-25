#![deny(unsafe_code)]
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

//! # HSM Blockchain Module
//!
//! Provides blockchain-specific cryptographic operations including HD key derivation,
//! multi-chain signing, and typed data hashing for Web3 applications.
//!
//! ## Features
//!
//! - **HD Key Derivation**: BIP-32/39/44 compliant hierarchical deterministic keys
//! - **Ethereum**: EIP-191 personal signing, EIP-712 typed data, transaction signing
//! - **Bitcoin**: BIP-341 Taproot, SegWit, P2PKH/P2SH address derivation
//! - **Solana**: Ed25519 signing, SPL token support
//! - **StarkNet**: SNIP-12 typed data, Stark curve signatures
//! - **Multi-chain**: Cosmos, Polkadot, NEAR, Sui, Aptos, TON
//!
//! ## Architecture
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
//!
//! ## Quick Start
//!
//! ### Generate HD Wallet from Mnemonic (BIP-39)
//!
//! ```rust,ignore
//! use hsm_blockchain::{Mnemonic, MnemonicType, Language, ExtendedPrivateKey};
//!
//! // Generate a new 24-word mnemonic
//! let mnemonic = Mnemonic::generate(MnemonicType::Words24, Language::English)?;
//! println!("Mnemonic: {}", mnemonic.phrase());
//!
//! // Or restore from existing phrase
//! let mnemonic = Mnemonic::from_phrase(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//!     Language::English,
//! )?;
//!
//! // Derive master key with optional passphrase
//! let seed = mnemonic.to_seed("optional-passphrase");
//! let master_key = ExtendedPrivateKey::from_seed(&seed)?;
//! ```
//!
//! ### Derive Keys (BIP-44 Multi-Account)
//!
//! ```rust,ignore
//! use hsm_blockchain::{DerivationPath, ExtendedPrivateKey, CoinType, AccountPath};
//!
//! // BIP-44 path: m/44'/60'/0'/0/0 (Ethereum, first account, first address)
//! let eth_path = AccountPath::new(CoinType::Ethereum, 0, false, 0);
//! let eth_key = master_key.derive(&eth_path.to_derivation_path())?;
//!
//! // Bitcoin path: m/44'/0'/0'/0/0
//! let btc_path = AccountPath::new(CoinType::Bitcoin, 0, false, 0);
//! let btc_key = master_key.derive(&btc_path.to_derivation_path())?;
//!
//! // Solana path: m/44'/501'/0'/0'
//! let sol_path = AccountPath::new(CoinType::Solana, 0, false, 0);
//! let sol_key = master_key.derive(&sol_path.to_derivation_path())?;
//!
//! // Custom derivation path
//! let custom_path = DerivationPath::from_str("m/44'/60'/0'/0/5")?;
//! let custom_key = master_key.derive(&custom_path)?;
//! ```
//!
//! ### Ethereum: EIP-191 Personal Message Signing
//!
//! Sign a human-readable message with the Ethereum personal_sign prefix:
//!
//! ```rust,ignore
//! use hsm_blockchain::ethereum::{PersonalMessage, Eip191Message};
//!
//! // Create a personal message (adds "\x19Ethereum Signed Message:\n" prefix)
//! let message = PersonalMessage::new("Hello, World!");
//!
//! // Get the hash to sign
//! let hash = message.hash();
//!
//! // Sign with your private key (secp256k1)
//! let signature = eth_key.sign(&hash)?;
//!
//! // The signature can be verified on-chain or off-chain
//! // Returns (v, r, s) format for EVM compatibility
//! println!("v: {}, r: {:?}, s: {:?}", signature.v, signature.r, signature.s);
//! ```
//!
//! ### Ethereum: EIP-712 Typed Data Signing
//!
//! Sign structured data for smart contract interactions (permits, orders, etc.):
//!
//! ```rust,ignore
//! use hsm_blockchain::ethereum::{Eip712Domain, Eip712TypedData, TypedDataHasher};
//! use serde_json::json;
//!
//! // Define the EIP-712 domain (identifies the dApp/contract)
//! let domain = Eip712Domain {
//!     name: Some("MyDApp".to_string()),
//!     version: Some("1".to_string()),
//!     chain_id: Some(1), // Ethereum mainnet
//!     verifying_contract: Some("0x1234...".parse()?),
//!     salt: None,
//! };
//!
//! // Define your typed data structure
//! let typed_data = json!({
//!     "types": {
//!         "EIP712Domain": [
//!             {"name": "name", "type": "string"},
//!             {"name": "version", "type": "string"},
//!             {"name": "chainId", "type": "uint256"},
//!             {"name": "verifyingContract", "type": "address"}
//!         ],
//!         "Permit": [
//!             {"name": "owner", "type": "address"},
//!             {"name": "spender", "type": "address"},
//!             {"name": "value", "type": "uint256"},
//!             {"name": "nonce", "type": "uint256"},
//!             {"name": "deadline", "type": "uint256"}
//!         ]
//!     },
//!     "primaryType": "Permit",
//!     "domain": domain,
//!     "message": {
//!         "owner": "0xowner...",
//!         "spender": "0xspender...",
//!         "value": "1000000000000000000",
//!         "nonce": 0,
//!         "deadline": 1704067200
//!     }
//! });
//!
//! // Compute the hash and sign
//! let hasher = TypedDataHasher::new(&typed_data)?;
//! let hash = hasher.hash()?;
//! let signature = eth_key.sign(&hash)?;
//! ```
//!
//! ### Multi-Chain Address Derivation
//!
//! ```rust,ignore
//! use hsm_blockchain::{
//!     EthereumAddress,
//!     bitcoin::BitcoinAddress,
//!     solana::SolanaAddress,
//!     starknet::StarknetAddress,
//! };
//!
//! // Derive addresses from keys
//! let eth_address = EthereumAddress::from_public_key(&eth_key.public_key())?;
//! println!("Ethereum: {}", eth_address); // 0x...
//!
//! let btc_address = BitcoinAddress::p2wpkh(&btc_key.public_key(), Network::Mainnet)?;
//! println!("Bitcoin (SegWit): {}", btc_address); // bc1q...
//!
//! let sol_address = SolanaAddress::from_public_key(&sol_key.public_key())?;
//! println!("Solana: {}", sol_address); // Base58 address
//!
//! let stark_address = StarknetAddress::from_public_key(&stark_key.public_key(), WalletType::ArgentX)?;
//! println!("StarkNet: {}", stark_address); // 0x...
//! ```
//!
//! ## Supported Chains
//!
//! | Chain | Curve | Address Format | Signing Standards |
//! |-------|-------|----------------|-------------------|
//! | Ethereum | secp256k1 | EIP-55 checksum | EIP-191, EIP-712, EIP-1559 |
//! | Bitcoin | secp256k1 | Bech32, Base58 | BIP-340 Schnorr, ECDSA |
//! | Solana | Ed25519 | Base58 | Ed25519 |
//! | StarkNet | Stark | Hex | SNIP-12 |
//! | Cosmos | secp256k1 | Bech32 | ADR-036 |
//! | Polkadot | Sr25519/Ed25519 | SS58 | Sr25519 |
//! | NEAR | Ed25519 | Base58 | Ed25519 |
//! | Sui | Ed25519 | Hex | Ed25519 |
//! | Aptos | Ed25519 | Hex | Ed25519 |
//! | TON | Ed25519 | Base64 | Ed25519 |
//!
//! ## Security Considerations
//!
//! - **Never Export Seeds**: Master seeds should never leave the HSM
//! - **Hardened Derivation**: Use hardened paths (') for account-level keys
//! - **Key Isolation**: Derive separate keys per application/chain
//! - **Deterministic Signatures**: All signatures are deterministic (RFC 6979)
//! - **Memory Zeroization**: Private keys are zeroized when dropped

pub mod bip;
pub mod bitcoin;
pub mod error;
pub mod ethereum;
pub mod solana;
pub mod starknet;

// New chain modules (HSM v2)
pub mod cosmos;
pub mod l2;
pub mod polkadot;
pub mod ton;

// Experimental, beyond-spec chains. Their transaction serialization is NOT yet
// canonical (each module carries an EXPERIMENTAL notice), so signatures produced
// for them are not guaranteed to verify on-chain. Gated off by default behind
// the `experimental-chains` feature so they are never part of a production build
// until canonical encoders land.
#[cfg(feature = "experimental-chains")]
pub mod aptos;
#[cfg(feature = "experimental-chains")]
pub mod near;
#[cfg(feature = "experimental-chains")]
pub mod sui;

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
