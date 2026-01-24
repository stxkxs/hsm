//! Cosmos SDK blockchain support
//!
//! Provides signing and transaction support for Cosmos-based chains:
//! - Cosmos Hub (ATOM)
//! - Osmosis (OSMO)
//! - Injective (INJ)
//! - Celestia (TIA)
//! - dYdX (DYDX)
//! - And other Cosmos SDK chains
//!
//! # Features
//!
//! - secp256k1 signing with Cosmos address derivation
//! - Amino and Protobuf transaction encoding
//! - Multi-chain support via chain registry
//! - ADR-036 arbitrary message signing

pub mod chains;
pub mod signing;
pub mod transaction;

pub use chains::{ChainConfig, ChainRegistry, KnownChain};
pub use signing::{CosmosAddress, CosmosSigner};
pub use transaction::{AuthInfo, Coin, Fee, MsgSend, SignDoc, SignMode, SignerInfo, TxBody, TxRaw};

use crate::error::Result;

/// Cosmos address prefix (bech32 human-readable part)
pub type AddressPrefix = String;

/// Cosmos public key types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubKeyType {
    /// secp256k1 (default for most Cosmos chains)
    Secp256k1,
    /// Ed25519 (used by some chains like Tendermint)
    Ed25519,
}

impl Default for PubKeyType {
    fn default() -> Self {
        Self::Secp256k1
    }
}

/// Create a Cosmos address from a public key
pub fn derive_address(public_key: &[u8], prefix: &str) -> Result<String> {
    CosmosAddress::from_public_key(public_key, prefix)
}

/// Sign a Cosmos transaction
pub fn sign_transaction(private_key: &[u8], sign_doc: &SignDoc) -> Result<Vec<u8>> {
    CosmosSigner::sign(private_key, sign_doc)
}

/// Sign an arbitrary message (ADR-036)
pub fn sign_arbitrary(private_key: &[u8], message: &[u8], signer_address: &str) -> Result<Vec<u8>> {
    CosmosSigner::sign_arbitrary(private_key, message, signer_address)
}
