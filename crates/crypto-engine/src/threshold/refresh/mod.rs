//! Key Refresh and Resharing Protocol for Threshold Cryptography
//!
//! This module implements proactive key refresh and resharing protocols that allow:
//!
//! - **Key Refresh**: Update all shares while preserving the same group public key.
//!   This provides proactive security against gradual key compromise.
//!
//! - **Resharing**: Change the threshold or participant set while preserving the
//!   group public key. This enables adding/removing participants or changing the
//!   security threshold.
//!
//! # Protocol Overview
//!
//! ## Key Refresh
//!
//! 1. Each participant generates a polynomial with ZERO constant term
//! 2. Compute and broadcast Feldman commitments (first must be identity point)
//! 3. Exchange refresh shares with all other participants
//! 4. Each participant adds all received refresh shares to their old share
//! 5. Result: new share = old share + sum(refresh_shares), group key unchanged
//!
//! ## Resharing
//!
//! 1. Old participants (at least t of them) generate new shares for new participants
//! 2. Each old participant evaluates their share at the new participant IDs
//! 3. New participants receive shares from old participants
//! 4. New participants combine using Lagrange interpolation
//!
//! # Security Properties
//!
//! - Shares are refreshed without changing the group public key
//! - Old shares become unusable for signing after refresh
//! - Proactive security: periodic refresh limits damage from gradual compromise
//! - Forward secrecy: compromised old shares don't help with new shares
//!
//! # Supported Schemes
//!
//! - FROST Ed25519
//! - Threshold ECDSA P-256
//! - Threshold ECDSA secp256k1
//! - Threshold BLS12-381

mod protocol;
mod resharing;

pub use protocol::{KeyRefreshProtocol, RefreshRound1Package, RefreshRound2Package, RefreshState};
pub use resharing::{Resharing, ResharingPackage};

#[cfg(test)]
mod tests;
