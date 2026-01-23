//! StarkNet Support
//!
//! This module provides StarkNet-specific cryptographic operations including:
//! - Stark curve key generation and management
//! - ECDSA signatures on the Stark curve
//! - StarkNet address derivation
//! - Message signing compatible with StarkNet wallets
//!
//! # Stark Curve
//!
//! StarkNet uses a STARK-friendly elliptic curve defined over a prime field.
//! The curve parameters are:
//! - Field prime: 2^251 + 17 * 2^192 + 1
//! - Curve equation: y² = x³ + α*x + β
//! - α = 1
//! - β = 3141592653589793238462643383279502884197169399375105820974944592307816406665
//!
//! # Security
//!
//! All private keys are zeroized on drop to prevent memory leakage.

pub mod address;
pub mod key;
pub mod signing;

pub use address::StarknetAddress;
pub use key::{StarkPrivateKey, StarkPublicKey};
pub use signing::{StarkSignature, TypedData};
