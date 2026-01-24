//! Threshold BLS12-381 module
//!
//! This module implements threshold signatures using the BLS12-381 curve.
//! BLS (Boneh-Lynn-Shacham) signatures provide several unique properties:
//!
//! - **Single-round signing**: No commitment phase needed (unlike FROST/ECDSA)
//! - **Native aggregation**: Multiple signatures can be combined into one
//! - **Deterministic**: Same key + message always produces the same signature
//! - **Short signatures**: 96 bytes (compressed G2 point)
//!
//! # FIPS Compliance Status
//!
//! BLS12-381 is currently under NIST evaluation and is NOT yet FIPS 140-3 approved.
//! For FIPS-compliant applications, use:
//! - FROST-Ed25519 (Ed25519 is FIPS 186-5 approved)
//! - Threshold-ECDSA-P256 (NIST P-256 curve)
//!
//! # Use Cases
//!
//! - Ethereum 2.0 validator signatures
//! - Blockchain consensus protocols
//! - Multi-party signature aggregation
//! - Privacy-preserving credential systems
//!
//! # Protocol Overview
//!
//! ## Key Generation (Trusted Dealer)
//!
//! 1. Generate random master secret key
//! 2. Split using Shamir's Secret Sharing over BLS scalar field
//! 3. Distribute shares to participants
//!
//! ## Signing (Single Round)
//!
//! 1. Each participant signs message: sigma_i = sk_i * H(m)
//! 2. Coordinator collects signature shares
//! 3. Aggregate using Lagrange interpolation: sigma = sum(lambda_i * sigma_i)
//!
//! ## Verification
//!
//! Standard BLS verification: e(pk, H(m)) == e(G1, sigma)
//!
//! # Example
//!
//! ```ignore
//! use hsm_crypto_engine::threshold::bls::{ThresholdBlsEngine, BlsKeyShare};
//! use hsm_crypto_engine::threshold::ThresholdConfig;
//!
//! // Generate 2-of-3 threshold keys
//! let config = ThresholdConfig::new(2, 3).unwrap();
//! let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();
//!
//! // Each participant signs independently (no coordination needed!)
//! let message = b"Hello, threshold BLS!";
//! let share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
//! let share2 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
//!
//! // Aggregate signature shares
//! let participants = vec![shares[0].participant_id, shares[1].participant_id];
//! let signature = ThresholdBlsEngine::aggregate(&[share1, share2], &participants).unwrap();
//!
//! // Verify against group public key
//! assert!(ThresholdBlsEngine::verify(&group_key, message, &signature).unwrap());
//! ```
//!
//! # Security Considerations
//!
//! - **Key Material**: All secret key shares are zeroized on drop
//! - **Determinism**: BLS signatures are deterministic - same key+message = same signature
//! - **No Nonce Risks**: Unlike ECDSA, no random nonces means no nonce-reuse vulnerabilities
//! - **Rogue Key Attacks**: Use proof-of-possession for aggregated public keys in production
//!
//! # Performance
//!
//! Typical performance on modern hardware:
//! - Key generation: ~1ms per participant
//! - Signing: ~0.5ms per share
//! - Aggregation: ~0.2ms for typical threshold
//! - Verification: ~1.5ms per signature

pub mod dkg;
pub mod engine;
pub mod types;

// Re-export main types for convenience
pub use dkg::{BlsDkg, BlsDkgRound1Package, BlsDkgRound2Package, BlsDkgState};
pub use engine::ThresholdBlsEngine;
pub use types::{
    BlsGroupPublicKey, BlsKeyShare, BlsSignatureShare, BlsThresholdSignature, BLS_DST,
};
