//! Threshold Cryptography module
//!
//! Implements threshold signature schemes where keys are split among
//! multiple parties, requiring t-of-n parties to sign. No single party
//! ever holds the complete signing key.
//!
//! # Supported Schemes
//!
//! - **FROST Ed25519**: Schnorr threshold signatures on Curve25519
//!
//! # Security Properties
//!
//! - No single party ever holds the complete signing key
//! - Compromising fewer than t parties reveals nothing about the key
//! - Supports distributed key generation (no trusted dealer needed)
//! - Threshold signatures are indistinguishable from regular Ed25519 signatures
//!
//! # Usage
//!
//! ## Trusted Dealer Key Generation
//!
//! When a trusted party can generate and distribute keys:
//!
//! ```rust
//! use hsm_crypto_engine::threshold::{ThresholdConfig, FrostEngine, SigningParticipant};
//!
//! // Generate 2-of-3 threshold keys
//! let config = ThresholdConfig::new(2, 3).unwrap();
//! let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();
//!
//! // Distribute shares to participants (securely!)
//! let mut participants: Vec<_> = shares
//!     .into_iter()
//!     .map(|share| SigningParticipant::new(share, group_key.clone()))
//!     .collect();
//! ```
//!
//! ## Distributed Key Generation (DKG)
//!
//! When no trusted dealer is available:
//!
//! ```rust
//! use hsm_crypto_engine::threshold::{ThresholdConfig, DistributedKeyGeneration, ParticipantId};
//!
//! // Each participant runs independently
//! let config = ThresholdConfig::new(2, 3).unwrap();
//! let mut dkg = DistributedKeyGeneration::new(config, ParticipantId(1)).unwrap();
//!
//! // Execute 3-round protocol
//! // Round 1: broadcast commitment
//! let round1_pkg = dkg.round1().unwrap();
//! // ... receive round1 packages from others ...
//!
//! // Round 2: generate per-participant shares
//! // let round2_pkgs = dkg.round2(received_round1_packages).unwrap();
//! // ... send round2 packages to each participant ...
//!
//! // Round 3: finalize
//! // let (key_share, group_key) = dkg.finalize(received_round2_packages).unwrap();
//! ```
//!
//! ## Threshold Signing
//!
//! ```rust
//! use hsm_crypto_engine::threshold::{ThresholdConfig, FrostEngine, SigningParticipant, SigningCoordinator};
//!
//! # let config = ThresholdConfig::new(2, 3).unwrap();
//! # let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();
//! # let mut participants: Vec<_> = shares.into_iter().map(|s| SigningParticipant::new(s, group_key.clone())).collect();
//!
//! let message = b"Message to sign";
//!
//! // Round 1: each participant generates a commitment
//! let commitment1 = participants[0].start_signing(message.to_vec()).unwrap();
//! let commitment2 = participants[1].start_signing(message.to_vec()).unwrap();
//! let all_commitments = vec![commitment1, commitment2];
//!
//! // Round 2: each participant generates a signature share
//! let share1 = participants[0].sign(message, &all_commitments).unwrap();
//! let share2 = participants[1].sign(message, &all_commitments).unwrap();
//!
//! // Coordinator aggregates shares
//! let signature = FrostEngine::aggregate_signatures(
//!     message,
//!     &all_commitments,
//!     &[share1, share2],
//!     &group_key,
//! ).unwrap();
//!
//! // Verify (works with standard Ed25519 verification)
//! let valid = FrostEngine::verify(&group_key, message, &signature).unwrap();
//! assert!(valid);
//! ```
//!
//! # Protocol Rounds
//!
//! Threshold signing requires two communication rounds:
//!
//! 1. **Round 1 (Commitment)**: Each participant generates a random nonce and
//!    broadcasts a commitment to it. This prevents replay attacks.
//!
//! 2. **Round 2 (Signing)**: After receiving all commitments, each participant
//!    generates their signature share. Shares are collected and aggregated.
//!
//! # Security Considerations
//!
//! - **Nonce Reuse**: NEVER reuse nonces. Reusing a nonce allows key extraction.
//!   Each signing session must use fresh nonces.
//!
//! - **Commitment Verification**: All participants must use the same set of
//!   commitments. Mismatched commitments will cause aggregation to fail.
//!
//! - **Participant Verification**: Verify participant identities before accepting
//!   their contributions to prevent impersonation attacks.
//!
//! - **Message Verification**: Participants should verify the message content
//!   before signing to prevent signing unintended data.

pub mod coordinator;
pub mod dkg;
pub mod frost;
pub mod participant;
pub mod types;

// Re-export main types for convenience
pub use coordinator::{SessionId, SigningCoordinator, SigningSessionConfig, SigningState};
pub use dkg::{DistributedKeyGeneration, DkgRound1Package, DkgRound2Package};
pub use frost::FrostEngine;
pub use participant::SigningParticipant;
pub use types::{
    GroupPublicKey, KeyShare, ParticipantId, SignatureShare, SigningCommitment, SigningNonce,
    ThresholdConfig, ThresholdError, ThresholdSignature,
};
