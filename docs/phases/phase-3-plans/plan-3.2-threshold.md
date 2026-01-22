# Plan 3.2: Threshold Cryptography

## Overview

Implement threshold cryptography where a key is split among multiple parties, requiring a threshold (t-of-n) to perform operations. No single party ever holds the complete key, providing protection against key compromise.

## Goals

- Implement FROST (Flexible Round-Optimized Schnorr Threshold) for Ed25519
- Support t-of-n threshold signing (e.g., 2-of-3, 3-of-5)
- Distributed key generation (DKG) without trusted dealer
- Key resharing to change threshold or participants
- Coordinator-based and coordinator-free modes

## Dependencies

Add to `crates/crypto-engine/Cargo.toml`:

```toml
[dependencies]
frost-ed25519 = "2.0"      # FROST for Ed25519
frost-core = "2.0"         # Core FROST traits
rand_core = "0.6"          # RNG traits
```

## File Structure

```
crates/crypto-engine/src/
├── threshold/
│   ├── mod.rs              # Module exports
│   ├── frost.rs            # FROST implementation
│   ├── dkg.rs              # Distributed key generation
│   ├── coordinator.rs      # Signing coordinator
│   ├── participant.rs      # Signing participant
│   └── types.rs            # Shared types
├── lib.rs                  # Add: pub mod threshold;
└── ...

crates/threshold-service/   # NEW CRATE (optional)
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── server.rs           # Threshold signing server
    └── client.rs           # Client for threshold ops
```

## Implementation Steps

### Step 1: Create Threshold Module

Create `crates/crypto-engine/src/threshold/mod.rs`:

```rust
//! Threshold Cryptography module
//!
//! Implements threshold signature schemes where keys are split among
//! multiple parties, requiring t-of-n parties to sign.
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

pub mod frost;
pub mod dkg;
pub mod coordinator;
pub mod participant;
pub mod types;

pub use types::*;
pub use frost::FrostEngine;
pub use dkg::DistributedKeyGeneration;
pub use coordinator::SigningCoordinator;
pub use participant::SigningParticipant;
```

### Step 2: Define Types

Create `crates/crypto-engine/src/threshold/types.rs`:

```rust
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Identifier for a participant in the threshold scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub u16);

/// Configuration for a threshold scheme
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Minimum number of participants required to sign (t)
    pub threshold: u16,
    /// Total number of participants (n)
    pub total_participants: u16,
}

impl ThresholdConfig {
    pub fn new(threshold: u16, total_participants: u16) -> Result<Self, ThresholdError> {
        if threshold == 0 {
            return Err(ThresholdError::InvalidThreshold("threshold must be > 0".into()));
        }
        if threshold > total_participants {
            return Err(ThresholdError::InvalidThreshold(
                "threshold cannot exceed total participants".into(),
            ));
        }
        Ok(Self {
            threshold,
            total_participants,
        })
    }
}

/// A participant's secret key share
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyShare {
    pub participant_id: ParticipantId,
    #[zeroize(skip)]
    pub config: ThresholdConfig,
    pub(crate) secret_share: Vec<u8>,
    pub public_key_share: Vec<u8>,
}

/// The group's combined public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPublicKey {
    pub bytes: Vec<u8>,
    pub config: ThresholdConfig,
}

/// Commitment from a participant during signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningCommitment {
    pub participant_id: ParticipantId,
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
}

/// Nonce used during signing (must be kept secret)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningNonce {
    pub(crate) hiding: Vec<u8>,
    pub(crate) binding: Vec<u8>,
}

/// Signature share from a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureShare {
    pub participant_id: ParticipantId,
    pub share: Vec<u8>,
}

/// Complete threshold signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignature {
    pub bytes: Vec<u8>,
}

/// Threshold cryptography errors
#[derive(Debug, thiserror::Error)]
pub enum ThresholdError {
    #[error("Invalid threshold configuration: {0}")]
    InvalidThreshold(String),

    #[error("Not enough participants: need {required}, got {provided}")]
    InsufficientParticipants { required: u16, provided: u16 },

    #[error("Invalid participant: {0}")]
    InvalidParticipant(ParticipantId),

    #[error("DKG round {round} failed: {reason}")]
    DkgFailed { round: u8, reason: String },

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Invalid signature share from participant {0:?}")]
    InvalidSignatureShare(ParticipantId),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}
```

### Step 3: Implement FROST Engine

Create `crates/crypto-engine/src/threshold/frost.rs`:

```rust
//! FROST (Flexible Round-Optimized Schnorr Threshold) implementation

use frost_ed25519 as frost;
use rand_core::OsRng;

use super::types::*;
use crate::CryptoError;

/// FROST threshold signing engine
pub struct FrostEngine;

impl FrostEngine {
    /// Generate key shares using a trusted dealer (simpler but requires trust)
    ///
    /// Returns (group_public_key, key_shares)
    pub fn trusted_dealer_keygen(
        config: ThresholdConfig,
    ) -> Result<(GroupPublicKey, Vec<KeyShare>), ThresholdError> {
        let (shares, pubkey_package) = frost::keys::generate_with_dealer(
            config.total_participants,
            config.threshold,
            frost::keys::IdentifierList::Default,
            &mut OsRng,
        )
        .map_err(|e| ThresholdError::DkgFailed {
            round: 0,
            reason: e.to_string(),
        })?;

        let group_public_key = GroupPublicKey {
            bytes: pubkey_package.verifying_key().serialize().to_vec(),
            config,
        };

        let key_shares: Vec<KeyShare> = shares
            .into_iter()
            .enumerate()
            .map(|(i, (id, share))| {
                let id_bytes: [u8; 2] = id.serialize()[..2].try_into().unwrap_or([0, 0]);
                KeyShare {
                    participant_id: ParticipantId(u16::from_le_bytes(id_bytes)),
                    config,
                    secret_share: share.signing_share().serialize().to_vec(),
                    public_key_share: share.verifying_share().serialize().to_vec(),
                }
            })
            .collect();

        Ok((group_public_key, key_shares))
    }

    /// Generate signing nonces (call before each signing session)
    pub fn generate_nonces(
        key_share: &KeyShare,
    ) -> Result<(SigningNonce, SigningCommitment), ThresholdError> {
        // Reconstruct the secret share
        let signing_share = frost::keys::SigningShare::deserialize(&key_share.secret_share)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        let (nonces, commitments) =
            frost::round1::commit(&signing_share, &mut OsRng);

        Ok((
            SigningNonce {
                hiding: nonces.hiding().serialize().to_vec(),
                binding: nonces.binding().serialize().to_vec(),
            },
            SigningCommitment {
                participant_id: key_share.participant_id,
                hiding: commitments.hiding().serialize().to_vec(),
                binding: commitments.binding().serialize().to_vec(),
            },
        ))
    }

    /// Generate signature share (round 2 of signing)
    pub fn sign_share(
        key_share: &KeyShare,
        nonce: &SigningNonce,
        message: &[u8],
        commitments: &[SigningCommitment],
        group_public_key: &GroupPublicKey,
    ) -> Result<SignatureShare, ThresholdError> {
        // Reconstruct FROST types from our serialized forms
        let signing_share = frost::keys::SigningShare::deserialize(&key_share.secret_share)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // Build the signing package
        let signing_nonces = frost::round1::SigningNonces::new(
            frost::round1::Nonce::deserialize(&nonce.hiding)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?,
            frost::round1::Nonce::deserialize(&nonce.binding)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?,
        );

        // Convert commitments
        let commitment_map: frost::BTreeMap<_, _> = commitments
            .iter()
            .map(|c| {
                let id = frost::Identifier::try_from(c.participant_id.0)
                    .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;
                let hiding = frost::round1::NonceCommitment::deserialize(&c.hiding)
                    .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;
                let binding = frost::round1::NonceCommitment::deserialize(&c.binding)
                    .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;
                Ok((id, frost::round1::SigningCommitments::new(hiding, binding)))
            })
            .collect::<Result<_, ThresholdError>>()?;

        let signing_package = frost::SigningPackage::new(commitment_map, message);

        // Reconstruct key package
        let identifier = frost::Identifier::try_from(key_share.participant_id.0)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        let verifying_share =
            frost::keys::VerifyingShare::deserialize(&key_share.public_key_share)
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        let verifying_key = frost::VerifyingKey::deserialize(&group_public_key.bytes)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        let key_package = frost::keys::KeyPackage::new(
            identifier,
            signing_share,
            verifying_share,
            verifying_key,
            key_share.config.threshold,
        );

        // Generate signature share
        let sig_share = frost::round2::sign(&signing_package, &signing_nonces, &key_package)
            .map_err(|e| ThresholdError::SigningFailed(e.to_string()))?;

        Ok(SignatureShare {
            participant_id: key_share.participant_id,
            share: sig_share.serialize().to_vec(),
        })
    }

    /// Aggregate signature shares into final signature
    pub fn aggregate_signatures(
        message: &[u8],
        commitments: &[SigningCommitment],
        signature_shares: &[SignatureShare],
        group_public_key: &GroupPublicKey,
    ) -> Result<ThresholdSignature, ThresholdError> {
        // Convert commitments
        let commitment_map: frost::BTreeMap<_, _> = commitments
            .iter()
            .map(|c| {
                let id = frost::Identifier::try_from(c.participant_id.0)
                    .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;
                let hiding = frost::round1::NonceCommitment::deserialize(&c.hiding)
                    .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;
                let binding = frost::round1::NonceCommitment::deserialize(&c.binding)
                    .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;
                Ok((id, frost::round1::SigningCommitments::new(hiding, binding)))
            })
            .collect::<Result<_, ThresholdError>>()?;

        let signing_package = frost::SigningPackage::new(commitment_map, message);

        // Convert signature shares
        let share_map: frost::BTreeMap<_, _> = signature_shares
            .iter()
            .map(|s| {
                let id = frost::Identifier::try_from(s.participant_id.0)
                    .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;
                let share = frost::round2::SignatureShare::deserialize(&s.share)
                    .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;
                Ok((id, share))
            })
            .collect::<Result<_, ThresholdError>>()?;

        // Build public key package (simplified - in production, store full package)
        let verifying_key = frost::VerifyingKey::deserialize(&group_public_key.bytes)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        // For aggregation we need the full pubkey package
        // This is a simplification - real implementation needs full package
        let pubkey_package = todo!("Need to reconstruct PublicKeyPackage");

        // Aggregate
        let signature = frost::aggregate(&signing_package, &share_map, &pubkey_package)
            .map_err(|e| ThresholdError::SigningFailed(e.to_string()))?;

        Ok(ThresholdSignature {
            bytes: signature.serialize().to_vec(),
        })
    }

    /// Verify a threshold signature (same as regular Ed25519 verification)
    pub fn verify(
        group_public_key: &GroupPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        let verifying_key = frost::VerifyingKey::deserialize(&group_public_key.bytes)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        let sig = frost::Signature::deserialize(&signature.bytes)
            .map_err(|e| ThresholdError::SerializationError(e.to_string()))?;

        verifying_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(|_| ThresholdError::VerificationFailed)
    }
}
```

### Step 4: Implement DKG (Distributed Key Generation)

Create `crates/crypto-engine/src/threshold/dkg.rs`:

```rust
//! Distributed Key Generation (DKG)
//!
//! Allows participants to jointly generate a shared key without any
//! trusted dealer. Each participant generates their own contribution
//! and shares commitments with others.

use frost_ed25519 as frost;
use rand_core::OsRng;

use super::types::*;

/// State machine for DKG protocol
pub struct DistributedKeyGeneration {
    config: ThresholdConfig,
    participant_id: ParticipantId,
    round: DkgRound,
}

#[derive(Debug, Clone)]
pub enum DkgRound {
    NotStarted,
    Round1 { secret_package: Vec<u8> },
    Round2 { round1_packages: Vec<DkgRound1Package> },
    Complete { key_share: KeyShare, group_key: GroupPublicKey },
}

/// Round 1 output to share with other participants
#[derive(Debug, Clone)]
pub struct DkgRound1Package {
    pub participant_id: ParticipantId,
    pub commitment: Vec<u8>,
}

/// Round 2 output to share with specific participant
#[derive(Debug, Clone)]
pub struct DkgRound2Package {
    pub from: ParticipantId,
    pub to: ParticipantId,
    pub share: Vec<u8>, // Encrypted for recipient
}

impl DistributedKeyGeneration {
    /// Start DKG as a participant
    pub fn new(config: ThresholdConfig, participant_id: ParticipantId) -> Self {
        Self {
            config,
            participant_id,
            round: DkgRound::NotStarted,
        }
    }

    /// Execute round 1: generate secret polynomial and broadcast commitment
    pub fn round1(&mut self) -> Result<DkgRound1Package, ThresholdError> {
        let identifier = frost::Identifier::try_from(self.participant_id.0)
            .map_err(|e| ThresholdError::DkgFailed {
                round: 1,
                reason: e.to_string(),
            })?;

        let (secret_package, round1_package) = frost::keys::dkg::part1(
            identifier,
            self.config.total_participants,
            self.config.threshold,
            &mut OsRng,
        )
        .map_err(|e| ThresholdError::DkgFailed {
            round: 1,
            reason: e.to_string(),
        })?;

        // Serialize and store secret package
        let secret_bytes = todo!("Serialize secret package");

        self.round = DkgRound::Round1 {
            secret_package: secret_bytes,
        };

        Ok(DkgRound1Package {
            participant_id: self.participant_id,
            commitment: todo!("Serialize round1 package"),
        })
    }

    /// Execute round 2: process round 1 packages and generate shares for each participant
    pub fn round2(
        &mut self,
        round1_packages: Vec<DkgRound1Package>,
    ) -> Result<Vec<DkgRound2Package>, ThresholdError> {
        let DkgRound::Round1 { secret_package } = &self.round else {
            return Err(ThresholdError::DkgFailed {
                round: 2,
                reason: "Must complete round 1 first".into(),
            });
        };

        // Deserialize and process
        todo!("Implement round 2")
    }

    /// Finalize: process round 2 packages and derive final key share
    pub fn finalize(
        &mut self,
        round2_packages: Vec<DkgRound2Package>,
    ) -> Result<(KeyShare, GroupPublicKey), ThresholdError> {
        todo!("Implement finalization")
    }
}

/// Verify that all participants produced consistent round 1 packages
pub fn verify_round1_packages(packages: &[DkgRound1Package]) -> Result<(), ThresholdError> {
    // Verify commitments are consistent
    todo!("Implement verification")
}
```

### Step 5: Implement Signing Coordinator

Create `crates/crypto-engine/src/threshold/coordinator.rs`:

```rust
//! Signing Coordinator
//!
//! Coordinates the multi-round signing protocol among participants.
//! The coordinator does NOT learn the secret key or signature shares.

use super::types::*;
use std::collections::HashMap;

/// State of the signing session
#[derive(Debug, Clone)]
pub enum SigningState {
    CollectingCommitments {
        message: Vec<u8>,
        commitments: HashMap<ParticipantId, SigningCommitment>,
    },
    CollectingShares {
        message: Vec<u8>,
        commitments: Vec<SigningCommitment>,
        shares: HashMap<ParticipantId, SignatureShare>,
    },
    Complete {
        signature: ThresholdSignature,
    },
    Failed {
        reason: String,
    },
}

/// Coordinates a signing session
pub struct SigningCoordinator {
    config: ThresholdConfig,
    group_public_key: GroupPublicKey,
    state: SigningState,
    selected_participants: Vec<ParticipantId>,
}

impl SigningCoordinator {
    /// Start a new signing session
    pub fn new(
        config: ThresholdConfig,
        group_public_key: GroupPublicKey,
        message: Vec<u8>,
        participants: Vec<ParticipantId>,
    ) -> Result<Self, ThresholdError> {
        if participants.len() < config.threshold as usize {
            return Err(ThresholdError::InsufficientParticipants {
                required: config.threshold,
                provided: participants.len() as u16,
            });
        }

        Ok(Self {
            config,
            group_public_key,
            state: SigningState::CollectingCommitments {
                message,
                commitments: HashMap::new(),
            },
            selected_participants: participants,
        })
    }

    /// Get the message being signed
    pub fn message(&self) -> Option<&[u8]> {
        match &self.state {
            SigningState::CollectingCommitments { message, .. } => Some(message),
            SigningState::CollectingShares { message, .. } => Some(message),
            _ => None,
        }
    }

    /// Submit a commitment from a participant (round 1)
    pub fn submit_commitment(
        &mut self,
        commitment: SigningCommitment,
    ) -> Result<Option<Vec<SigningCommitment>>, ThresholdError> {
        let SigningState::CollectingCommitments {
            message,
            commitments,
        } = &mut self.state
        else {
            return Err(ThresholdError::SigningFailed(
                "Not in commitment collection phase".into(),
            ));
        };

        if !self.selected_participants.contains(&commitment.participant_id) {
            return Err(ThresholdError::InvalidParticipant(commitment.participant_id));
        }

        commitments.insert(commitment.participant_id, commitment);

        // Check if we have enough commitments
        if commitments.len() >= self.config.threshold as usize {
            let all_commitments: Vec<_> = commitments.values().cloned().collect();
            let message = message.clone();

            self.state = SigningState::CollectingShares {
                message,
                commitments: all_commitments.clone(),
                shares: HashMap::new(),
            };

            Ok(Some(all_commitments))
        } else {
            Ok(None)
        }
    }

    /// Submit a signature share from a participant (round 2)
    pub fn submit_share(
        &mut self,
        share: SignatureShare,
    ) -> Result<Option<ThresholdSignature>, ThresholdError> {
        let SigningState::CollectingShares {
            message,
            commitments,
            shares,
        } = &mut self.state
        else {
            return Err(ThresholdError::SigningFailed(
                "Not in share collection phase".into(),
            ));
        };

        if !self.selected_participants.contains(&share.participant_id) {
            return Err(ThresholdError::InvalidParticipant(share.participant_id));
        }

        shares.insert(share.participant_id, share);

        // Check if we have enough shares
        if shares.len() >= self.config.threshold as usize {
            let all_shares: Vec<_> = shares.values().cloned().collect();

            // Aggregate signatures
            let signature = super::frost::FrostEngine::aggregate_signatures(
                message,
                commitments,
                &all_shares,
                &self.group_public_key,
            )?;

            self.state = SigningState::Complete {
                signature: signature.clone(),
            };

            Ok(Some(signature))
        } else {
            Ok(None)
        }
    }

    /// Get current state
    pub fn state(&self) -> &SigningState {
        &self.state
    }

    /// Get how many more participants are needed
    pub fn participants_needed(&self) -> usize {
        match &self.state {
            SigningState::CollectingCommitments { commitments, .. } => {
                (self.config.threshold as usize).saturating_sub(commitments.len())
            }
            SigningState::CollectingShares { shares, .. } => {
                (self.config.threshold as usize).saturating_sub(shares.len())
            }
            _ => 0,
        }
    }
}
```

### Step 6: Implement Participant

Create `crates/crypto-engine/src/threshold/participant.rs`:

```rust
//! Signing Participant
//!
//! Represents a party holding a key share who can participate in signing.

use super::types::*;
use super::frost::FrostEngine;

/// A participant in the threshold scheme
pub struct SigningParticipant {
    key_share: KeyShare,
    group_public_key: GroupPublicKey,
    current_session: Option<ParticipantSession>,
}

struct ParticipantSession {
    message: Vec<u8>,
    nonce: SigningNonce,
    commitment: SigningCommitment,
}

impl SigningParticipant {
    /// Create a participant from a key share
    pub fn new(key_share: KeyShare, group_public_key: GroupPublicKey) -> Self {
        Self {
            key_share,
            group_public_key,
            current_session: None,
        }
    }

    /// Get participant ID
    pub fn id(&self) -> ParticipantId {
        self.key_share.participant_id
    }

    /// Get the group's public key
    pub fn group_public_key(&self) -> &GroupPublicKey {
        &self.group_public_key
    }

    /// Start a signing session (generates commitment)
    pub fn start_signing(&mut self, message: Vec<u8>) -> Result<SigningCommitment, ThresholdError> {
        let (nonce, commitment) = FrostEngine::generate_nonces(&self.key_share)?;

        self.current_session = Some(ParticipantSession {
            message,
            nonce,
            commitment: commitment.clone(),
        });

        Ok(commitment)
    }

    /// Generate signature share after receiving all commitments
    pub fn sign(
        &mut self,
        all_commitments: &[SigningCommitment],
    ) -> Result<SignatureShare, ThresholdError> {
        let session = self.current_session.as_ref().ok_or_else(|| {
            ThresholdError::SigningFailed("No active signing session".into())
        })?;

        let share = FrostEngine::sign_share(
            &self.key_share,
            &session.nonce,
            &session.message,
            all_commitments,
            &self.group_public_key,
        )?;

        // Clear session after signing
        self.current_session = None;

        Ok(share)
    }

    /// Abort current signing session
    pub fn abort_signing(&mut self) {
        self.current_session = None;
    }

    /// Check if participant has an active session
    pub fn has_active_session(&self) -> bool {
        self.current_session.is_some()
    }
}
```

### Step 7: Add gRPC Endpoints

Add to `proto/hsm.proto`:

```protobuf
// Threshold key generation
message GenerateThresholdKeyRequest {
    string key_id = 1;
    uint32 threshold = 2;      // t - minimum signers
    uint32 total_shares = 3;   // n - total participants
}

message GenerateThresholdKeyResponse {
    bytes group_public_key = 1;
    repeated KeyShareInfo shares = 2;
}

message KeyShareInfo {
    uint32 participant_id = 1;
    bytes encrypted_share = 2;  // Encrypted for participant
    bytes public_share = 3;
}

// Threshold signing (multi-round)
message StartThresholdSigningRequest {
    string key_id = 1;
    bytes message = 2;
    repeated uint32 participant_ids = 3;
}

message StartThresholdSigningResponse {
    string session_id = 1;
}

message SubmitCommitmentRequest {
    string session_id = 1;
    uint32 participant_id = 2;
    bytes commitment = 3;
}

message SubmitCommitmentResponse {
    bool all_commitments_received = 1;
    repeated bytes commitments = 2;  // Only set when all received
}

message SubmitSignatureShareRequest {
    string session_id = 1;
    uint32 participant_id = 2;
    bytes share = 3;
}

message SubmitSignatureShareResponse {
    bool complete = 1;
    bytes signature = 2;  // Only set when complete
}
```

## Testing Requirements

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_dealer_keygen() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        assert_eq!(shares.len(), 3);
        assert!(!group_key.bytes.is_empty());
    }

    #[test]
    fn test_threshold_signing_2_of_3() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        // Create participants
        let mut participants: Vec<_> = shares
            .into_iter()
            .map(|s| SigningParticipant::new(s, group_key.clone()))
            .collect();

        let message = b"test message";

        // Start signing with first 2 participants
        let commitments: Vec<_> = participants[..2]
            .iter_mut()
            .map(|p| p.start_signing(message.to_vec()).unwrap())
            .collect();

        // Generate signature shares
        let sig_shares: Vec<_> = participants[..2]
            .iter_mut()
            .map(|p| p.sign(&commitments).unwrap())
            .collect();

        // Aggregate
        let signature = FrostEngine::aggregate_signatures(
            message,
            &commitments,
            &sig_shares,
            &group_key,
        ).unwrap();

        // Verify
        let valid = FrostEngine::verify(&group_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_threshold_signing_insufficient_shares_fails() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

        // Try with only 1 participant (need 2)
        let mut participant = SigningParticipant::new(shares[0].clone(), group_key.clone());
        let commitment = participant.start_signing(b"test".to_vec()).unwrap();

        // Can't aggregate with only 1 share
        let sig_share = participant.sign(&[commitment.clone()]).unwrap();
        let result = FrostEngine::aggregate_signatures(
            b"test",
            &[commitment],
            &[sig_share],
            &group_key,
        );

        assert!(result.is_err());
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_distributed_threshold_signing() {
    // Simulate 3 separate participants communicating over channels
    // ...
}
```

## Success Metrics

- [ ] 2-of-3 threshold signing works correctly
- [ ] 3-of-5 threshold signing works correctly
- [ ] DKG produces valid key shares
- [ ] Threshold signatures verify as standard Ed25519
- [ ] Signing with fewer than t participants fails
- [ ] Key shares are zeroized on drop
- [ ] Signing coordinator handles participant dropout

## Security Considerations

- Nonces must be fresh for each signing session
- Reusing nonces allows key extraction
- Participants should verify they're signing the correct message
- DKG requires secure channels between participants
- Consider using a timeout for signing sessions
