//! Ethereum 2.0 Validator Support
//!
//! This module provides validator signing with anti-slashing protection for
//! Ethereum 2.0 beacon chain operations.
//!
//! # Supported Operations
//!
//! - Attestations (with Casper FFG slashing protection)
//! - Block proposals (with double-proposal protection)
//! - RANDAO reveals
//! - Voluntary exits
//! - Sync committee contributions
//! - Aggregation duties
//!
//! # Security
//!
//! All signing operations are protected by the anti-slashing database.
//! Protection **cannot be disabled**.

use crate::error::{Result, ValidatorError};
use crate::slashing_db::SlashingProtectionDb;
use crate::types::*;
use blst::min_pk::{PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Domain separation tag for Ethereum 2.0 BLS signatures.
pub const ETH2_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Attestation data for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationData {
    /// Slot number
    pub slot: Slot,
    /// Committee index
    pub index: CommitteeIndex,
    /// Beacon block root
    pub beacon_block_root: [u8; 32],
    /// Source checkpoint
    pub source: Checkpoint,
    /// Target checkpoint
    pub target: Checkpoint,
}

impl AttestationData {
    /// Compute the signing root for this attestation data.
    pub fn signing_root(&self, domain: &[u8; 32]) -> SigningRoot {
        // Hash tree root of attestation data
        let data_root = self.hash_tree_root();

        // Combine with domain for signing root
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&data_root);
        combined[32..64].copy_from_slice(domain);

        SigningRoot::new(Sha256::digest(combined).into())
    }

    /// Compute the hash tree root of this attestation data.
    fn hash_tree_root(&self) -> [u8; 32] {
        // Simplified SSZ hash tree root
        // In production, use a proper SSZ library
        let mut hasher = Sha256::new();
        hasher.update(self.slot.to_le_bytes());
        hasher.update(self.index.to_le_bytes());
        hasher.update(self.beacon_block_root);
        hasher.update(self.source.epoch.to_le_bytes());
        hasher.update(self.source.root);
        hasher.update(self.target.epoch.to_le_bytes());
        hasher.update(self.target.root);
        hasher.finalize().into()
    }
}

/// Checkpoint (for Casper FFG).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Epoch number
    pub epoch: Epoch,
    /// Block root
    pub root: [u8; 32],
}

/// Beacon block header for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    /// Slot number
    pub slot: Slot,
    /// Proposer index
    pub proposer_index: ValidatorIndex,
    /// Parent root
    pub parent_root: [u8; 32],
    /// State root
    pub state_root: [u8; 32],
    /// Body root
    pub body_root: [u8; 32],
}

impl BeaconBlockHeader {
    /// Compute the signing root for this block header.
    pub fn signing_root(&self, domain: &[u8; 32]) -> SigningRoot {
        let data_root = self.hash_tree_root();

        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&data_root);
        combined[32..64].copy_from_slice(domain);

        SigningRoot::new(Sha256::digest(combined).into())
    }

    fn hash_tree_root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.slot.to_le_bytes());
        hasher.update(self.proposer_index.to_le_bytes());
        hasher.update(self.parent_root);
        hasher.update(self.state_root);
        hasher.update(self.body_root);
        hasher.finalize().into()
    }
}

/// Voluntary exit for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoluntaryExit {
    /// Epoch when the exit was signed
    pub epoch: Epoch,
    /// Validator index
    pub validator_index: ValidatorIndex,
}

impl VoluntaryExit {
    /// Compute the signing root.
    pub fn signing_root(&self, domain: &[u8; 32]) -> SigningRoot {
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&self.epoch.to_le_bytes());
        data[8..16].copy_from_slice(&self.validator_index.to_le_bytes());
        let data_root: [u8; 32] = Sha256::digest(data).into();

        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&data_root);
        combined[32..64].copy_from_slice(domain);

        SigningRoot::new(Sha256::digest(combined).into())
    }
}

/// Sync committee message for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCommitteeMessage {
    /// Slot
    pub slot: Slot,
    /// Beacon block root
    pub beacon_block_root: [u8; 32],
}

impl SyncCommitteeMessage {
    /// Compute the signing root.
    pub fn signing_root(&self, domain: &[u8; 32]) -> SigningRoot {
        // For sync committee, we sign the block root directly with domain
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&self.beacon_block_root);
        combined[32..64].copy_from_slice(domain);

        SigningRoot::new(Sha256::digest(combined).into())
    }
}

/// An Ethereum 2.0 validator with anti-slashing protection.
///
/// This struct wraps a BLS signing key and enforces slashing protection
/// for all signing operations. **Protection cannot be disabled.**
pub struct EthereumValidator {
    /// The validator's public key
    public_key: BlsPublicKey,
    /// The validator's secret key (stored encrypted in the key manager)
    secret_key: SecretKey,
    /// Reference to the slashing protection database
    slashing_db: Arc<SlashingProtectionDb>,
    /// Fork information for computing domains
    fork_info: ForkInfo,
}

impl EthereumValidator {
    /// Create a new Ethereum validator.
    ///
    /// # Arguments
    ///
    /// * `secret_key_bytes` - The 32-byte BLS secret key
    /// * `slashing_db` - Reference to the slashing protection database
    /// * `fork_info` - Fork information for the network
    ///
    /// # Security
    ///
    /// The validator is automatically registered in the slashing database.
    pub fn new(
        secret_key_bytes: &[u8],
        slashing_db: Arc<SlashingProtectionDb>,
        fork_info: ForkInfo,
    ) -> Result<Self> {
        let secret_key = SecretKey::from_bytes(secret_key_bytes).map_err(|e| {
            ValidatorError::InvalidPublicKey {
                reason: format!("Invalid BLS secret key: {:?}", e),
            }
        })?;

        let public_key = secret_key.sk_to_pk();
        let public_key_bytes = public_key.compress().to_vec();

        // Register in slashing database if not already registered
        if !slashing_db.is_registered(&public_key_bytes)? {
            slashing_db.register_validator(&public_key_bytes)?;
            info!(
                validator = %hex::encode(&public_key_bytes[..8]),
                "Registered new Ethereum validator"
            );
        }

        Ok(Self {
            public_key: BlsPublicKey(public_key_bytes),
            secret_key,
            slashing_db,
            fork_info,
        })
    }

    /// Get the validator's public key.
    pub fn public_key(&self) -> &BlsPublicKey {
        &self.public_key
    }

    /// Sign an attestation with slashing protection.
    ///
    /// # Arguments
    ///
    /// * `attestation` - The attestation data to sign
    ///
    /// # Returns
    ///
    /// - `Ok(signature)` if the attestation is safe and signed
    /// - `Err(SlashingError)` if signing would cause slashing
    ///
    /// # Security
    ///
    /// This function **atomically** checks for slashable conditions and records
    /// the attestation before signing. If any slashing condition is detected,
    /// the attestation is NOT signed and an error is returned.
    pub fn sign_attestation(&self, attestation: &AttestationData) -> Result<Vec<u8>> {
        let domain = self.fork_info.compute_domain(DomainType::BeaconAttester);
        let signing_root = attestation.signing_root(&domain);

        // Check and record in slashing database BEFORE signing
        self.slashing_db
            .check_and_record_attestation(
                self.public_key.as_bytes(),
                attestation.source.epoch,
                attestation.target.epoch,
                &signing_root,
            )
            .map_err(ValidatorError::Slashing)?;

        // Safe to sign
        let signature = self.sign_root(&signing_root);

        debug!(
            validator = %hex::encode(&self.public_key.as_bytes()[..8]),
            source_epoch = attestation.source.epoch,
            target_epoch = attestation.target.epoch,
            "Signed attestation"
        );

        Ok(signature)
    }

    /// Sign a block proposal with slashing protection.
    ///
    /// # Arguments
    ///
    /// * `block` - The block header to sign
    ///
    /// # Returns
    ///
    /// - `Ok(signature)` if the block is safe and signed
    /// - `Err(SlashingError)` if signing would cause slashing
    pub fn sign_block(&self, block: &BeaconBlockHeader) -> Result<Vec<u8>> {
        let domain = self.fork_info.compute_domain(DomainType::BeaconProposer);
        let signing_root = block.signing_root(&domain);

        // Check and record in slashing database BEFORE signing
        self.slashing_db
            .check_and_record_block(self.public_key.as_bytes(), block.slot, &signing_root)
            .map_err(ValidatorError::Slashing)?;

        // Safe to sign
        let signature = self.sign_root(&signing_root);

        debug!(
            validator = %hex::encode(&self.public_key.as_bytes()[..8]),
            slot = block.slot,
            "Signed block proposal"
        );

        Ok(signature)
    }

    /// Sign a RANDAO reveal.
    ///
    /// RANDAO reveals don't have slashing conditions, but we still log them.
    pub fn sign_randao(&self, epoch: Epoch) -> Result<Vec<u8>> {
        let domain = self.fork_info.compute_domain(DomainType::Randao);

        // Sign the epoch directly
        let epoch_root: [u8; 32] = Sha256::digest(epoch.to_le_bytes()).into();
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&epoch_root);
        combined[32..64].copy_from_slice(&domain);
        let signing_root = SigningRoot::new(Sha256::digest(combined).into());

        let signature = self.sign_root(&signing_root);

        debug!(
            validator = %hex::encode(&self.public_key.as_bytes()[..8]),
            epoch,
            "Signed RANDAO reveal"
        );

        Ok(signature)
    }

    /// Sign a voluntary exit.
    ///
    /// Voluntary exits don't have slashing conditions, but we log them
    /// and may want to add additional safety checks in the future.
    pub fn sign_voluntary_exit(&self, exit: &VoluntaryExit) -> Result<Vec<u8>> {
        let domain = self.fork_info.compute_domain(DomainType::VoluntaryExit);
        let signing_root = exit.signing_root(&domain);

        let signature = self.sign_root(&signing_root);

        warn!(
            validator = %hex::encode(&self.public_key.as_bytes()[..8]),
            epoch = exit.epoch,
            "Signed voluntary exit - validator will exit"
        );

        Ok(signature)
    }

    /// Sign a sync committee message.
    ///
    /// Sync committee messages don't have slashing conditions.
    pub fn sign_sync_committee(&self, message: &SyncCommitteeMessage) -> Result<Vec<u8>> {
        let domain = self.fork_info.compute_domain(DomainType::SyncCommittee);
        let signing_root = message.signing_root(&domain);

        let signature = self.sign_root(&signing_root);

        debug!(
            validator = %hex::encode(&self.public_key.as_bytes()[..8]),
            slot = message.slot,
            "Signed sync committee message"
        );

        Ok(signature)
    }

    /// Sign an aggregation selection proof.
    pub fn sign_selection_proof(&self, slot: Slot) -> Result<Vec<u8>> {
        let domain = self.fork_info.compute_domain(DomainType::SelectionProof);

        let slot_root: [u8; 32] = Sha256::digest(slot.to_le_bytes()).into();
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&slot_root);
        combined[32..64].copy_from_slice(&domain);
        let signing_root = SigningRoot::new(Sha256::digest(combined).into());

        let signature = self.sign_root(&signing_root);

        debug!(
            validator = %hex::encode(&self.public_key.as_bytes()[..8]),
            slot,
            "Signed selection proof"
        );

        Ok(signature)
    }

    /// Sign a sync committee selection proof.
    pub fn sign_sync_committee_selection_proof(
        &self,
        slot: Slot,
        subcommittee_index: u64,
    ) -> Result<Vec<u8>> {
        let domain = self
            .fork_info
            .compute_domain(DomainType::SyncCommitteeSelectionProof);

        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&slot.to_le_bytes());
        data[8..16].copy_from_slice(&subcommittee_index.to_le_bytes());
        let data_root: [u8; 32] = Sha256::digest(data).into();

        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&data_root);
        combined[32..64].copy_from_slice(&domain);
        let signing_root = SigningRoot::new(Sha256::digest(combined).into());

        let signature = self.sign_root(&signing_root);

        debug!(
            validator = %hex::encode(&self.public_key.as_bytes()[..8]),
            slot,
            subcommittee_index,
            "Signed sync committee selection proof"
        );

        Ok(signature)
    }

    /// Get the validator's signing summary.
    pub fn summary(&self) -> Result<ValidatorSummary> {
        self.slashing_db
            .get_validator_summary(self.public_key.as_bytes())
    }

    /// Internal: Sign a signing root.
    fn sign_root(&self, signing_root: &SigningRoot) -> Vec<u8> {
        let signature = self.secret_key.sign(signing_root.as_bytes(), ETH2_DST, &[]);
        signature.compress().to_vec()
    }
}

/// Verify a BLS signature.
pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    let pk = PublicKey::from_bytes(public_key).map_err(|e| ValidatorError::InvalidPublicKey {
        reason: format!("Invalid BLS public key: {:?}", e),
    })?;

    let sig = Signature::from_bytes(signature).map_err(|e| ValidatorError::InvalidSignature {
        reason: format!("Invalid BLS signature: {:?}", e),
    })?;

    let result = sig.verify(true, message, ETH2_DST, &[], &pk, true);

    match result {
        BLST_ERROR::BLST_SUCCESS => Ok(true),
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SlashingError;

    fn create_test_validator() -> (EthereumValidator, Arc<SlashingProtectionDb>) {
        let db = Arc::new(SlashingProtectionDb::in_memory().unwrap());

        // Generate a random secret key
        let mut ikm = [0u8; 32];
        getrandom::fill(&mut ikm).unwrap();
        let secret_key = SecretKey::key_gen(&ikm, &[]).unwrap();

        let fork_info = ForkInfo::new([0x01, 0x00, 0x00, 0x00], [0; 32]);

        let validator =
            EthereumValidator::new(&secret_key.to_bytes(), db.clone(), fork_info).unwrap();

        (validator, db)
    }

    #[test]
    fn test_sign_attestation() {
        let (validator, _db) = create_test_validator();

        let attestation = AttestationData {
            slot: 100,
            index: 0,
            beacon_block_root: [0xab; 32],
            source: Checkpoint {
                epoch: 10,
                root: [0xcd; 32],
            },
            target: Checkpoint {
                epoch: 11,
                root: [0xef; 32],
            },
        };

        let signature = validator.sign_attestation(&attestation).unwrap();
        assert_eq!(signature.len(), 96);
    }

    #[test]
    fn test_attestation_double_vote_prevented() {
        let (validator, _db) = create_test_validator();

        let attestation1 = AttestationData {
            slot: 100,
            index: 0,
            beacon_block_root: [0xab; 32],
            source: Checkpoint {
                epoch: 10,
                root: [0xcd; 32],
            },
            target: Checkpoint {
                epoch: 11,
                root: [0xef; 32],
            },
        };

        let attestation2 = AttestationData {
            slot: 100,
            index: 0,
            beacon_block_root: [0x12; 32], // Different root
            source: Checkpoint {
                epoch: 10,
                root: [0xcd; 32],
            },
            target: Checkpoint {
                epoch: 11, // Same target epoch
                root: [0x34; 32],
            },
        };

        // First attestation succeeds
        validator.sign_attestation(&attestation1).unwrap();

        // Second attestation with same target epoch should fail
        let result = validator.sign_attestation(&attestation2);
        assert!(matches!(
            result,
            Err(ValidatorError::Slashing(SlashingError::DoubleVote { .. }))
        ));
    }

    #[test]
    fn test_attestation_surrounding_vote_prevented() {
        let (validator, _db) = create_test_validator();

        // First: sign attestation at (source: 10, target: 15)
        let attestation1 = AttestationData {
            slot: 100,
            index: 0,
            beacon_block_root: [0xab; 32],
            source: Checkpoint {
                epoch: 10,
                root: [0xcd; 32],
            },
            target: Checkpoint {
                epoch: 15,
                root: [0xef; 32],
            },
        };
        validator.sign_attestation(&attestation1).unwrap();

        // Second: try to sign surrounding attestation (source: 5, target: 20)
        let attestation2 = AttestationData {
            slot: 200,
            index: 0,
            beacon_block_root: [0x12; 32],
            source: Checkpoint {
                epoch: 5, // Less than 10
                root: [0x34; 32],
            },
            target: Checkpoint {
                epoch: 20, // Greater than 15
                root: [0x56; 32],
            },
        };

        let result = validator.sign_attestation(&attestation2);
        assert!(matches!(
            result,
            Err(ValidatorError::Slashing(
                SlashingError::SurroundingVote { .. }
            ))
        ));
    }

    #[test]
    fn test_sign_block() {
        let (validator, _db) = create_test_validator();

        let block = BeaconBlockHeader {
            slot: 100,
            proposer_index: 42,
            parent_root: [0xab; 32],
            state_root: [0xcd; 32],
            body_root: [0xef; 32],
        };

        let signature = validator.sign_block(&block).unwrap();
        assert_eq!(signature.len(), 96);
    }

    #[test]
    fn test_block_double_proposal_prevented() {
        let (validator, _db) = create_test_validator();

        let block1 = BeaconBlockHeader {
            slot: 100,
            proposer_index: 42,
            parent_root: [0xab; 32],
            state_root: [0xcd; 32],
            body_root: [0xef; 32],
        };

        let block2 = BeaconBlockHeader {
            slot: 100, // Same slot
            proposer_index: 42,
            parent_root: [0x12; 32], // Different content
            state_root: [0x34; 32],
            body_root: [0x56; 32],
        };

        // First block succeeds
        validator.sign_block(&block1).unwrap();

        // Second block at same slot should fail
        let result = validator.sign_block(&block2);
        assert!(matches!(
            result,
            Err(ValidatorError::Slashing(
                SlashingError::DoubleBlockProposal { .. }
            ))
        ));
    }

    #[test]
    fn test_sign_randao() {
        let (validator, _db) = create_test_validator();

        let signature = validator.sign_randao(100).unwrap();
        assert_eq!(signature.len(), 96);
    }

    #[test]
    fn test_sign_voluntary_exit() {
        let (validator, _db) = create_test_validator();

        let exit = VoluntaryExit {
            epoch: 100,
            validator_index: 42,
        };

        let signature = validator.sign_voluntary_exit(&exit).unwrap();
        assert_eq!(signature.len(), 96);
    }

    #[test]
    fn test_sign_sync_committee() {
        let (validator, _db) = create_test_validator();

        let message = SyncCommitteeMessage {
            slot: 100,
            beacon_block_root: [0xab; 32],
        };

        let signature = validator.sign_sync_committee(&message).unwrap();
        assert_eq!(signature.len(), 96);
    }

    #[test]
    fn test_idempotent_attestation() {
        let (validator, _db) = create_test_validator();

        let attestation = AttestationData {
            slot: 100,
            index: 0,
            beacon_block_root: [0xab; 32],
            source: Checkpoint {
                epoch: 10,
                root: [0xcd; 32],
            },
            target: Checkpoint {
                epoch: 11,
                root: [0xef; 32],
            },
        };

        // Sign twice with same data - should succeed both times
        let sig1 = validator.sign_attestation(&attestation).unwrap();
        let sig2 = validator.sign_attestation(&attestation).unwrap();

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_verify_signature() {
        let (validator, _db) = create_test_validator();

        let attestation = AttestationData {
            slot: 100,
            index: 0,
            beacon_block_root: [0xab; 32],
            source: Checkpoint {
                epoch: 10,
                root: [0xcd; 32],
            },
            target: Checkpoint {
                epoch: 11,
                root: [0xef; 32],
            },
        };

        let signature = validator.sign_attestation(&attestation).unwrap();

        // Compute the signing root the same way
        let fork_info = ForkInfo::new([0x01, 0x00, 0x00, 0x00], [0; 32]);
        let domain = fork_info.compute_domain(DomainType::BeaconAttester);
        let signing_root = attestation.signing_root(&domain);

        let valid = verify_signature(
            validator.public_key().as_bytes(),
            signing_root.as_bytes(),
            &signature,
        )
        .unwrap();

        assert!(valid);
    }
}
