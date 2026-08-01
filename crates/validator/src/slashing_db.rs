//! Slashing Protection Database
//!
//! This module implements a persistent database for tracking validator signing history
//! to prevent slashable offenses. The protection **cannot be disabled**.
//!
//! # Security Properties
//!
//! - **Atomic check-and-record**: Uses database transactions to prevent TOCTOU attacks
//! - **Persistent**: All data survives process restarts
//! - **Crash-safe**: Uses write-ahead logging
//! - **Cannot be bypassed**: No API to disable protection
//!
//! # Slashing Conditions Prevented
//!
//! ## Attestations (Casper FFG)
//! 1. **Double Vote**: Signing two attestations with the same target epoch
//! 2. **Surrounding Vote**: Signing an attestation that surrounds a previous one
//! 3. **Surrounded Vote**: Signing an attestation surrounded by a previous one
//!
//! ## Block Proposals
//! 1. **Double Block**: Proposing two different blocks at the same slot

use crate::error::{Result, SlashingError, SlashingResult, ValidatorError};
use crate::types::*;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sled::{Db, Tree};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Tree names in the database
const VALIDATORS_TREE: &str = "validators";
const ATTESTATIONS_TREE: &str = "attestations";
const BLOCKS_TREE: &str = "blocks";
const METADATA_TREE: &str = "metadata";

/// Slashing Protection Database.
///
/// This database tracks all validator signing operations to prevent slashable offenses.
/// Protection is **always on** and **cannot be disabled**.
///
/// # Thread Safety
///
/// The database is safe for concurrent access from multiple threads. Each validator
/// has its own lock to allow parallel operations across different validators while
/// ensuring serialized access to the same validator.
pub struct SlashingProtectionDb {
    /// The underlying database
    db: Db,
    /// Validators tree
    validators: Tree,
    /// Attestations tree (keyed by validator pubkey)
    attestations: Tree,
    /// Blocks tree (keyed by validator pubkey)
    blocks: Tree,
    /// Metadata tree (reserved for future use)
    #[allow(dead_code)]
    metadata: Tree,
    /// Per-validator locks for atomic check-and-sign
    validator_locks: Arc<dashmap::DashMap<Vec<u8>, Arc<RwLock<()>>>>,
    /// Statistics
    stats: Arc<RwLock<SlashingStats>>,
}

/// Internal representation of a validator in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidatorData {
    /// Public key
    public_key: Vec<u8>,
    /// Status
    status: ValidatorStatus,
    /// Minimum source epoch seen
    min_source_epoch: Option<Epoch>,
    /// Minimum target epoch seen
    min_target_epoch: Option<Epoch>,
    /// Minimum slot seen
    min_slot: Option<Slot>,
    /// Created timestamp
    created_at: chrono::DateTime<chrono::Utc>,
    /// Last updated timestamp
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// Internal representation of an attestation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttestationData {
    source_epoch: Epoch,
    target_epoch: Epoch,
    signing_root: [u8; 32],
    signed_at: chrono::DateTime<chrono::Utc>,
}

/// Internal representation of a block record.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockData {
    slot: Slot,
    signing_root: [u8; 32],
    signed_at: chrono::DateTime<chrono::Utc>,
}

impl SlashingProtectionDb {
    /// Open or create a slashing protection database.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the database directory
    ///
    /// # Security
    ///
    /// The database directory should be on a persistent, reliable storage medium.
    /// Data loss could result in slashing if the validator signs conflicting messages.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        // SECURITY: Disable sled's periodic background flush (default 500ms). Slashing
        // protection requires that a signing record is durable on disk *before* the
        // signature is produced. We therefore flush explicitly inside the
        // check-and-record functions while still holding the per-validator write lock.
        // Relying on the background flush would leave a window in which a crash after
        // signing but before fsync allows the record to be lost, enabling a double-sign.
        let db = sled::Config::new()
            .path(path.as_ref())
            .flush_every_ms(None)
            .open()?;

        let validators = db.open_tree(VALIDATORS_TREE)?;
        let attestations = db.open_tree(ATTESTATIONS_TREE)?;
        let blocks = db.open_tree(BLOCKS_TREE)?;
        let metadata = db.open_tree(METADATA_TREE)?;

        info!("Opened slashing protection database at {:?}", path.as_ref());

        Ok(Self {
            db,
            validators,
            attestations,
            blocks,
            metadata,
            validator_locks: Arc::new(dashmap::DashMap::new()),
            stats: Arc::new(RwLock::new(SlashingStats::default())),
        })
    }

    /// Create an in-memory database (for testing and benchmarking only).
    #[cfg(any(test, feature = "test-util"))]
    pub fn in_memory() -> Result<Self> {
        let db = sled::Config::new()
            .temporary(true)
            .flush_every_ms(None)
            .open()?;

        let validators = db.open_tree(VALIDATORS_TREE)?;
        let attestations = db.open_tree(ATTESTATIONS_TREE)?;
        let blocks = db.open_tree(BLOCKS_TREE)?;
        let metadata = db.open_tree(METADATA_TREE)?;

        Ok(Self {
            db,
            validators,
            attestations,
            blocks,
            metadata,
            validator_locks: Arc::new(dashmap::DashMap::new()),
            stats: Arc::new(RwLock::new(SlashingStats::default())),
        })
    }

    /// Register a new validator.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The validator's BLS public key (48 bytes)
    ///
    /// # Returns
    ///
    /// Error if the validator already exists.
    pub fn register_validator(&self, public_key: &[u8]) -> Result<()> {
        if public_key.len() != 48 {
            return Err(ValidatorError::InvalidPublicKey {
                reason: format!("Expected 48 bytes, got {}", public_key.len()),
            });
        }

        if self.validators.contains_key(public_key)? {
            return Err(ValidatorError::ValidatorAlreadyExists {
                public_key: hex::encode(public_key),
            });
        }

        let now = chrono::Utc::now();
        let data = ValidatorData {
            public_key: public_key.to_vec(),
            status: ValidatorStatus::Active,
            min_source_epoch: None,
            min_target_epoch: None,
            min_slot: None,
            created_at: now,
            updated_at: now,
        };

        let encoded = serde_json::to_vec(&data)?;
        self.validators.insert(public_key, encoded)?;

        // Ensure lock exists
        self.validator_locks
            .entry(public_key.to_vec())
            .or_insert_with(|| Arc::new(RwLock::new(())));

        info!(
            validator = %hex::encode(&public_key[..8]),
            "Registered new validator"
        );

        Ok(())
    }

    /// Check if a validator is registered.
    pub fn is_registered(&self, public_key: &[u8]) -> Result<bool> {
        Ok(self.validators.contains_key(public_key)?)
    }

    /// Get validator summary.
    pub fn get_validator_summary(&self, public_key: &[u8]) -> Result<ValidatorSummary> {
        let data = self.get_validator_data(public_key)?;

        // Count attestations and blocks
        let attestation_prefix = self.attestation_key_prefix(public_key);
        let attestation_count = self.attestations.scan_prefix(&attestation_prefix).count() as u64;

        let block_prefix = self.block_key_prefix(public_key);
        let block_count = self.blocks.scan_prefix(&block_prefix).count() as u64;

        Ok(ValidatorSummary {
            public_key: BlsPublicKey(data.public_key),
            status: data.status,
            min_source_epoch: data.min_source_epoch,
            min_target_epoch: data.min_target_epoch,
            min_slot: data.min_slot,
            attestation_count,
            block_count,
            last_activity: Some(data.updated_at),
        })
    }

    /// Get the lock for a validator.
    fn get_validator_lock(&self, public_key: &[u8]) -> Arc<RwLock<()>> {
        self.validator_locks
            .entry(public_key.to_vec())
            .or_insert_with(|| Arc::new(RwLock::new(())))
            .clone()
    }

    /// Get validator data from the database.
    fn get_validator_data(&self, public_key: &[u8]) -> Result<ValidatorData> {
        let encoded =
            self.validators
                .get(public_key)?
                .ok_or_else(|| ValidatorError::ValidatorNotFound {
                    public_key: hex::encode(public_key),
                })?;

        let data: ValidatorData = serde_json::from_slice(&encoded)?;
        Ok(data)
    }

    /// Update validator data in the database.
    fn update_validator_data(&self, data: &ValidatorData) -> Result<()> {
        let encoded = serde_json::to_vec(data)?;
        self.validators.insert(&data.public_key, encoded)?;
        Ok(())
    }

    /// Create the key prefix for attestations.
    fn attestation_key_prefix(&self, public_key: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(public_key.len() + 1);
        key.extend_from_slice(public_key);
        key.push(b':');
        key
    }

    /// Create the full key for an attestation.
    fn attestation_key(&self, public_key: &[u8], target_epoch: Epoch) -> Vec<u8> {
        let mut key = self.attestation_key_prefix(public_key);
        key.extend_from_slice(&target_epoch.to_be_bytes());
        key
    }

    /// Create the key prefix for blocks.
    fn block_key_prefix(&self, public_key: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(public_key.len() + 1);
        key.extend_from_slice(public_key);
        key.push(b':');
        key
    }

    /// Create the full key for a block.
    fn block_key(&self, public_key: &[u8], slot: Slot) -> Vec<u8> {
        let mut key = self.block_key_prefix(public_key);
        key.extend_from_slice(&slot.to_be_bytes());
        key
    }

    /// Check if an attestation would be slashable and record it atomically.
    ///
    /// This is the **core anti-slashing function** for attestations. It performs
    /// an atomic check-and-record operation that:
    ///
    /// 1. Checks for double voting (same target epoch, different signing root)
    /// 2. Checks for surrounding votes
    /// 3. Checks for surrounded votes
    /// 4. Records the attestation if safe
    ///
    /// # Arguments
    ///
    /// * `public_key` - The validator's public key
    /// * `source_epoch` - The source (justified) epoch
    /// * `target_epoch` - The target epoch
    /// * `signing_root` - The signing root of the attestation data
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the attestation is safe and has been recorded
    /// - `Err(SlashingError)` if signing would cause slashing
    ///
    /// # Security
    ///
    /// This function holds a lock for the validator for the duration of the operation
    /// to prevent TOCTOU race conditions.
    pub fn check_and_record_attestation(
        &self,
        public_key: &[u8],
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root: &SigningRoot,
    ) -> SlashingResult<()> {
        // Acquire exclusive lock for this validator
        let lock = self.get_validator_lock(public_key);
        let _guard = lock.write();

        // Get validator data
        let mut validator_data =
            self.get_validator_data(public_key)
                .map_err(|_| SlashingError::SourceEpochTooLow {
                    source_epoch,
                    min_source_epoch: 0,
                })?;

        // Check 3 (done first): Double vote / idempotent repeat.
        //
        // We look up any existing attestation at this exact target epoch BEFORE the
        // min-epoch checks. This implements the EIP-3076 "identical repeat" exception:
        // re-signing the exact same attestation (same signing root) at the minimum
        // target epoch must be allowed even though `target == min_target` would
        // otherwise be refused by the `<=` boundary check below.
        //
        // SECURITY (fail closed): a sled read error MUST NOT silently fall through to
        // record-and-sign. Any Err here aborts signing with DatabaseError.
        let attestation_key = self.attestation_key(public_key, target_epoch);
        match self.attestations.get(&attestation_key) {
            Ok(Some(existing)) => {
                let existing_data: AttestationData =
                    serde_json::from_slice(&existing).map_err(|_| SlashingError::DoubleVote {
                        target_epoch,
                        existing_root: "unknown".to_string(),
                        attempted_root: signing_root.to_hex(),
                    })?;

                if existing_data.signing_root != *signing_root.as_bytes() {
                    error!(
                        validator = %hex::encode(&public_key[..8]),
                        target_epoch,
                        existing_root = %hex::encode(&existing_data.signing_root[..8]),
                        attempted_root = %hex::encode(&signing_root.as_bytes()[..8]),
                        "DOUBLE VOTE PREVENTED"
                    );
                    self.stats.write().slashable_prevented += 1;
                    self.stats.write().double_votes_prevented += 1;
                    return Err(SlashingError::DoubleVote {
                        target_epoch,
                        existing_root: hex::encode(existing_data.signing_root),
                        attempted_root: signing_root.to_hex(),
                    });
                }

                // Same signing root is fine (idempotent repeat) - already durable.
                debug!(
                    validator = %hex::encode(&public_key[..8]),
                    target_epoch,
                    "Attestation already recorded with same signing root"
                );
                return Ok(());
            }
            Ok(None) => {}
            Err(e) => {
                error!(
                    validator = %hex::encode(&public_key[..8]),
                    target_epoch,
                    error = %e,
                    "Slashing DB read error during double-vote check - refusing to sign (fail closed)"
                );
                self.stats.write().slashable_prevented += 1;
                return Err(SlashingError::DatabaseError(format!(
                    "Failed to read attestation record: {e}"
                )));
            }
        }

        // Check 1: Source epoch must be >= min_source_epoch.
        //
        // EIP-3076 uses a strict `<` here (NOT `<=`): the FFG source is the last
        // justified checkpoint and legitimately repeats across many attestations
        // within and across epochs, so re-using the minimum source epoch is allowed.
        // Only the *target* epoch boundary (Check 2) uses `<=`.
        if let Some(min_source) = validator_data.min_source_epoch {
            if source_epoch < min_source {
                warn!(
                    validator = %hex::encode(&public_key[..8]),
                    source_epoch,
                    min_source_epoch = min_source,
                    "Attestation source epoch too low"
                );
                self.stats.write().slashable_prevented += 1;
                return Err(SlashingError::SourceEpochTooLow {
                    source_epoch,
                    min_source_epoch: min_source,
                });
            }
        }

        // Check 2: Target epoch must be > min_target_epoch (EIP-3076 boundary: refuse <=).
        // The identical-repeat exception (target == min_target with the same signing
        // root) was already handled by the double-vote check above.
        if let Some(min_target) = validator_data.min_target_epoch {
            if target_epoch <= min_target {
                warn!(
                    validator = %hex::encode(&public_key[..8]),
                    target_epoch,
                    min_target_epoch = min_target,
                    "Attestation target epoch too low"
                );
                self.stats.write().slashable_prevented += 1;
                return Err(SlashingError::TargetEpochTooLow {
                    target_epoch,
                    min_target_epoch: min_target,
                });
            }
        }

        // Check 4 & 5: Surrounding and surrounded votes
        // We need to check all existing attestations for this validator
        let prefix = self.attestation_key_prefix(public_key);
        for item in self.attestations.scan_prefix(&prefix) {
            let (_, value) = item.map_err(|_| SlashingError::SurroundingVote {
                new_source: source_epoch,
                new_target: target_epoch,
                existing_source: 0,
                existing_target: 0,
            })?;

            let existing: AttestationData =
                serde_json::from_slice(&value).map_err(|_| SlashingError::SurroundingVote {
                    new_source: source_epoch,
                    new_target: target_epoch,
                    existing_source: 0,
                    existing_target: 0,
                })?;

            // Surrounding vote: new.source < existing.source AND new.target > existing.target
            if source_epoch < existing.source_epoch && target_epoch > existing.target_epoch {
                error!(
                    validator = %hex::encode(&public_key[..8]),
                    new_source = source_epoch,
                    new_target = target_epoch,
                    existing_source = existing.source_epoch,
                    existing_target = existing.target_epoch,
                    "SURROUNDING VOTE PREVENTED"
                );
                self.stats.write().slashable_prevented += 1;
                self.stats.write().surrounding_votes_prevented += 1;
                return Err(SlashingError::SurroundingVote {
                    new_source: source_epoch,
                    new_target: target_epoch,
                    existing_source: existing.source_epoch,
                    existing_target: existing.target_epoch,
                });
            }

            // Surrounded vote: new.source > existing.source AND new.target < existing.target
            if source_epoch > existing.source_epoch && target_epoch < existing.target_epoch {
                error!(
                    validator = %hex::encode(&public_key[..8]),
                    new_source = source_epoch,
                    new_target = target_epoch,
                    existing_source = existing.source_epoch,
                    existing_target = existing.target_epoch,
                    "SURROUNDED VOTE PREVENTED"
                );
                self.stats.write().slashable_prevented += 1;
                self.stats.write().surrounded_votes_prevented += 1;
                return Err(SlashingError::SurroundedVote {
                    new_source: source_epoch,
                    new_target: target_epoch,
                    existing_source: existing.source_epoch,
                    existing_target: existing.target_epoch,
                });
            }
        }

        // All checks passed - record the attestation
        let now = chrono::Utc::now();
        let attestation_data = AttestationData {
            source_epoch,
            target_epoch,
            signing_root: *signing_root.as_bytes(),
            signed_at: now,
        };

        let encoded =
            serde_json::to_vec(&attestation_data).map_err(|_| SlashingError::DoubleVote {
                target_epoch,
                existing_root: "serialization error".to_string(),
                attempted_root: signing_root.to_hex(),
            })?;

        self.attestations
            .insert(&attestation_key, encoded)
            .map_err(|_| SlashingError::DoubleVote {
                target_epoch,
                existing_root: "database error".to_string(),
                attempted_root: signing_root.to_hex(),
            })?;

        // Update validator last activity timestamp
        // Note: min epochs are NOT automatically updated here - they should only
        // be set via EIP-3076 import to prevent blocking surrounding vote detection
        validator_data.updated_at = now;
        self.update_validator_data(&validator_data).map_err(|e| {
            SlashingError::DatabaseError(format!("Failed to persist validator data: {}", e))
        })?;

        // SECURITY (durability before signing): the attestation record MUST be durable
        // on disk before the caller produces a signature. We flush WHILE STILL HOLDING
        // the per-validator write lock and only return Ok once fsync succeeds. If the
        // flush fails we report DatabaseError and the caller must NOT sign. Without this,
        // a crash in sled's background-flush window would lose the record and permit a
        // double-vote on restart.
        self.db.flush().map_err(|e| {
            error!(
                validator = %hex::encode(&public_key[..8]),
                target_epoch,
                error = %e,
                "Failed to flush attestation record to disk - refusing to sign"
            );
            SlashingError::DatabaseError(format!("Failed to flush attestation record: {e}"))
        })?;

        // Update stats
        self.stats.write().attestations_signed += 1;

        debug!(
            validator = %hex::encode(&public_key[..8]),
            source_epoch,
            target_epoch,
            "Attestation recorded successfully"
        );

        Ok(())
    }

    /// Check if a block proposal would be slashable and record it atomically.
    ///
    /// This is the **core anti-slashing function** for block proposals. It performs
    /// an atomic check-and-record operation that:
    ///
    /// 1. Checks for double block proposals (same slot, different signing root)
    /// 2. Records the block if safe
    ///
    /// # Arguments
    ///
    /// * `public_key` - The validator's public key
    /// * `slot` - The slot of the block
    /// * `signing_root` - The signing root of the block
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the block is safe and has been recorded
    /// - `Err(SlashingError)` if signing would cause slashing
    pub fn check_and_record_block(
        &self,
        public_key: &[u8],
        slot: Slot,
        signing_root: &SigningRoot,
    ) -> SlashingResult<()> {
        // Acquire exclusive lock for this validator
        let lock = self.get_validator_lock(public_key);
        let _guard = lock.write();

        // Get validator data
        let mut validator_data = self
            .get_validator_data(public_key)
            .map_err(|_| SlashingError::SlotTooLow { slot, min_slot: 0 })?;

        // Check 2 (done first): Double block proposal / idempotent repeat.
        //
        // Looked up before the min-slot check so that re-proposing the exact same block
        // (same signing root) at the minimum slot is allowed (EIP-3076 identical-repeat
        // exception), even though `slot == min_slot` is otherwise refused below.
        //
        // SECURITY (fail closed): a sled read error MUST NOT silently fall through to
        // record-and-sign. Any Err here aborts signing with DatabaseError.
        let block_key = self.block_key(public_key, slot);
        match self.blocks.get(&block_key) {
            Ok(Some(existing)) => {
                let existing_data: BlockData = serde_json::from_slice(&existing).map_err(|_| {
                    SlashingError::DoubleBlockProposal {
                        slot,
                        existing_root: "unknown".to_string(),
                        attempted_root: signing_root.to_hex(),
                    }
                })?;

                if existing_data.signing_root != *signing_root.as_bytes() {
                    error!(
                        validator = %hex::encode(&public_key[..8]),
                        slot,
                        existing_root = %hex::encode(&existing_data.signing_root[..8]),
                        attempted_root = %hex::encode(&signing_root.as_bytes()[..8]),
                        "DOUBLE BLOCK PROPOSAL PREVENTED"
                    );
                    self.stats.write().slashable_prevented += 1;
                    self.stats.write().double_blocks_prevented += 1;
                    return Err(SlashingError::DoubleBlockProposal {
                        slot,
                        existing_root: hex::encode(existing_data.signing_root),
                        attempted_root: signing_root.to_hex(),
                    });
                }

                // Same signing root is fine (idempotent repeat) - already durable.
                debug!(
                    validator = %hex::encode(&public_key[..8]),
                    slot,
                    "Block already recorded with same signing root"
                );
                return Ok(());
            }
            Ok(None) => {}
            Err(e) => {
                error!(
                    validator = %hex::encode(&public_key[..8]),
                    slot,
                    error = %e,
                    "Slashing DB read error during double-proposal check - refusing to sign (fail closed)"
                );
                self.stats.write().slashable_prevented += 1;
                return Err(SlashingError::DatabaseError(format!(
                    "Failed to read block record: {e}"
                )));
            }
        }

        // Check 1: Slot must be > min_slot (EIP-3076 boundary: refuse <=). The
        // identical-repeat exception (slot == min_slot with the same signing root)
        // was already handled by the double-proposal check above.
        if let Some(min_slot) = validator_data.min_slot {
            if slot <= min_slot {
                warn!(
                    validator = %hex::encode(&public_key[..8]),
                    slot,
                    min_slot,
                    "Block slot too low"
                );
                self.stats.write().slashable_prevented += 1;
                return Err(SlashingError::SlotTooLow { slot, min_slot });
            }
        }

        // All checks passed - record the block
        let now = chrono::Utc::now();
        let block_data = BlockData {
            slot,
            signing_root: *signing_root.as_bytes(),
            signed_at: now,
        };

        let encoded =
            serde_json::to_vec(&block_data).map_err(|_| SlashingError::DoubleBlockProposal {
                slot,
                existing_root: "serialization error".to_string(),
                attempted_root: signing_root.to_hex(),
            })?;

        self.blocks.insert(&block_key, encoded).map_err(|_| {
            SlashingError::DoubleBlockProposal {
                slot,
                existing_root: "database error".to_string(),
                attempted_root: signing_root.to_hex(),
            }
        })?;

        // Update validator last activity timestamp
        // Note: min_slot is NOT automatically updated here - it should only
        // be set via EIP-3076 import
        validator_data.updated_at = now;
        self.update_validator_data(&validator_data).map_err(|e| {
            SlashingError::DatabaseError(format!("Failed to persist validator data: {}", e))
        })?;

        // SECURITY (durability before signing): the block record MUST be durable on disk
        // before the caller produces a signature. We flush WHILE STILL HOLDING the
        // per-validator write lock and only return Ok once fsync succeeds. If the flush
        // fails we report DatabaseError and the caller must NOT sign.
        self.db.flush().map_err(|e| {
            error!(
                validator = %hex::encode(&public_key[..8]),
                slot,
                error = %e,
                "Failed to flush block record to disk - refusing to sign"
            );
            SlashingError::DatabaseError(format!("Failed to flush block record: {e}"))
        })?;

        // Update stats
        self.stats.write().blocks_signed += 1;

        debug!(
            validator = %hex::encode(&public_key[..8]),
            slot,
            "Block recorded successfully"
        );

        Ok(())
    }

    /// Get all attestation records for a validator.
    pub fn get_attestation_records(&self, public_key: &[u8]) -> Result<Vec<AttestationRecord>> {
        let prefix = self.attestation_key_prefix(public_key);
        let mut records = Vec::new();

        for item in self.attestations.scan_prefix(&prefix) {
            let (_, value) = item?;
            let data: AttestationData = serde_json::from_slice(&value)?;
            records.push(AttestationRecord {
                source_epoch: data.source_epoch,
                target_epoch: data.target_epoch,
                signing_root: SigningRoot::new(data.signing_root),
                signed_at: data.signed_at,
            });
        }

        Ok(records)
    }

    /// Get all block records for a validator.
    pub fn get_block_records(&self, public_key: &[u8]) -> Result<Vec<BlockRecord>> {
        let prefix = self.block_key_prefix(public_key);
        let mut records = Vec::new();

        for item in self.blocks.scan_prefix(&prefix) {
            let (_, value) = item?;
            let data: BlockData = serde_json::from_slice(&value)?;
            records.push(BlockRecord {
                slot: data.slot,
                signing_root: SigningRoot::new(data.signing_root),
                signed_at: data.signed_at,
            });
        }

        Ok(records)
    }

    /// Set minimum source epoch for a validator (for EIP-3076 import).
    pub fn set_min_source_epoch(&self, public_key: &[u8], epoch: Epoch) -> Result<()> {
        let lock = self.get_validator_lock(public_key);
        let _guard = lock.write();

        let mut data = self.get_validator_data(public_key)?;
        data.min_source_epoch = Some(epoch);
        data.updated_at = chrono::Utc::now();
        self.update_validator_data(&data)?;

        Ok(())
    }

    /// Set minimum target epoch for a validator (for EIP-3076 import).
    pub fn set_min_target_epoch(&self, public_key: &[u8], epoch: Epoch) -> Result<()> {
        let lock = self.get_validator_lock(public_key);
        let _guard = lock.write();

        let mut data = self.get_validator_data(public_key)?;
        data.min_target_epoch = Some(epoch);
        data.updated_at = chrono::Utc::now();
        self.update_validator_data(&data)?;

        Ok(())
    }

    /// Set minimum slot for a validator (for EIP-3076 import).
    pub fn set_min_slot(&self, public_key: &[u8], slot: Slot) -> Result<()> {
        let lock = self.get_validator_lock(public_key);
        let _guard = lock.write();

        let mut data = self.get_validator_data(public_key)?;
        data.min_slot = Some(slot);
        data.updated_at = chrono::Utc::now();
        self.update_validator_data(&data)?;

        Ok(())
    }

    /// Get statistics.
    pub fn stats(&self) -> SlashingStats {
        self.stats.read().clone()
    }

    /// List all registered validators.
    pub fn list_validators(&self) -> Result<Vec<BlsPublicKey>> {
        let mut validators = Vec::new();

        for item in self.validators.iter() {
            let (key, _) = item?;
            validators.push(BlsPublicKey(key.to_vec()));
        }

        Ok(validators)
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_root() -> SigningRoot {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).unwrap();
        SigningRoot::new(bytes)
    }

    fn random_pubkey() -> Vec<u8> {
        let mut bytes = vec![0u8; 48];
        getrandom::fill(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn test_register_validator() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();

        db.register_validator(&pubkey).unwrap();
        assert!(db.is_registered(&pubkey).unwrap());

        // Registering again should fail
        let result = db.register_validator(&pubkey);
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_double_vote_prevention() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        let source = 10;
        let target = 20;
        let root1 = random_root();
        let root2 = random_root();

        // First attestation should succeed
        db.check_and_record_attestation(&pubkey, source, target, &root1)
            .unwrap();

        // Same attestation (idempotent) should succeed
        db.check_and_record_attestation(&pubkey, source, target, &root1)
            .unwrap();

        // Different root at same target should fail (double vote)
        let result = db.check_and_record_attestation(&pubkey, source, target, &root2);
        assert!(matches!(result, Err(SlashingError::DoubleVote { .. })));
    }

    #[test]
    fn test_attestation_surrounding_vote_prevention() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        // Record attestation at (source: 10, target: 15)
        let root1 = random_root();
        db.check_and_record_attestation(&pubkey, 10, 15, &root1)
            .unwrap();

        // Attempt surrounding vote at (source: 5, target: 20) should fail
        let root2 = random_root();
        let result = db.check_and_record_attestation(&pubkey, 5, 20, &root2);
        assert!(matches!(result, Err(SlashingError::SurroundingVote { .. })));
    }

    #[test]
    fn test_attestation_surrounded_vote_prevention() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        // Record attestation at (source: 5, target: 20)
        let root1 = random_root();
        db.check_and_record_attestation(&pubkey, 5, 20, &root1)
            .unwrap();

        // Attempt surrounded vote at (source: 10, target: 15) should fail
        let root2 = random_root();
        let result = db.check_and_record_attestation(&pubkey, 10, 15, &root2);
        assert!(matches!(result, Err(SlashingError::SurroundedVote { .. })));
    }

    #[test]
    fn test_block_double_proposal_prevention() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        let slot = 100;
        let root1 = random_root();
        let root2 = random_root();

        // First block should succeed
        db.check_and_record_block(&pubkey, slot, &root1).unwrap();

        // Same block (idempotent) should succeed
        db.check_and_record_block(&pubkey, slot, &root1).unwrap();

        // Different root at same slot should fail
        let result = db.check_and_record_block(&pubkey, slot, &root2);
        assert!(matches!(
            result,
            Err(SlashingError::DoubleBlockProposal { .. })
        ));
    }

    #[test]
    fn test_source_epoch_too_low() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        // Set min source epoch
        db.set_min_source_epoch(&pubkey, 100).unwrap();

        // Attempt attestation with lower source should fail
        let root = random_root();
        let result = db.check_and_record_attestation(&pubkey, 50, 200, &root);
        assert!(matches!(
            result,
            Err(SlashingError::SourceEpochTooLow { .. })
        ));
    }

    #[test]
    fn test_target_epoch_too_low() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        // Set min target epoch
        db.set_min_target_epoch(&pubkey, 100).unwrap();

        // Attempt attestation with lower target should fail
        let root = random_root();
        let result = db.check_and_record_attestation(&pubkey, 50, 90, &root);
        assert!(matches!(
            result,
            Err(SlashingError::TargetEpochTooLow { .. })
        ));
    }

    #[test]
    fn test_slot_too_low() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        // Set min slot
        db.set_min_slot(&pubkey, 100).unwrap();

        // Attempt block at lower slot should fail
        let root = random_root();
        let result = db.check_and_record_block(&pubkey, 50, &root);
        assert!(matches!(result, Err(SlashingError::SlotTooLow { .. })));
    }

    #[test]
    fn test_multiple_validators_independent() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey1 = random_pubkey();
        let pubkey2 = random_pubkey();

        db.register_validator(&pubkey1).unwrap();
        db.register_validator(&pubkey2).unwrap();

        let root1 = random_root();
        let root2 = random_root();

        // Both validators can sign at same target with different roots
        db.check_and_record_attestation(&pubkey1, 10, 20, &root1)
            .unwrap();
        db.check_and_record_attestation(&pubkey2, 10, 20, &root2)
            .unwrap();
    }

    #[test]
    fn test_valid_non_surrounding_attestations() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        // These attestations should all be valid (non-surrounding)
        let root1 = random_root();
        let root2 = random_root();
        let root3 = random_root();

        // (5, 10)
        db.check_and_record_attestation(&pubkey, 5, 10, &root1)
            .unwrap();

        // (10, 15) - source > prev source, target > prev target
        db.check_and_record_attestation(&pubkey, 10, 15, &root2)
            .unwrap();

        // (15, 20) - source > prev source, target > prev target
        db.check_and_record_attestation(&pubkey, 15, 20, &root3)
            .unwrap();
    }

    #[test]
    fn test_stats_tracking() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        // Sign some attestations and blocks
        for i in 0..5 {
            let root = random_root();
            db.check_and_record_attestation(&pubkey, i * 10, i * 10 + 5, &root)
                .unwrap();
        }

        for i in 0..3 {
            let root = random_root();
            db.check_and_record_block(&pubkey, i * 100, &root).unwrap();
        }

        let stats = db.stats();
        assert_eq!(stats.attestations_signed, 5);
        assert_eq!(stats.blocks_signed, 3);
    }

    // ---------------------------------------------------------------------
    // CRITICAL #4: durability-before-signature regression tests.
    //
    // These prove that `check_and_record_attestation` / `check_and_record_block`
    // make the signing record durable on disk (fsync) BEFORE returning Ok, while
    // still holding the per-validator write lock. The signature is produced by the
    // caller only after Ok, so if the record is durable before Ok, a crash in the
    // signing window cannot lose it (which would permit a double-sign on restart).
    //
    // The crash is simulated by re-executing the test binary as a child that writes
    // the record and then calls `std::process::abort()` (terminates WITHOUT running
    // destructors, so sled's Drop-flush never runs). The database is opened with
    // `flush_every_ms(None)`, so the ONLY thing that can make the record durable is
    // the explicit flush inside the check-and-record function. The parent then
    // reopens the DB from a fresh process and asserts the record survived.
    //
    // Before the fix (no internal flush) the record lives only in the in-memory IO
    // buffer and is lost by the abort, so the conflicting re-sign below would be
    // ALLOWED and these tests would FAIL.
    // ---------------------------------------------------------------------

    const CRASH_CHILD_ENV: &str = "HSM_VALIDATOR_CRASH_CHILD";
    // 48-byte pubkey used by the crash-durability child/parent (deterministic).
    const CRASH_PUBKEY: [u8; 48] = [0x42u8; 48];
    // Signing root recorded by the child before it crashes.
    const CRASH_ROOT: [u8; 32] = [0x11u8; 32];
    const CRASH_SOURCE: Epoch = 10;
    const CRASH_TARGET: Epoch = 20;
    const CRASH_SLOT: Slot = 100;

    // If this test process was re-spawned as a crash child, perform the recorded
    // write and abort before any normal test runs. Marked #[ctor]-like via a guard
    // inside each test entrypoint instead would be cleaner, but a plain helper keeps
    // it dependency-free; the parent only ever spawns the child with the env var set.
    fn maybe_run_crash_child() {
        let mode = match std::env::var(CRASH_CHILD_ENV) {
            Ok(m) => m,
            Err(_) => return,
        };
        let path = std::env::var("HSM_VALIDATOR_CRASH_PATH").unwrap();
        let db = SlashingProtectionDb::open(&path).unwrap();
        db.register_validator(&CRASH_PUBKEY).unwrap();
        match mode.as_str() {
            "attestation" => {
                db.check_and_record_attestation(
                    &CRASH_PUBKEY,
                    CRASH_SOURCE,
                    CRASH_TARGET,
                    &SigningRoot::new(CRASH_ROOT),
                )
                .unwrap();
            }
            "block" => {
                db.check_and_record_block(&CRASH_PUBKEY, CRASH_SLOT, &SigningRoot::new(CRASH_ROOT))
                    .unwrap();
            }
            other => panic!("unknown crash mode: {other}"),
        }
        // Simulate a crash immediately after the check-and-record returned Ok: abort
        // terminates the process WITHOUT running destructors, so sled's Drop-flush
        // never executes. Only the explicit in-function flush can have persisted data.
        std::process::abort();
    }

    fn spawn_crash_child(mode: &str, db_path: &std::path::Path) {
        let exe = std::env::current_exe().expect("current_exe");
        let status = std::process::Command::new(exe)
            // Run only this single test in the child so it hits maybe_run_crash_child.
            .arg("--exact")
            .arg(match mode {
                "attestation" => {
                    "slashing_db::tests::test_attestation_durable_before_signature_returned"
                }
                "block" => "slashing_db::tests::test_block_durable_before_signature_returned",
                _ => unreachable!(),
            })
            .env(CRASH_CHILD_ENV, mode)
            .env("HSM_VALIDATOR_CRASH_PATH", db_path)
            .status()
            .expect("spawn crash child");
        // The child aborts, so it must NOT exit successfully.
        assert!(
            !status.success(),
            "crash child should have aborted, got {status:?}"
        );
    }

    #[test]
    fn test_attestation_durable_before_signature_returned() {
        maybe_run_crash_child();

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("slashing-db");

        // Child records an attestation, then crashes (abort, no Drop-flush).
        spawn_crash_child("attestation", &db_path);

        // Reopen from this (fresh) process. The record must have survived because the
        // check-and-record flushed it to disk before returning Ok.
        let db = SlashingProtectionDb::open(&db_path).unwrap();
        let records = db.get_attestation_records(&CRASH_PUBKEY).unwrap();
        assert_eq!(
            records.len(),
            1,
            "attestation record must be durable across a crash (flush before signature)"
        );
        assert_eq!(records[0].target_epoch, CRASH_TARGET);
        assert_eq!(records[0].signing_root.as_bytes(), &CRASH_ROOT);

        // And the durable record must now block a conflicting double-vote.
        let conflicting = SigningRoot::new([0x22u8; 32]);
        let result = db.check_and_record_attestation(
            &CRASH_PUBKEY,
            CRASH_SOURCE,
            CRASH_TARGET,
            &conflicting,
        );
        assert!(
            matches!(result, Err(SlashingError::DoubleVote { .. })),
            "after crash recovery the recorded attestation must prevent a double vote, got {result:?}"
        );
    }

    #[test]
    fn test_block_durable_before_signature_returned() {
        maybe_run_crash_child();

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("slashing-db");

        spawn_crash_child("block", &db_path);

        let db = SlashingProtectionDb::open(&db_path).unwrap();
        let records = db.get_block_records(&CRASH_PUBKEY).unwrap();
        assert_eq!(
            records.len(),
            1,
            "block record must be durable across a crash (flush before signature)"
        );
        assert_eq!(records[0].slot, CRASH_SLOT);

        let conflicting = SigningRoot::new([0x33u8; 32]);
        let result = db.check_and_record_block(&CRASH_PUBKEY, CRASH_SLOT, &conflicting);
        assert!(
            matches!(result, Err(SlashingError::DoubleBlockProposal { .. })),
            "after crash recovery the recorded block must prevent a double proposal, got {result:?}"
        );
    }

    // ---------------------------------------------------------------------
    // MEDIUM #21: EIP-3076 boundary regression tests.
    //
    // EIP-3076 requires refusing to sign an attestation whose target epoch is
    // `<= min_target_epoch` and a block whose slot is `<= min_slot` (the previous
    // code used strict `<`, which permitted signing AT the minimum - a slashable
    // gap when migrating protection between clients). The identical-signing-root
    // repeat is still allowed.
    // ---------------------------------------------------------------------

    #[test]
    fn test_attestation_at_min_target_epoch_refused() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        // Imported protection sets the minimum target epoch to 100.
        db.set_min_target_epoch(&pubkey, 100).unwrap();

        // Signing AT the minimum target epoch (100) with a fresh root must be refused.
        // Source is well above any min_source so only the target boundary is exercised.
        let root = random_root();
        let result = db.check_and_record_attestation(&pubkey, 90, 100, &root);
        assert!(
            matches!(result, Err(SlashingError::TargetEpochTooLow { .. })),
            "signing AT the minimum target epoch must be refused (EIP-3076 <=), got {result:?}"
        );

        // One above the minimum is allowed.
        let root2 = random_root();
        db.check_and_record_attestation(&pubkey, 90, 101, &root2)
            .expect("target epoch above minimum must be allowed");
    }

    #[test]
    fn test_block_at_min_slot_refused() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        db.set_min_slot(&pubkey, 100).unwrap();

        // Signing AT the minimum slot (100) must be refused.
        let root = random_root();
        let result = db.check_and_record_block(&pubkey, 100, &root);
        assert!(
            matches!(result, Err(SlashingError::SlotTooLow { .. })),
            "signing AT the minimum slot must be refused (EIP-3076 <=), got {result:?}"
        );

        // One above the minimum is allowed.
        let root2 = random_root();
        db.check_and_record_block(&pubkey, 101, &root2)
            .expect("slot above minimum must be allowed");
    }

    #[test]
    fn test_source_epoch_at_min_allowed() {
        // Source epoch uses strict `<` (NOT `<=`): the FFG source legitimately repeats,
        // so signing AT the minimum source epoch must be allowed (only target/slot use
        // the `<=` boundary).
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        db.set_min_source_epoch(&pubkey, 50).unwrap();

        let root = random_root();
        db.check_and_record_attestation(&pubkey, 50, 200, &root)
            .expect("source epoch AT the minimum must be allowed (strict < for source)");
    }

    // ---------------------------------------------------------------------
    // HIGH #5: fail-closed on an unreadable existing record.
    //
    // The previous code used `if let Ok(Some(existing)) = ...get(&key)`, so a read
    // that did not yield `Ok(Some(_))` silently fell through to record-and-sign. We
    // now match explicitly. This test corrupts the stored value at the exact
    // attestation key so it cannot be deserialized; signing MUST be refused rather
    // than proceeding to overwrite/record and sign.
    // ---------------------------------------------------------------------

    #[test]
    fn test_attestation_unreadable_record_fails_closed() {
        let db = SlashingProtectionDb::in_memory().unwrap();
        let pubkey = random_pubkey();
        db.register_validator(&pubkey).unwrap();

        let target = 20u64;
        // Plant a value at the attestation key that is NOT valid AttestationData JSON.
        let key = db.attestation_key(&pubkey, target);
        db.attestations
            .insert(&key, b"not valid json".as_ref())
            .unwrap();

        // Attempting to sign at this target must be refused (fail closed), not signed.
        let root = random_root();
        let result = db.check_and_record_attestation(&pubkey, 10, target, &root);
        assert!(
            result.is_err(),
            "an unreadable existing attestation record must fail closed, got {result:?}"
        );
    }
}
