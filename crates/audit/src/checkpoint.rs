//! # Signed-Root Checkpoints
//!
//! A checkpoint binds the audit log's latest sequence number to the Merkle
//! root that commits to *all* events up to that sequence. Persisting a
//! checkpoint at write time and verifying the live chain tip against the most
//! recent checkpoint closes a tail-truncation gap: a hash chain alone cannot
//! detect that the most recent `k` events were deleted, because the truncated
//! prefix is still internally consistent.
//!
//! ## Tamper-evidence model
//!
//! The checkpoint carries an integrity tag computed over `(sequence ||
//! merkle_root)`:
//!
//! - When a `checkpoint_key` is configured, the tag is `HMAC-SHA256(key,
//!   domain || sequence || merkle_root)`. An attacker who truncates the log
//!   but does not possess the key cannot forge a checkpoint that points at the
//!   shortened chain, so the truncation is detected. This is the production
//!   posture.
//! - When no key is configured, the tag degrades to a plain
//!   `SHA256(domain || sequence || merkle_root)`. This still detects accidental
//!   corruption and naive truncation (where the attacker forgets to rewrite the
//!   checkpoint), but it is NOT secure against an attacker who can rewrite the
//!   checkpoint file. Operators are expected to provision a key for any
//!   deployment with a meaningful threat model; the keyless mode exists only so
//!   the feature is usable in tests and single-tenant dev setups.
//!
//! Because there is no cryptographic signing key plumbed into the audit crate
//! itself, true non-repudiable signing (e.g. Ed25519 over the root) is left to
//! the caller, who can supply the HMAC key derived from the HSM master key.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation tag for checkpoint integrity computation.
const CHECKPOINT_DOMAIN: &[u8] = b"hsm-audit-checkpoint-v1";

#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("checkpoint integrity tag mismatch (corrupted or forged checkpoint)")]
    IntegrityMismatch,

    #[error(
        "log tip is behind the checkpoint: checkpoint sequence {checkpoint}, live tip {live} (possible tail truncation)"
    )]
    TipBehindCheckpoint { checkpoint: u64, live: u64 },

    #[error("merkle root mismatch at sequence {sequence}: checkpoint {checkpoint}, live {live}")]
    RootMismatch {
        sequence: u64,
        checkpoint: String,
        live: String,
    },

    #[error("serialization error: {0}")]
    Serialization(String),
}

/// A persisted commitment to the audit log state at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    /// Highest sequence number committed by this checkpoint.
    pub sequence: u64,
    /// Merkle root over all event hashes `1..=sequence`.
    pub merkle_root: String,
    /// Integrity tag binding `sequence` and `merkle_root` (hex).
    pub integrity_tag: String,
}

impl Checkpoint {
    /// Compute the integrity tag for a `(sequence, merkle_root)` pair.
    ///
    /// Uses HMAC-SHA256 when `key` is `Some`, otherwise a plain domain-separated
    /// SHA-256 digest. The byte layout is identical in both cases:
    /// `DOMAIN || sequence_le_bytes || merkle_root_bytes`.
    fn compute_tag(sequence: u64, merkle_root: &str, key: Option<&[u8]>) -> String {
        match key {
            Some(k) => {
                let mut mac =
                    HmacSha256::new_from_slice(k).expect("HMAC accepts keys of any length");
                mac.update(CHECKPOINT_DOMAIN);
                mac.update(&sequence.to_le_bytes());
                mac.update(merkle_root.as_bytes());
                hex::encode(mac.finalize().into_bytes())
            }
            None => {
                let mut hasher = Sha256::new();
                hasher.update(CHECKPOINT_DOMAIN);
                hasher.update(sequence.to_le_bytes());
                hasher.update(merkle_root.as_bytes());
                hex::encode(hasher.finalize())
            }
        }
    }

    /// Create a new checkpoint, computing its integrity tag.
    pub fn new(sequence: u64, merkle_root: impl Into<String>, key: Option<&[u8]>) -> Self {
        let merkle_root = merkle_root.into();
        let integrity_tag = Self::compute_tag(sequence, &merkle_root, key);
        Self {
            sequence,
            merkle_root,
            integrity_tag,
        }
    }

    /// Verify the checkpoint's own integrity tag.
    ///
    /// Uses a constant-time comparison so a corrupted/forged checkpoint cannot
    /// be distinguished by timing. Returns `Err(IntegrityMismatch)` if the tag
    /// does not match `(sequence, merkle_root)` under `key`.
    pub fn verify_integrity(&self, key: Option<&[u8]>) -> Result<(), CheckpointError> {
        let expected = Self::compute_tag(self.sequence, &self.merkle_root, key);
        // Constant-time-ish comparison via byte-equal length check then fold.
        if ct_eq(expected.as_bytes(), self.integrity_tag.as_bytes()) {
            Ok(())
        } else {
            Err(CheckpointError::IntegrityMismatch)
        }
    }

    /// Serialize to a JSON line for persistence.
    pub fn to_json(&self) -> Result<String, CheckpointError> {
        serde_json::to_string(self).map_err(|e| CheckpointError::Serialization(e.to_string()))
    }

    /// Parse from a JSON line.
    pub fn from_json(s: &str) -> Result<Self, CheckpointError> {
        serde_json::from_str(s).map_err(|e| CheckpointError::Serialization(e.to_string()))
    }

    /// Verify a live chain tip against this checkpoint.
    ///
    /// This is the core tail-truncation guard:
    ///
    /// 1. The checkpoint's own integrity tag must validate (rejects a
    ///    corrupted/forged checkpoint under a keyed deployment).
    /// 2. The live sequence must be `>=` the checkpoint sequence. A live tip
    ///    that is *behind* the checkpoint means events committed by the
    ///    checkpoint have been deleted — fail closed.
    /// 3. If the live tip is exactly at the checkpoint sequence, the live
    ///    Merkle root must match the checkpoint root (rejects in-place
    ///    rewriting of the committed prefix).
    pub fn verify_against_live(
        &self,
        live_sequence: u64,
        live_root: Option<&str>,
        key: Option<&[u8]>,
    ) -> Result<(), CheckpointError> {
        self.verify_integrity(key)?;

        if live_sequence < self.sequence {
            return Err(CheckpointError::TipBehindCheckpoint {
                checkpoint: self.sequence,
                live: live_sequence,
            });
        }

        if live_sequence == self.sequence {
            if let Some(live_root) = live_root {
                if live_root != self.merkle_root {
                    return Err(CheckpointError::RootMismatch {
                        sequence: self.sequence,
                        checkpoint: self.merkle_root.clone(),
                        live: live_root.to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Length-checked, branch-minimized byte comparison for tag verification.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_roundtrip_keyed() {
        let key = b"super-secret-key";
        let cp = Checkpoint::new(42, "deadbeef", Some(key));
        assert!(cp.verify_integrity(Some(key)).is_ok());
    }

    #[test]
    fn test_tag_roundtrip_keyless() {
        let cp = Checkpoint::new(42, "deadbeef", None);
        assert!(cp.verify_integrity(None).is_ok());
    }

    #[test]
    fn test_forged_checkpoint_rejected_with_key() {
        let key = b"super-secret-key";
        let mut cp = Checkpoint::new(10, "root10", Some(key));
        // Attacker rewrites the checkpoint to point at a truncated chain but
        // cannot recompute the HMAC tag without the key.
        cp.sequence = 3;
        cp.merkle_root = "root3".to_string();
        assert!(matches!(
            cp.verify_integrity(Some(key)),
            Err(CheckpointError::IntegrityMismatch)
        ));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let cp = Checkpoint::new(10, "root10", Some(b"key-a"));
        assert!(cp.verify_integrity(Some(b"key-b")).is_err());
    }

    #[test]
    fn test_tip_behind_checkpoint_rejected() {
        let key = b"k";
        let cp = Checkpoint::new(100, "root100", Some(key));
        // Live chain only has 90 events -> tail truncation of 10 events.
        let err = cp.verify_against_live(90, None, Some(key)).unwrap_err();
        assert!(matches!(
            err,
            CheckpointError::TipBehindCheckpoint {
                checkpoint: 100,
                live: 90
            }
        ));
    }

    #[test]
    fn test_tip_at_checkpoint_root_mismatch_rejected() {
        let key = b"k";
        let cp = Checkpoint::new(5, "honest-root", Some(key));
        // Same length but the committed prefix was rewritten in place.
        let err = cp
            .verify_against_live(5, Some("tampered-root"), Some(key))
            .unwrap_err();
        assert!(matches!(err, CheckpointError::RootMismatch { .. }));
    }

    #[test]
    fn test_tip_ahead_of_checkpoint_ok() {
        let key = b"k";
        let cp = Checkpoint::new(5, "root5", Some(key));
        // Live chain has grown past the checkpoint -> fine.
        assert!(cp.verify_against_live(8, None, Some(key)).is_ok());
    }

    #[test]
    fn test_json_roundtrip() {
        let key = b"k";
        let cp = Checkpoint::new(7, "root7", Some(key));
        let json = cp.to_json().unwrap();
        let parsed = Checkpoint::from_json(&json).unwrap();
        assert_eq!(cp, parsed);
        assert!(parsed.verify_integrity(Some(key)).is_ok());
    }
}
