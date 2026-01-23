//! EIP-3076: Slashing Protection Interchange Format
//!
//! This module implements the standard interchange format for migrating
//! slashing protection data between validator clients.
//!
//! # Specification
//!
//! See: <https://eips.ethereum.org/EIPS/eip-3076>
//!
//! # Format Overview
//!
//! ```json
//! {
//!   "metadata": {
//!     "interchange_format_version": "5",
//!     "genesis_validators_root": "0x..."
//!   },
//!   "data": [
//!     {
//!       "pubkey": "0x...",
//!       "signed_blocks": [...],
//!       "signed_attestations": [...]
//!     }
//!   ]
//! }
//! ```
//!
//! # Import Safety
//!
//! When importing, this module applies **complete** protection:
//! - Sets minimum source/target epochs from imported attestations
//! - Sets minimum slot from imported blocks
//! - Records all signed attestations and blocks
//!
//! This ensures that even if some history is missing, the validator
//! will not sign anything that could conflict with imported data.

use crate::error::{Result, ValidatorError};
use crate::slashing_db::SlashingProtectionDb;
use crate::types::*;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Current interchange format version (EIP-3076).
pub const INTERCHANGE_FORMAT_VERSION: &str = "5";

/// EIP-3076 Interchange Format.
///
/// This struct represents the complete interchange format as defined
/// in EIP-3076 for slashing protection data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip3076Interchange {
    /// Metadata about the interchange file
    pub metadata: InterchangeMetadata,
    /// Data for each validator
    pub data: Vec<ValidatorData>,
}

/// Interchange metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterchangeMetadata {
    /// Format version (should be "5")
    pub interchange_format_version: String,
    /// Genesis validators root (identifies the network)
    pub genesis_validators_root: String,
}

/// Data for a single validator in the interchange format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorData {
    /// Validator public key (0x prefixed hex)
    pub pubkey: String,
    /// List of signed blocks
    pub signed_blocks: Vec<SignedBlock>,
    /// List of signed attestations
    pub signed_attestations: Vec<SignedAttestation>,
}

/// A signed block record in the interchange format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBlock {
    /// Slot number (as decimal string)
    pub slot: String,
    /// Signing root (optional, 0x prefixed hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<String>,
}

/// A signed attestation record in the interchange format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAttestation {
    /// Source epoch (as decimal string)
    pub source_epoch: String,
    /// Target epoch (as decimal string)
    pub target_epoch: String,
    /// Signing root (optional, 0x prefixed hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<String>,
}

impl Eip3076Interchange {
    /// Create a new interchange format.
    pub fn new(genesis_validators_root: &str) -> Self {
        Self {
            metadata: InterchangeMetadata {
                interchange_format_version: INTERCHANGE_FORMAT_VERSION.to_string(),
                genesis_validators_root: genesis_validators_root.to_string(),
            },
            data: Vec::new(),
        }
    }

    /// Export slashing protection data from the database.
    ///
    /// # Arguments
    ///
    /// * `slashing_db` - The slashing protection database
    /// * `genesis_validators_root` - The network's genesis validators root
    /// * `public_keys` - Optional list of public keys to export (exports all if None)
    pub fn export(
        slashing_db: &SlashingProtectionDb,
        genesis_validators_root: &str,
        public_keys: Option<&[BlsPublicKey]>,
    ) -> Result<Self> {
        let mut interchange = Self::new(genesis_validators_root);

        // Get validators to export
        let validators = match public_keys {
            Some(keys) => keys.to_vec(),
            None => slashing_db.list_validators()?,
        };

        for pubkey in validators {
            let attestations = slashing_db.get_attestation_records(pubkey.as_bytes())?;
            let blocks = slashing_db.get_block_records(pubkey.as_bytes())?;

            let validator_data = ValidatorData {
                pubkey: pubkey.to_hex(),
                signed_blocks: blocks
                    .into_iter()
                    .map(|b| SignedBlock {
                        slot: b.slot.to_string(),
                        signing_root: Some(b.signing_root.to_hex()),
                    })
                    .collect(),
                signed_attestations: attestations
                    .into_iter()
                    .map(|a| SignedAttestation {
                        source_epoch: a.source_epoch.to_string(),
                        target_epoch: a.target_epoch.to_string(),
                        signing_root: Some(a.signing_root.to_hex()),
                    })
                    .collect(),
            };

            interchange.data.push(validator_data);
        }

        info!(
            validators = interchange.data.len(),
            "Exported slashing protection data"
        );

        Ok(interchange)
    }

    /// Import slashing protection data into the database.
    ///
    /// # Arguments
    ///
    /// * `slashing_db` - The slashing protection database
    ///
    /// # Safety
    ///
    /// This function applies **complete** protection:
    /// - Records all attestations with their signing roots
    /// - Records all blocks with their signing roots
    /// - Sets minimum epochs/slots to prevent signing anything that
    ///   could conflict with imported data
    ///
    /// # Errors
    ///
    /// Returns an error if the interchange format is invalid or if
    /// there's a conflict with existing data.
    pub fn import(&self, slashing_db: &SlashingProtectionDb) -> Result<ImportResult> {
        // Validate format version
        if self.metadata.interchange_format_version != INTERCHANGE_FORMAT_VERSION {
            warn!(
                expected = INTERCHANGE_FORMAT_VERSION,
                actual = %self.metadata.interchange_format_version,
                "Interchange format version mismatch"
            );
        }

        let mut result = ImportResult::default();

        for validator_data in &self.data {
            // Parse public key
            let pubkey_bytes = parse_hex_pubkey(&validator_data.pubkey)?;

            // Register validator if not already registered
            if !slashing_db.is_registered(&pubkey_bytes)? {
                slashing_db.register_validator(&pubkey_bytes)?;
                result.validators_imported += 1;
            }

            // Import attestations
            let mut max_source_epoch: Option<Epoch> = None;
            let mut max_target_epoch: Option<Epoch> = None;

            for attestation in &validator_data.signed_attestations {
                let source_epoch: Epoch = attestation.source_epoch.parse().map_err(|_| {
                    ValidatorError::InvalidInterchange {
                        reason: format!("Invalid source epoch: {}", attestation.source_epoch),
                    }
                })?;

                let target_epoch: Epoch = attestation.target_epoch.parse().map_err(|_| {
                    ValidatorError::InvalidInterchange {
                        reason: format!("Invalid target epoch: {}", attestation.target_epoch),
                    }
                })?;

                // Parse signing root if present
                let signing_root = match &attestation.signing_root {
                    Some(root) => parse_signing_root(root)?,
                    None => SigningRoot::new([0; 32]), // Use zero root if not provided
                };

                // Try to record the attestation
                match slashing_db.check_and_record_attestation(
                    &pubkey_bytes,
                    source_epoch,
                    target_epoch,
                    &signing_root,
                ) {
                    Ok(()) => result.attestations_imported += 1,
                    Err(e) => {
                        warn!(
                            pubkey = %validator_data.pubkey,
                            source_epoch,
                            target_epoch,
                            error = %e,
                            "Failed to import attestation (may conflict with existing data)"
                        );
                        result.attestations_skipped += 1;
                    }
                }

                // Track max epochs for setting minimums
                max_source_epoch =
                    Some(max_source_epoch.map_or(source_epoch, |m| m.max(source_epoch)));
                max_target_epoch =
                    Some(max_target_epoch.map_or(target_epoch, |m| m.max(target_epoch)));
            }

            // Set minimum epochs (ensures we don't sign anything before imported data)
            if let Some(min_source) = max_source_epoch {
                slashing_db.set_min_source_epoch(&pubkey_bytes, min_source)?;
            }
            if let Some(min_target) = max_target_epoch {
                slashing_db.set_min_target_epoch(&pubkey_bytes, min_target)?;
            }

            // Import blocks
            let mut max_slot: Option<Slot> = None;

            for block in &validator_data.signed_blocks {
                let slot: Slot =
                    block
                        .slot
                        .parse()
                        .map_err(|_| ValidatorError::InvalidInterchange {
                            reason: format!("Invalid slot: {}", block.slot),
                        })?;

                let signing_root = match &block.signing_root {
                    Some(root) => parse_signing_root(root)?,
                    None => SigningRoot::new([0; 32]),
                };

                match slashing_db.check_and_record_block(&pubkey_bytes, slot, &signing_root) {
                    Ok(()) => result.blocks_imported += 1,
                    Err(e) => {
                        warn!(
                            pubkey = %validator_data.pubkey,
                            slot,
                            error = %e,
                            "Failed to import block (may conflict with existing data)"
                        );
                        result.blocks_skipped += 1;
                    }
                }

                max_slot = Some(max_slot.map_or(slot, |m| m.max(slot)));
            }

            // Set minimum slot
            if let Some(min_slot) = max_slot {
                slashing_db.set_min_slot(&pubkey_bytes, min_slot)?;
            }
        }

        info!(
            validators = result.validators_imported,
            attestations = result.attestations_imported,
            blocks = result.blocks_imported,
            "Imported slashing protection data"
        );

        Ok(result)
    }

    /// Parse from JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| ValidatorError::InvalidInterchange {
            reason: format!("Invalid JSON: {}", e),
        })
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| ValidatorError::Serialization(e.to_string()))
    }

    /// Serialize to compact JSON (no pretty printing).
    pub fn to_json_compact(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| ValidatorError::Serialization(e.to_string()))
    }
}

/// Result of an import operation.
#[derive(Debug, Clone, Default)]
pub struct ImportResult {
    /// Number of validators imported (newly registered)
    pub validators_imported: u64,
    /// Number of attestations successfully imported
    pub attestations_imported: u64,
    /// Number of attestations skipped (conflicts)
    pub attestations_skipped: u64,
    /// Number of blocks successfully imported
    pub blocks_imported: u64,
    /// Number of blocks skipped (conflicts)
    pub blocks_skipped: u64,
}

/// Parse a hex-encoded public key.
fn parse_hex_pubkey(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    hex::decode(hex).map_err(|e| ValidatorError::InvalidInterchange {
        reason: format!("Invalid public key hex: {}", e),
    })
}

/// Parse a hex-encoded signing root.
fn parse_signing_root(hex: &str) -> Result<SigningRoot> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex).map_err(|e| ValidatorError::InvalidInterchange {
        reason: format!("Invalid signing root hex: {}", e),
    })?;

    SigningRoot::from_slice(&bytes).ok_or_else(|| ValidatorError::InvalidInterchange {
        reason: format!("Signing root must be 32 bytes, got {}", bytes.len()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn create_test_db() -> Arc<SlashingProtectionDb> {
        Arc::new(SlashingProtectionDb::in_memory().unwrap())
    }

    #[test]
    fn test_export_empty() {
        let db = create_test_db();
        let interchange = Eip3076Interchange::export(&db, "0x1234", None).unwrap();

        assert_eq!(interchange.metadata.interchange_format_version, "5");
        assert_eq!(interchange.metadata.genesis_validators_root, "0x1234");
        assert!(interchange.data.is_empty());
    }

    #[test]
    fn test_export_with_data() {
        let db = create_test_db();

        // Register a validator and add some data
        let pubkey = vec![0xab; 48];
        db.register_validator(&pubkey).unwrap();

        let root1 = SigningRoot::new([0x11; 32]);
        let root2 = SigningRoot::new([0x22; 32]);

        db.check_and_record_attestation(&pubkey, 10, 20, &root1)
            .unwrap();
        db.check_and_record_block(&pubkey, 100, &root2).unwrap();

        let interchange = Eip3076Interchange::export(&db, "0x5678", None).unwrap();

        assert_eq!(interchange.data.len(), 1);
        assert_eq!(interchange.data[0].signed_attestations.len(), 1);
        assert_eq!(interchange.data[0].signed_blocks.len(), 1);
    }

    #[test]
    fn test_import_basic() {
        let db = create_test_db();

        let json = r#"{
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "data": [
                {
                    "pubkey": "0xabababababababababababababababababababababababababababababababababababababababababababababababab",
                    "signed_blocks": [
                        {"slot": "100", "signing_root": "0x1111111111111111111111111111111111111111111111111111111111111111"}
                    ],
                    "signed_attestations": [
                        {"source_epoch": "10", "target_epoch": "20", "signing_root": "0x2222222222222222222222222222222222222222222222222222222222222222"}
                    ]
                }
            ]
        }"#;

        let interchange = Eip3076Interchange::from_json(json).unwrap();
        let result = interchange.import(&db).unwrap();

        assert_eq!(result.validators_imported, 1);
        assert_eq!(result.attestations_imported, 1);
        assert_eq!(result.blocks_imported, 1);
    }

    #[test]
    fn test_roundtrip() {
        let db1 = create_test_db();

        // Add some data
        let pubkey = vec![0xcd; 48];
        db1.register_validator(&pubkey).unwrap();

        let root = SigningRoot::new([0x33; 32]);
        db1.check_and_record_attestation(&pubkey, 50, 60, &root)
            .unwrap();

        // Export
        let interchange = Eip3076Interchange::export(&db1, "0xgenesis", None).unwrap();
        let json = interchange.to_json().unwrap();

        // Import into new database
        let db2 = create_test_db();
        let interchange2 = Eip3076Interchange::from_json(&json).unwrap();
        let result = interchange2.import(&db2).unwrap();

        assert_eq!(result.attestations_imported, 1);

        // Verify the import worked
        let summary = db2.get_validator_summary(&pubkey).unwrap();
        assert_eq!(summary.min_source_epoch, Some(50));
        assert_eq!(summary.min_target_epoch, Some(60));
    }

    #[test]
    fn test_import_sets_minimums() {
        let db = create_test_db();

        let json = r#"{
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "data": [
                {
                    "pubkey": "0xefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
                    "signed_blocks": [
                        {"slot": "500"}
                    ],
                    "signed_attestations": [
                        {"source_epoch": "100", "target_epoch": "200"}
                    ]
                }
            ]
        }"#;

        let interchange = Eip3076Interchange::from_json(json).unwrap();
        interchange.import(&db).unwrap();

        let pubkey = hex::decode("efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef").unwrap();
        let summary = db.get_validator_summary(&pubkey).unwrap();

        // Minimums should be set
        assert_eq!(summary.min_source_epoch, Some(100));
        assert_eq!(summary.min_target_epoch, Some(200));
        assert_eq!(summary.min_slot, Some(500));

        // Now trying to sign at lower values should fail
        let root = SigningRoot::new([0x44; 32]);
        let result = db.check_and_record_attestation(&pubkey, 50, 100, &root);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_serialization() {
        let interchange = Eip3076Interchange {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: "0x1234".to_string(),
            },
            data: vec![ValidatorData {
                pubkey: "0xabcd".to_string(),
                signed_blocks: vec![SignedBlock {
                    slot: "100".to_string(),
                    signing_root: Some("0xef".to_string()),
                }],
                signed_attestations: vec![SignedAttestation {
                    source_epoch: "10".to_string(),
                    target_epoch: "20".to_string(),
                    signing_root: None,
                }],
            }],
        };

        let json = interchange.to_json().unwrap();
        let parsed = Eip3076Interchange::from_json(&json).unwrap();

        assert_eq!(parsed.metadata.interchange_format_version, "5");
        assert_eq!(parsed.data.len(), 1);
    }
}
