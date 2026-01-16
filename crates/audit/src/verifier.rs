//! # Audit Log Verification
//!
//! Utilities for verifying the integrity and authenticity of audit logs using
//! hash chain and Merkle tree verification.
//!
//! ## Verification Methods
//!
//! The verifier provides multiple verification strategies:
//!
//! 1. **Hash Chain Verification**: Verifies each event's hash and chain linkage
//! 2. **Merkle Tree Verification**: Verifies events against a known Merkle root
//! 3. **Range Verification**: Verifies a subset of events
//! 4. **Report Generation**: Produces detailed verification reports
//!
//! ## Verification Workflow
//!
//! ```text
//! ┌─────────────────┐
//! │  Audit Events   │
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ Hash Verification│  ← Verify each event's hash
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │Chain Verification│  ← Verify prev_hash linkage
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │Sequence Check   │  ← Verify continuous sequence
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │Merkle Verification│ ← Optional: verify against root
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ Report/Result   │
//! └─────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ```rust
//! use audit::{AuditVerifier, AuditEvent};
//! use std::path::Path;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Verify events from a log file
//! # let path = Path::new("/tmp/audit.log");
//! # if !path.exists() { return Ok(()); }
//! let result = AuditVerifier::verify_log_file(path)?;
//!
//! if result.passed {
//!     println!("✓ Log verified: {} events", result.total_events);
//! } else {
//!     println!("✗ Verification failed:");
//!     for error in &result.errors {
//!         println!("  - {}", error);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Detailed Report Example
//!
//! ```rust
//! # use audit::{AuditVerifier, HashChain};
//! # use audit::event::{AuditEvent, EventType, OperationResult};
//! # use chrono::Utc;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let chain = HashChain::new();
//! # for i in 1..=5 {
//! #     let event = AuditEvent::builder()
//! #         .sequence(i)
//! #         .event_type(EventType::Sign)
//! #         .operation("test")
//! #         .namespace("default")
//! #         .client_id("client")
//! #         .result(OperationResult::Success)
//! #         .timestamp(Utc::now())
//! #         .build()?;
//! #     chain.append(event)?;
//! # }
//! let events = chain.get_all_events();
//!
//! // Generate detailed report
//! let report = AuditVerifier::generate_report(&events);
//!
//! println!("{}", report.summary());
//! // Output:
//! // Total Events: 5
//! // Hash Valid: 5/5
//! // Chain Valid: 4/4
//! // Sequence Valid: 5/5
//! // Overall: VALID
//! // Merkle Root: abc123...
//! # Ok(())
//! # }
//! ```
//!
//! ## Range Verification
//!
//! For large logs, you can verify specific ranges:
//!
//! ```rust
//! # use audit::{AuditVerifier, HashChain};
//! # use audit::event::{AuditEvent, EventType, OperationResult};
//! # use chrono::Utc;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let chain = HashChain::new();
//! # for i in 1..=100 {
//! #     let event = AuditEvent::builder()
//! #         .sequence(i)
//! #         .event_type(EventType::Sign)
//! #         .operation("test")
//! #         .namespace("default")
//! #         .client_id("client")
//! #         .result(OperationResult::Success)
//! #         .timestamp(Utc::now())
//! #         .build()?;
//! #     chain.append(event)?;
//! # }
//! let events = chain.get_all_events();
//!
//! // Verify the last 50 events
//! AuditVerifier::verify_range(&events, 51, 100)?;
//!
//! // Verify a specific suspicious range
//! AuditVerifier::verify_range(&events, 45, 55)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Merkle Tree Verification
//!
//! Verify events against a trusted Merkle root:
//!
//! ```rust
//! # use audit::{AuditVerifier, MerkleTree};
//! # use audit::event::{AuditEvent, EventType, OperationResult};
//! # use chrono::Utc;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut events = Vec::new();
//! # for i in 1..=10 {
//! #     let event = AuditEvent::builder()
//! #         .sequence(i)
//! #         .event_type(EventType::Sign)
//! #         .operation("test")
//! #         .namespace("default")
//! #         .client_id("client")
//! #         .result(OperationResult::Success)
//! #         .timestamp(Utc::now())
//! #         .prev_hash("0".repeat(64))
//! #         .build()?;
//! #     events.push(event);
//! # }
//! // Get trusted root from a checkpoint or backup
//! let trusted_root = "abc123...";  // From secure storage
//!
//! // Verify all events match the trusted root
//! AuditVerifier::verify_merkle_tree(&events, trusted_root)?;
//!
//! println!("✓ Events match trusted Merkle root");
//! # Ok(())
//! # }
//! ```
//!
//! ## Tamper Detection
//!
//! The verifier detects various types of tampering:
//!
//! - **Modified event data**: Hash verification fails
//! - **Deleted events**: Sequence gaps detected
//! - **Inserted events**: Chain linkage breaks
//! - **Reordered events**: Sequence and chain verification fail
//!
//! ## Performance Characteristics
//!
//! - **Hash Chain Verification**: O(n) - must check each event
//! - **Merkle Verification**: O(n) - build tree + verify inclusion
//! - **Range Verification**: O(range_size) - only checks subset
//! - **Report Generation**: O(n) - collects detailed statistics

use crate::event::AuditEvent;
use crate::merkle_tree::MerkleTree;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Hash mismatch at sequence {sequence}: expected {expected}, got {actual}")]
    HashMismatch {
        sequence: u64,
        expected: String,
        actual: String,
    },

    #[error("Chain broken at sequence {sequence}: prev_hash mismatch")]
    ChainBroken { sequence: u64 },

    #[error("Sequence gap detected: expected {expected}, got {actual}")]
    SequenceGap { expected: u64, actual: u64 },

    #[error("Merkle root mismatch: expected {expected}, got {actual}")]
    MerkleRootMismatch { expected: String, actual: String },

    #[error("Event not found in Merkle tree: sequence {0}")]
    EventNotInMerkleTree(u64),

    #[error("Empty log file")]
    EmptyLog,
}

/// Result of a verification operation
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub passed: bool,
    pub total_events: usize,
    pub verified_events: usize,
    pub errors: Vec<String>,
}

impl VerificationResult {
    pub fn success(total_events: usize) -> Self {
        Self {
            passed: true,
            total_events,
            verified_events: total_events,
            errors: Vec::new(),
        }
    }

    pub fn failure(total_events: usize, verified_events: usize, errors: Vec<String>) -> Self {
        Self {
            passed: false,
            total_events,
            verified_events,
            errors,
        }
    }
}

/// Verifier for audit log integrity.
///
/// Provides static methods for verifying audit logs using hash chains,
/// Merkle trees, and sequence continuity checks.
///
/// # Examples
///
/// ```rust
/// use audit::AuditVerifier;
/// # use audit::event::{AuditEvent, EventType, OperationResult};
/// # use chrono::Utc;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let mut events = Vec::new();
/// # for i in 1..=5 {
/// #     let event = AuditEvent::builder()
/// #         .sequence(i)
/// #         .event_type(EventType::Sign)
/// #         .operation("test")
/// #         .namespace("default")
/// #         .client_id("client")
/// #         .result(OperationResult::Success)
/// #         .timestamp(Utc::now())
/// #         .prev_hash("0".repeat(64))
/// #         .build()?;
/// #     events.push(event);
/// # }
/// // Verify a list of events
/// let result = AuditVerifier::verify_events(&events)?;
/// assert!(result.passed);
///
/// // Generate detailed report
/// let report = AuditVerifier::generate_report(&events);
/// println!("{}", report.summary());
/// # Ok(())
/// # }
/// ```
pub struct AuditVerifier;

impl AuditVerifier {
    /// Verifies the integrity of a log file.
    ///
    /// Reads events from a JSON lines file and performs full verification
    /// including hash, chain, and sequence checks.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the audit log file (JSON lines format)
    ///
    /// # Returns
    ///
    /// A `VerificationResult` indicating success or failure with details
    ///
    /// # Errors
    ///
    /// - `Io` - If the file cannot be read
    /// - `Serialization` - If JSON parsing fails
    /// - `EmptyLog` - If the file contains no events
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use audit::AuditVerifier;
    /// use std::path::Path;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let path = Path::new("/var/log/hsm/audit.log");
    /// let result = AuditVerifier::verify_log_file(path)?;
    ///
    /// if result.passed {
    ///     println!("Log is valid: {} events verified", result.total_events);
    /// } else {
    ///     for error in &result.errors {
    ///         eprintln!("Verification error: {}", error);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify_log_file(path: &Path) -> Result<VerificationResult, VerificationError> {
        let events = Self::read_events_from_file(path)?;

        if events.is_empty() {
            return Err(VerificationError::EmptyLog);
        }

        Self::verify_events(&events)
    }

    /// Verify a list of events
    pub fn verify_events(events: &[AuditEvent]) -> Result<VerificationResult, VerificationError> {
        let mut errors = Vec::new();
        let total = events.len();
        let mut verified = 0;

        // Verify each event's hash
        for event in events {
            if !event.verify_hash() {
                errors.push(format!(
                    "Hash mismatch at sequence {}: computed hash does not match stored hash",
                    event.sequence
                ));
                continue;
            }
            verified += 1;
        }

        // Verify sequence continuity
        for (i, event) in events.iter().enumerate() {
            let expected_seq = i as u64 + 1;
            if event.sequence != expected_seq {
                errors.push(format!(
                    "Sequence gap: expected {}, got {}",
                    expected_seq, event.sequence
                ));
            }
        }

        // Verify hash chain
        for i in 1..events.len() {
            if events[i].prev_hash != events[i - 1].current_hash {
                errors.push(format!(
                    "Chain broken at sequence {}: prev_hash does not match previous event's hash",
                    events[i].sequence
                ));
            }
        }

        if errors.is_empty() {
            Ok(VerificationResult::success(total))
        } else {
            Ok(VerificationResult::failure(total, verified, errors))
        }
    }

    /// Verify hash chain integrity
    pub fn verify_hash_chain(events: &[AuditEvent]) -> Result<(), VerificationError> {
        for i in 0..events.len() {
            let event = &events[i];

            // Verify event hash
            let computed_hash = event.compute_hash();
            if computed_hash != event.current_hash {
                return Err(VerificationError::HashMismatch {
                    sequence: event.sequence,
                    expected: event.current_hash.clone(),
                    actual: computed_hash,
                });
            }

            // Verify chain linkage (except for first event)
            if i > 0 {
                let prev_event = &events[i - 1];
                if event.prev_hash != prev_event.current_hash {
                    return Err(VerificationError::ChainBroken {
                        sequence: event.sequence,
                    });
                }
            }

            // Verify sequence continuity
            let expected_seq = i as u64 + 1;
            if event.sequence != expected_seq {
                return Err(VerificationError::SequenceGap {
                    expected: expected_seq,
                    actual: event.sequence,
                });
            }
        }

        Ok(())
    }

    /// Verify Merkle tree integrity
    pub fn verify_merkle_tree(
        events: &[AuditEvent],
        expected_root: &str,
    ) -> Result<(), VerificationError> {
        let hashes: Vec<String> = events.iter().map(|e| e.current_hash.clone()).collect();

        let tree = MerkleTree::from_hashes(hashes);
        let actual_root = tree.get_root().map_err(|_| VerificationError::EmptyLog)?;

        if actual_root != expected_root {
            return Err(VerificationError::MerkleRootMismatch {
                expected: expected_root.to_string(),
                actual: actual_root,
            });
        }

        // Verify each event is in the tree
        for event in events {
            if !tree.verify_inclusion(&event.current_hash) {
                return Err(VerificationError::EventNotInMerkleTree(event.sequence));
            }
        }

        Ok(())
    }

    /// Verify a specific range of events
    pub fn verify_range(
        events: &[AuditEvent],
        from: u64,
        to: u64,
    ) -> Result<(), VerificationError> {
        if from == 0 || to > events.len() as u64 || from > to {
            return Err(VerificationError::SequenceGap {
                expected: from,
                actual: to,
            });
        }

        let range_events = &events[((from - 1) as usize)..(to as usize)];

        // Verify each event's hash and chain linkage
        for i in 0..range_events.len() {
            let event = &range_events[i];

            // Verify event hash
            let computed_hash = event.compute_hash();
            if computed_hash != event.current_hash {
                return Err(VerificationError::HashMismatch {
                    sequence: event.sequence,
                    expected: event.current_hash.clone(),
                    actual: computed_hash,
                });
            }

            // Verify chain linkage (except for first event in range)
            if i > 0 {
                let prev_event = &range_events[i - 1];
                if event.prev_hash != prev_event.current_hash {
                    return Err(VerificationError::ChainBroken {
                        sequence: event.sequence,
                    });
                }
            }

            // Verify sequence continuity within the range
            let expected_seq = from + i as u64;
            if event.sequence != expected_seq {
                return Err(VerificationError::SequenceGap {
                    expected: expected_seq,
                    actual: event.sequence,
                });
            }
        }

        Ok(())
    }

    /// Read events from a file
    fn read_events_from_file(path: &Path) -> Result<Vec<AuditEvent>, VerificationError> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let mut events = Vec::new();

        use std::io::BufRead;
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let event: AuditEvent = serde_json::from_str(&line)?;
            events.push(event);
        }

        Ok(events)
    }

    /// Generate a verification report
    pub fn generate_report(events: &[AuditEvent]) -> VerificationReport {
        let total = events.len();
        let mut hash_valid = 0;
        let mut chain_valid = 0;
        let mut sequence_valid = 0;

        // Check individual hashes
        for event in events {
            if event.verify_hash() {
                hash_valid += 1;
            }
        }

        // Check sequence continuity
        let mut sequences_ok = true;
        for (i, event) in events.iter().enumerate() {
            let expected_seq = i as u64 + 1;
            if event.sequence != expected_seq {
                sequences_ok = false;
                break;
            }
            sequence_valid += 1;
        }

        // Check chain integrity
        let mut chain_ok = true;
        for i in 1..events.len() {
            if events[i].prev_hash != events[i - 1].current_hash {
                chain_ok = false;
                break;
            } else {
                chain_valid += 1;
            }
        }

        // Build Merkle tree and get root
        let hashes: Vec<String> = events.iter().map(|e| e.current_hash.clone()).collect();
        let tree = MerkleTree::from_hashes(hashes);
        let merkle_root = tree.get_root().ok();

        VerificationReport {
            total_events: total,
            hash_valid_count: hash_valid,
            chain_valid_count: chain_valid,
            sequence_valid_count: sequence_valid,
            all_hashes_valid: hash_valid == total,
            chain_intact: chain_ok,
            sequences_continuous: sequences_ok,
            merkle_root,
        }
    }
}

/// Detailed verification report
#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub total_events: usize,
    pub hash_valid_count: usize,
    pub chain_valid_count: usize,
    pub sequence_valid_count: usize,
    pub all_hashes_valid: bool,
    pub chain_intact: bool,
    pub sequences_continuous: bool,
    pub merkle_root: Option<String>,
}

impl VerificationReport {
    pub fn is_valid(&self) -> bool {
        self.all_hashes_valid && self.chain_intact && self.sequences_continuous
    }

    pub fn summary(&self) -> String {
        format!(
            "Total Events: {}\n\
             Hash Valid: {}/{}\n\
             Chain Valid: {}/{}\n\
             Sequence Valid: {}/{}\n\
             Overall: {}\n\
             Merkle Root: {}",
            self.total_events,
            self.hash_valid_count,
            self.total_events,
            self.chain_valid_count,
            self.total_events.saturating_sub(1),
            self.sequence_valid_count,
            self.total_events,
            if self.is_valid() { "VALID" } else { "INVALID" },
            self.merkle_root.as_deref().unwrap_or("N/A")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventType, OperationResult};
    use chrono::Utc;
    use tempfile::NamedTempFile;

    fn create_test_event(seq: u64, prev_hash: &str) -> AuditEvent {
        AuditEvent::builder()
            .sequence(seq)
            .event_type(EventType::Sign)
            .operation("test_op")
            .namespace("test")
            .client_id("client_1")
            .result(OperationResult::Success)
            .timestamp(Utc::now())
            .prev_hash(prev_hash)
            .build()
            .unwrap()
    }

    fn create_event_chain(count: usize) -> Vec<AuditEvent> {
        let mut events = Vec::new();
        let mut prev_hash = "0".repeat(64);

        for i in 1..=count {
            let event = create_test_event(i as u64, &prev_hash);
            prev_hash = event.current_hash.clone();
            events.push(event);
        }

        events
    }

    #[test]
    fn test_verify_valid_events() {
        let events = create_event_chain(5);
        let result = AuditVerifier::verify_events(&events).unwrap();
        assert!(result.passed);
        assert_eq!(result.total_events, 5);
        assert_eq!(result.verified_events, 5);
    }

    #[test]
    fn test_verify_hash_chain() {
        let events = create_event_chain(10);
        assert!(AuditVerifier::verify_hash_chain(&events).is_ok());
    }

    #[test]
    fn test_verify_broken_chain() {
        let mut events = create_event_chain(5);

        // Break the chain
        events[2].prev_hash = "invalid_hash".to_string();

        assert!(AuditVerifier::verify_hash_chain(&events).is_err());
    }

    #[test]
    fn test_verify_tampered_event() {
        let mut events = create_event_chain(5);

        // Tamper with an event
        events[2].operation = "tampered".to_string();

        assert!(AuditVerifier::verify_hash_chain(&events).is_err());
    }

    #[test]
    fn test_verify_sequence_gap() {
        let mut events = create_event_chain(5);

        // Create a sequence gap
        events[2].sequence = 10;

        assert!(AuditVerifier::verify_hash_chain(&events).is_err());
    }

    #[test]
    fn test_verify_merkle_tree() {
        let events = create_event_chain(8);
        let hashes: Vec<String> = events.iter().map(|e| e.current_hash.clone()).collect();

        let tree = MerkleTree::from_hashes(hashes);
        let root = tree.get_root().unwrap();

        assert!(AuditVerifier::verify_merkle_tree(&events, &root).is_ok());
    }

    #[test]
    fn test_verify_merkle_tree_mismatch() {
        let events = create_event_chain(5);
        let wrong_root = "0".repeat(64);

        assert!(AuditVerifier::verify_merkle_tree(&events, &wrong_root).is_err());
    }

    #[test]
    fn test_verify_range() {
        let events = create_event_chain(10);
        assert!(AuditVerifier::verify_range(&events, 1, 5).is_ok());
        assert!(AuditVerifier::verify_range(&events, 5, 10).is_ok());
    }

    #[test]
    fn test_generate_report() {
        let events = create_event_chain(10);
        let report = AuditVerifier::generate_report(&events);

        assert_eq!(report.total_events, 10);
        assert!(report.is_valid());
        assert!(report.all_hashes_valid);
        assert!(report.chain_intact);
        assert!(report.sequences_continuous);
        assert!(report.merkle_root.is_some());
    }

    #[test]
    fn test_generate_report_invalid() {
        let mut events = create_event_chain(5);

        // Tamper with an event
        events[2].operation = "tampered".to_string();

        let report = AuditVerifier::generate_report(&events);

        assert!(!report.is_valid());
        assert!(!report.all_hashes_valid);
    }

    #[test]
    fn test_verify_log_file() {
        let events = create_event_chain(5);

        // Write events to a temp file
        let temp_file = NamedTempFile::new().unwrap();
        let mut writer = std::io::BufWriter::new(temp_file.as_file());

        use std::io::Write;
        for event in &events {
            let json = serde_json::to_string(&event).unwrap();
            writeln!(writer, "{}", json).unwrap();
        }
        writer.flush().unwrap();

        // Verify the file
        let result = AuditVerifier::verify_log_file(temp_file.path()).unwrap();
        assert!(result.passed);
        assert_eq!(result.total_events, 5);
    }

    #[test]
    fn test_report_summary() {
        let events = create_event_chain(3);
        let report = AuditVerifier::generate_report(&events);

        let summary = report.summary();
        assert!(summary.contains("Total Events: 3"));
        assert!(summary.contains("Overall: VALID"));
    }
}
