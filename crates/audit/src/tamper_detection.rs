//! Enhanced tamper detection and integrity verification
//!
//! This module provides comprehensive tamper detection including:
//! - Hash chain verification
//! - Merkle tree consistency checks
//! - Sequence gap detection
//! - Timestamp anomaly detection

use crate::checkpoint::Checkpoint;
use crate::event::AuditEvent;
use crate::merkle_tree::MerkleTree;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TamperDetectionError {
    #[error("Integrity check failed")]
    IntegrityCheckFailed,

    #[error("Empty event log")]
    EmptyLog,
}

/// Types of integrity violations
#[derive(Debug, Clone, PartialEq)]
pub enum Violation {
    /// Hash chain is broken at this sequence
    HashChainBroken {
        sequence: u64,
        expected: String,
        actual: String,
    },

    /// Event hash doesn't match computed hash
    HashMismatch {
        sequence: u64,
        expected: String,
        actual: String,
    },

    /// Sequence numbers have a gap
    SequenceGap { prev: u64, next: u64 },

    /// Duplicate sequence number
    DuplicateSequence { sequence: u64 },

    /// Merkle tree is inconsistent
    MerkleTreeInconsistent { expected: String, actual: String },

    /// Live log tip is behind the signed checkpoint (tail truncation)
    TailTruncated { checkpoint: u64, live: u64 },

    /// Timestamp is not monotonically increasing
    TimestampAnomaly {
        sequence: u64,
        prev_time: DateTime<Utc>,
        curr_time: DateTime<Utc>,
    },

    /// Event appears to have been modified
    EventModified { sequence: u64, details: String },
}

/// Integrity report from tamper detection
#[derive(Debug, Clone)]
pub struct IntegrityReport {
    /// Total events checked
    pub total_events: usize,

    /// Number of violations found
    pub violation_count: usize,

    /// List of violations
    pub violations: Vec<Violation>,

    /// Overall integrity status
    pub is_valid: bool,

    /// Merkle root hash
    pub merkle_root: Option<String>,

    /// Time taken for verification
    pub verification_time_ms: u64,
}

impl IntegrityReport {
    pub fn new() -> Self {
        Self {
            total_events: 0,
            violation_count: 0,
            violations: Vec::new(),
            is_valid: true,
            merkle_root: None,
            verification_time_ms: 0,
        }
    }

    pub fn add_violation(&mut self, violation: Violation) {
        self.violations.push(violation);
        self.violation_count += 1;
        self.is_valid = false;
    }

    pub fn summary(&self) -> String {
        let mut summary = format!(
            "Integrity Report:\n\
             Total Events: {}\n\
             Violations Found: {}\n\
             Status: {}\n",
            self.total_events,
            self.violation_count,
            if self.is_valid { "VALID" } else { "INVALID" }
        );

        if !self.violations.is_empty() {
            summary.push_str("\nViolations:\n");
            for (i, violation) in self.violations.iter().enumerate() {
                summary.push_str(&format!("  {}. {:?}\n", i + 1, violation));
            }
        }

        if let Some(root) = &self.merkle_root {
            summary.push_str(&format!("\nMerkle Root: {}\n", root));
        }

        summary.push_str(&format!(
            "Verification Time: {}ms\n",
            self.verification_time_ms
        ));

        summary
    }
}

impl Default for IntegrityReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Enhanced tamper detector
pub struct TamperDetector;

impl TamperDetector {
    /// Perform comprehensive integrity verification
    pub fn verify_integrity(
        events: &[AuditEvent],
    ) -> Result<IntegrityReport, TamperDetectionError> {
        if events.is_empty() {
            return Err(TamperDetectionError::EmptyLog);
        }

        let start = std::time::Instant::now();
        let mut report = IntegrityReport::new();
        report.total_events = events.len();

        // 1. Verify hash chain continuity
        Self::verify_hash_chain(events, &mut report);

        // 2. Verify sequence numbers
        Self::verify_sequences(events, &mut report);

        // 3. Verify individual event hashes
        Self::verify_event_hashes(events, &mut report);

        // 4. Verify Merkle tree consistency (no external commitment available)
        Self::verify_merkle_consistency(events, None, &mut report);

        // 5. Verify timestamp ordering
        Self::verify_timestamps(events, &mut report);

        report.verification_time_ms = start.elapsed().as_millis() as u64;

        Ok(report)
    }

    /// Perform integrity verification against a persisted, signed checkpoint.
    ///
    /// In addition to the standard checks, this:
    /// - validates the checkpoint's own integrity tag (under `checkpoint_key`),
    /// - detects tail truncation (live tip behind the checkpoint sequence), and
    /// - compares the recomputed Merkle root against the checkpoint root,
    ///   turning the previously no-op consistency check into a real
    ///   commitment comparison.
    pub fn verify_integrity_with_checkpoint(
        events: &[AuditEvent],
        checkpoint: &Checkpoint,
        checkpoint_key: Option<&[u8]>,
    ) -> Result<IntegrityReport, TamperDetectionError> {
        if events.is_empty() {
            return Err(TamperDetectionError::EmptyLog);
        }

        let start = std::time::Instant::now();
        let mut report = IntegrityReport::new();
        report.total_events = events.len();

        Self::verify_hash_chain(events, &mut report);
        Self::verify_sequences(events, &mut report);
        Self::verify_event_hashes(events, &mut report);

        // Tail-truncation guard. The live tip is the highest sequence present.
        let live_tip = events.last().map(|e| e.sequence).unwrap_or(0);
        if live_tip < checkpoint.sequence {
            report.add_violation(Violation::TailTruncated {
                checkpoint: checkpoint.sequence,
                live: live_tip,
            });
        }

        // Merkle consistency against the committed root. Only meaningful when
        // the event set covers exactly the checkpointed prefix; if the live
        // tip equals the checkpoint sequence the recomputed root MUST equal the
        // checkpoint root.
        let expected_root = if checkpoint.verify_integrity(checkpoint_key).is_err() {
            // A bad checkpoint tag is itself a violation; record it and do not
            // trust its root.
            report.add_violation(Violation::MerkleTreeInconsistent {
                expected: "<invalid checkpoint tag>".to_string(),
                actual: checkpoint.merkle_root.clone(),
            });
            None
        } else if live_tip == checkpoint.sequence {
            Some(checkpoint.merkle_root.as_str())
        } else {
            None
        };
        Self::verify_merkle_consistency(events, expected_root, &mut report);

        Self::verify_timestamps(events, &mut report);

        report.verification_time_ms = start.elapsed().as_millis() as u64;

        Ok(report)
    }

    /// Verify hash chain continuity
    fn verify_hash_chain(events: &[AuditEvent], report: &mut IntegrityReport) {
        let mut prev_hash = "0".repeat(64); // Genesis hash

        for event in events {
            if event.prev_hash != prev_hash {
                report.add_violation(Violation::HashChainBroken {
                    sequence: event.sequence,
                    expected: prev_hash.clone(),
                    actual: event.prev_hash.clone(),
                });
            }
            prev_hash = event.current_hash.clone();
        }
    }

    /// Verify sequence numbers are continuous and unique
    fn verify_sequences(events: &[AuditEvent], report: &mut IntegrityReport) {
        let mut seen_sequences = HashSet::new();
        let mut prev_sequence = 0u64;

        for event in events {
            // Check for duplicates
            if !seen_sequences.insert(event.sequence) {
                report.add_violation(Violation::DuplicateSequence {
                    sequence: event.sequence,
                });
            }

            // Check for gaps
            if prev_sequence > 0 && event.sequence != prev_sequence + 1 {
                report.add_violation(Violation::SequenceGap {
                    prev: prev_sequence,
                    next: event.sequence,
                });
            }

            prev_sequence = event.sequence;
        }
    }

    /// Verify each event's hash
    fn verify_event_hashes(events: &[AuditEvent], report: &mut IntegrityReport) {
        for event in events {
            let computed_hash = event.compute_hash();
            if computed_hash != event.current_hash {
                report.add_violation(Violation::HashMismatch {
                    sequence: event.sequence,
                    expected: event.current_hash.clone(),
                    actual: computed_hash,
                });
            }
        }
    }

    /// Verify Merkle tree consistency.
    ///
    /// Recomputes the Merkle root from the event hashes and, when an
    /// `expected_root` (e.g. from a signed checkpoint) is supplied, compares
    /// the recomputed root against it. Without an expected root the inclusion
    /// check alone is self-referential (the tree is built from the same
    /// hashes), so the comparison against an external commitment is what makes
    /// this a real tamper check — mirroring
    /// [`crate::verifier::AuditVerifier::verify_merkle_tree`].
    fn verify_merkle_consistency(
        events: &[AuditEvent],
        expected_root: Option<&str>,
        report: &mut IntegrityReport,
    ) {
        let hashes: Vec<String> = events.iter().map(|e| e.current_hash.clone()).collect();

        let tree = MerkleTree::from_hashes(hashes);

        if let Ok(root) = tree.get_root() {
            report.merkle_root = Some(root.clone());

            // Compare against an external commitment when available. A
            // mismatch means the committed prefix was altered (in-place
            // tampering of a middle entry that survived the per-event hash
            // check would still shift the root).
            if let Some(expected) = expected_root {
                if root != expected {
                    report.add_violation(Violation::MerkleTreeInconsistent {
                        expected: expected.to_string(),
                        actual: root.clone(),
                    });
                }
            }

            // Verify each event is in the tree
            for event in events {
                if !tree.verify_inclusion(&event.current_hash) {
                    report.add_violation(Violation::EventModified {
                        sequence: event.sequence,
                        details: "Event not found in Merkle tree".to_string(),
                    });
                }
            }
        }
    }

    /// Verify timestamps are monotonically increasing (within reason)
    fn verify_timestamps(events: &[AuditEvent], report: &mut IntegrityReport) {
        let mut prev_timestamp: Option<DateTime<Utc>> = None;

        for event in events {
            if let Some(prev_time) = prev_timestamp {
                // Timestamps should generally be increasing
                // Allow small backwards jumps due to clock skew (< 1 second)
                if event.timestamp < prev_time {
                    let diff = prev_time.signed_duration_since(event.timestamp);
                    if diff.num_seconds() > 1 {
                        report.add_violation(Violation::TimestampAnomaly {
                            sequence: event.sequence,
                            prev_time,
                            curr_time: event.timestamp,
                        });
                    }
                }
            }
            prev_timestamp = Some(event.timestamp);
        }
    }

    /// Quick verification (hash chain and sequences only)
    pub fn quick_verify(events: &[AuditEvent]) -> Result<bool, TamperDetectionError> {
        if events.is_empty() {
            return Err(TamperDetectionError::EmptyLog);
        }

        let mut prev_hash = "0".repeat(64);
        let mut prev_sequence = 0u64;

        for event in events {
            // Check hash chain
            if event.prev_hash != prev_hash {
                return Ok(false);
            }

            // Check event hash
            if !event.verify_hash() {
                return Ok(false);
            }

            // Check sequence continuity
            if prev_sequence > 0 && event.sequence != prev_sequence + 1 {
                return Ok(false);
            }

            prev_hash = event.current_hash.clone();
            prev_sequence = event.sequence;
        }

        Ok(true)
    }

    /// Verify a specific range of events
    pub fn verify_range(
        events: &[AuditEvent],
        from: u64,
        to: u64,
    ) -> Result<IntegrityReport, TamperDetectionError> {
        if from == 0 || to > events.len() as u64 || from > to {
            return Err(TamperDetectionError::IntegrityCheckFailed);
        }

        let range_events = &events[((from - 1) as usize)..(to as usize)];
        Self::verify_integrity(range_events)
    }

    /// Periodic integrity check (for long-running systems)
    pub fn periodic_check(events: &[AuditEvent]) -> IntegrityReport {
        match Self::verify_integrity(events) {
            Ok(report) => report,
            Err(_) => {
                let mut report = IntegrityReport::new();
                report.is_valid = false;
                report
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventType, OperationResult};
    use chrono::Utc;

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

    /// Compute the Merkle root over a chain's event hashes, matching the
    /// commitment the loggers persist in checkpoints.
    fn merkle_root_of(events: &[AuditEvent]) -> String {
        let hashes: Vec<String> = events.iter().map(|e| e.current_hash.clone()).collect();
        MerkleTree::from_hashes(hashes).get_root().unwrap()
    }

    /// Re-link a chain after a middle entry was mutated, so the chain is once
    /// again internally self-consistent (every per-event hash and prev_hash
    /// link is valid). This models a sophisticated attacker who rewrites an
    /// event and patches all downstream hashes — exactly the case a hash chain
    /// alone cannot catch but a committed Merkle root can.
    fn relink(events: &mut [AuditEvent]) {
        let mut prev_hash = "0".repeat(64);
        for e in events.iter_mut() {
            e.prev_hash = prev_hash.clone();
            e.current_hash = e.compute_hash();
            prev_hash = e.current_hash.clone();
        }
    }

    #[test]
    fn test_verify_valid_chain() {
        let events = create_event_chain(10);
        let report = TamperDetector::verify_integrity(&events).unwrap();

        assert_eq!(report.total_events, 10);
        assert_eq!(report.violation_count, 0);
        assert!(report.is_valid);
        assert!(report.merkle_root.is_some());
    }

    #[test]
    fn test_checkpoint_catches_mutated_middle_entry() {
        let key: &[u8] = b"checkpoint-key";
        let honest = create_event_chain(8);
        let honest_root = merkle_root_of(&honest);
        let checkpoint = Checkpoint::new(8, honest_root, Some(key));

        // Sanity: honest events verify clean against the checkpoint.
        let clean =
            TamperDetector::verify_integrity_with_checkpoint(&honest, &checkpoint, Some(key))
                .unwrap();
        assert!(
            clean.is_valid,
            "honest chain must pass: {:?}",
            clean.violations
        );

        // Attacker rewrites a MIDDLE event and re-links the whole chain so that
        // the hash chain is internally valid again. A plain hash-chain check
        // (or the old no-op Merkle check) would PASS this. The committed root
        // no longer matches, so the checkpoint comparison must catch it.
        let mut tampered = honest.clone();
        tampered[3].operation = "tampered".to_string();
        relink(&mut tampered);

        // The re-linked chain passes the plain hash-chain integrity check...
        let plain = TamperDetector::verify_integrity(&tampered).unwrap();
        assert!(
            plain.is_valid,
            "re-linked chain is internally consistent (demonstrates why a root commitment is needed)"
        );

        // ...but fails against the signed checkpoint root.
        let report =
            TamperDetector::verify_integrity_with_checkpoint(&tampered, &checkpoint, Some(key))
                .unwrap();
        assert!(!report.is_valid);
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v, Violation::MerkleTreeInconsistent { .. })));
    }

    #[test]
    fn test_checkpoint_catches_truncated_tail() {
        let key: &[u8] = b"checkpoint-key";
        let honest = create_event_chain(10);
        let honest_root = merkle_root_of(&honest);
        let checkpoint = Checkpoint::new(10, honest_root, Some(key));

        // Attacker deletes the last 3 events. The remaining 7-event prefix is a
        // perfectly valid hash chain, so verify_integrity alone passes.
        let truncated: Vec<AuditEvent> = honest[..7].to_vec();
        let plain = TamperDetector::verify_integrity(&truncated).unwrap();
        assert!(plain.is_valid, "truncated prefix is internally valid");

        // Against the checkpoint, the missing tail is detected.
        let report =
            TamperDetector::verify_integrity_with_checkpoint(&truncated, &checkpoint, Some(key))
                .unwrap();
        assert!(!report.is_valid);
        assert!(report.violations.iter().any(|v| matches!(
            v,
            Violation::TailTruncated {
                checkpoint: 10,
                live: 7
            }
        )));
    }

    #[test]
    fn test_checkpoint_with_wrong_key_is_flagged() {
        let honest = create_event_chain(5);
        let root = merkle_root_of(&honest);
        let checkpoint = Checkpoint::new(5, root, Some(b"real-key"));

        // Verifying with the wrong key: the checkpoint tag fails to validate,
        // so its root is not trusted and a violation is recorded.
        let report =
            TamperDetector::verify_integrity_with_checkpoint(&honest, &checkpoint, Some(b"wrong"))
                .unwrap();
        assert!(!report.is_valid);
    }

    #[test]
    fn test_detect_hash_chain_break() {
        let mut events = create_event_chain(5);

        // Break the chain
        events[2].prev_hash = "invalid_hash".to_string();

        let report = TamperDetector::verify_integrity(&events).unwrap();

        assert!(!report.is_valid);
        assert!(report.violation_count > 0);

        // Should detect the broken chain
        let has_chain_break = report
            .violations
            .iter()
            .any(|v| matches!(v, Violation::HashChainBroken { .. }));
        assert!(has_chain_break);
    }

    #[test]
    fn test_detect_hash_mismatch() {
        let mut events = create_event_chain(5);

        // Tamper with an event (change operation)
        events[2].operation = "tampered".to_string();

        let report = TamperDetector::verify_integrity(&events).unwrap();

        assert!(!report.is_valid);

        // Should detect hash mismatch
        let has_hash_mismatch = report
            .violations
            .iter()
            .any(|v| matches!(v, Violation::HashMismatch { .. }));
        assert!(has_hash_mismatch);
    }

    #[test]
    fn test_detect_sequence_gap() {
        let mut events = create_event_chain(5);

        // Create a gap in sequences
        events[3].sequence = 10;

        let report = TamperDetector::verify_integrity(&events).unwrap();

        assert!(!report.is_valid);

        // Should detect sequence gap
        let has_gap = report
            .violations
            .iter()
            .any(|v| matches!(v, Violation::SequenceGap { .. }));
        assert!(has_gap);
    }

    #[test]
    fn test_detect_duplicate_sequence() {
        let mut events = create_event_chain(5);

        // Create duplicate sequence
        events[3].sequence = events[2].sequence;

        let report = TamperDetector::verify_integrity(&events).unwrap();

        assert!(!report.is_valid);

        // Should detect duplicate
        let has_duplicate = report
            .violations
            .iter()
            .any(|v| matches!(v, Violation::DuplicateSequence { .. }));
        assert!(has_duplicate);
    }

    #[test]
    fn test_quick_verify() {
        let events = create_event_chain(10);
        assert!(TamperDetector::quick_verify(&events).unwrap());

        let mut tampered = create_event_chain(5);
        tampered[2].operation = "tampered".to_string();
        assert!(!TamperDetector::quick_verify(&tampered).unwrap());
    }

    #[test]
    fn test_verify_range() {
        let events = create_event_chain(20);

        // Verify range starting from event 1 (valid)
        let report = TamperDetector::verify_range(&events, 1, 15).unwrap();
        assert!(report.is_valid);
        assert_eq!(report.total_events, 15);
    }

    #[test]
    fn test_report_summary() {
        let mut events = create_event_chain(5);
        events[2].prev_hash = "invalid".to_string();

        let report = TamperDetector::verify_integrity(&events).unwrap();

        let summary = report.summary();
        assert!(summary.contains("INVALID"));
        assert!(summary.contains("Violations"));
    }

    #[test]
    fn test_periodic_check() {
        let events = create_event_chain(10);
        let report = TamperDetector::periodic_check(&events);

        assert!(report.is_valid);
        assert_eq!(report.violation_count, 0);
    }

    #[test]
    fn test_multiple_violations() {
        let mut events = create_event_chain(5);

        // Introduce multiple violations
        events[1].prev_hash = "wrong".to_string();
        events[2].operation = "tampered".to_string();
        events[3].sequence = 100;

        let report = TamperDetector::verify_integrity(&events).unwrap();

        assert!(!report.is_valid);
        assert!(report.violation_count >= 3);
    }
}
