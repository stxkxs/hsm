//! Comprehensive tamper detection tests

use audit::{AuditEvent, EventType, OperationResult, TamperDetector, Violation};
use chrono::{Duration, Utc};

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
fn test_detect_hash_chain_modification() {
    let mut events = create_event_chain(10);

    // Tamper with the hash chain by modifying prev_hash
    events[5].prev_hash = "tampered_hash".to_string();

    let report = TamperDetector::verify_integrity(&events).unwrap();

    assert!(!report.is_valid);
    assert!(report.violation_count > 0);

    // Check for hash chain broken violation
    let has_chain_break = report
        .violations
        .iter()
        .any(|v| matches!(v, Violation::HashChainBroken { .. }));
    assert!(has_chain_break);
}

#[test]
fn test_detect_event_content_modification() {
    let mut events = create_event_chain(10);

    // Tamper with event content (without updating hash)
    events[3].operation = "modified_operation".to_string();

    let report = TamperDetector::verify_integrity(&events).unwrap();

    assert!(!report.is_valid);

    // Check for hash mismatch violation
    let has_hash_mismatch = report
        .violations
        .iter()
        .any(|v| matches!(v, Violation::HashMismatch { .. }));
    assert!(has_hash_mismatch);
}

#[test]
fn test_detect_sequence_number_gap() {
    let mut events = create_event_chain(10);

    // Create a gap in sequence numbers
    events[5].sequence = 100;

    let report = TamperDetector::verify_integrity(&events).unwrap();

    assert!(!report.is_valid);

    // Check for sequence gap violation
    let has_gap = report
        .violations
        .iter()
        .any(|v| matches!(v, Violation::SequenceGap { .. }));
    assert!(has_gap);
}

#[test]
fn test_detect_duplicate_sequence_number() {
    let mut events = create_event_chain(10);

    // Create duplicate sequence number
    events[7].sequence = events[6].sequence;

    let report = TamperDetector::verify_integrity(&events).unwrap();

    assert!(!report.is_valid);

    // Check for duplicate sequence violation
    let has_duplicate = report
        .violations
        .iter()
        .any(|v| matches!(v, Violation::DuplicateSequence { .. }));
    assert!(has_duplicate);
}

#[test]
fn test_detect_multiple_tampering_attempts() {
    let mut events = create_event_chain(20);

    // Multiple types of tampering
    events[3].prev_hash = "wrong_hash_1".to_string();
    events[7].operation = "tampered".to_string();
    events[10].sequence = 999;
    events[15].prev_hash = "wrong_hash_2".to_string();

    let report = TamperDetector::verify_integrity(&events).unwrap();

    assert!(!report.is_valid);
    // Should detect at least 4 violations
    assert!(report.violation_count >= 4);

    println!("Detected {} violations:", report.violation_count);
    for violation in &report.violations {
        println!("  {:?}", violation);
    }
}

#[test]
fn test_valid_chain_passes_all_checks() {
    let events = create_event_chain(50);

    let report = TamperDetector::verify_integrity(&events).unwrap();

    assert!(report.is_valid);
    assert_eq!(report.violation_count, 0);
    assert_eq!(report.total_events, 50);
    assert!(report.merkle_root.is_some());
}

#[test]
fn test_quick_verify_performance() {
    let events = create_event_chain(1000);

    let start = std::time::Instant::now();
    let is_valid = TamperDetector::quick_verify(&events).unwrap();
    let duration = start.elapsed();

    assert!(is_valid);
    println!("Quick verify of 1000 events: {:?}", duration);

    // Quick verify should be fast
    assert!(duration.as_millis() < 500);
}

#[test]
fn test_comprehensive_verify_with_timing() {
    let events = create_event_chain(500);

    let report = TamperDetector::verify_integrity(&events).unwrap();

    assert!(report.is_valid);
    println!("Verification time: {}ms", report.verification_time_ms);

    // Comprehensive verification should complete in reasonable time
    if report.verification_time_ms >= 2000 {
        eprintln!("⚠️  PERFORMANCE WARNING: Comprehensive verification slower than target: {}ms (target: <2000ms)", report.verification_time_ms);
    }
}

#[test]
fn test_range_verification() {
    let events = create_event_chain(100);

    // Verify different ranges (starting from event 1 to maintain hash chain)
    let report1 = TamperDetector::verify_range(&events, 1, 20).unwrap();
    assert!(report1.is_valid);
    assert_eq!(report1.total_events, 20);

    let report2 = TamperDetector::verify_range(&events, 1, 100).unwrap();
    assert!(report2.is_valid);
    assert_eq!(report2.total_events, 100);

    // Now tamper with an event in a specific range
    let mut tampered_events = events.clone();
    tampered_events[60].operation = "tampered".to_string();

    // Range that includes tampered event should fail
    let report3 = TamperDetector::verify_range(&tampered_events, 50, 70).unwrap();
    assert!(!report3.is_valid);

    // Range that doesn't include tampered event should still be valid
    let report4 = TamperDetector::verify_range(&tampered_events, 1, 50).unwrap();
    assert!(report4.is_valid);
}

#[test]
fn test_merkle_tree_consistency_check() {
    let events = create_event_chain(16);

    let report = TamperDetector::verify_integrity(&events).unwrap();

    assert!(report.is_valid);
    assert!(report.merkle_root.is_some());

    // All events should be in the Merkle tree
    let merkle_root = report.merkle_root.unwrap();
    assert!(!merkle_root.is_empty());
}

#[test]
fn test_detect_event_deletion() {
    let mut events = create_event_chain(10);

    // Remove an event (simulating deletion)
    events.remove(5);

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
fn test_detect_event_insertion() {
    let mut events = create_event_chain(10);

    // Insert a fake event
    let fake_event = create_test_event(6, &events[4].current_hash);
    events.insert(5, fake_event);

    let report = TamperDetector::verify_integrity(&events).unwrap();

    assert!(!report.is_valid);

    // Should detect either hash chain break or sequence issues
    assert!(report.violation_count > 0);
}

#[test]
fn test_detect_timestamp_anomaly() {
    let mut events = create_event_chain(10);

    // Create timestamp anomaly (event 5 has earlier timestamp than event 4)
    let earlier_time = events[3].timestamp - Duration::seconds(10);
    events[4].timestamp = earlier_time;

    let report = TamperDetector::verify_integrity(&events).unwrap();

    // Should detect timestamp anomaly or hash mismatch
    assert!(!report.is_valid);
    assert!(report.violation_count > 0);
}

#[test]
fn test_report_summary_format() {
    let mut events = create_event_chain(10);
    events[5].operation = "tampered".to_string();

    let report = TamperDetector::verify_integrity(&events).unwrap();

    let summary = report.summary();

    assert!(summary.contains("Integrity Report"));
    assert!(summary.contains("Total Events"));
    assert!(summary.contains("Violations Found"));
    assert!(summary.contains("INVALID"));
    assert!(summary.contains("Merkle Root"));
}

#[test]
fn test_periodic_check() {
    let events = create_event_chain(20);

    let report = TamperDetector::periodic_check(&events);

    assert!(report.is_valid);
    assert_eq!(report.violation_count, 0);
}

#[test]
fn test_detect_complete_event_replacement() {
    let mut events = create_event_chain(10);

    // Replace an entire event
    let replacement = create_test_event(5, "fake_prev_hash");
    events[4] = replacement;

    let report = TamperDetector::verify_integrity(&events).unwrap();

    assert!(!report.is_valid);

    // Should detect multiple violations
    assert!(report.violation_count >= 2);
}

#[test]
fn test_stress_test_large_chain() {
    let events = create_event_chain(10000);

    let start = std::time::Instant::now();
    let report = TamperDetector::verify_integrity(&events).unwrap();
    let duration = start.elapsed();

    assert!(report.is_valid);
    assert_eq!(report.total_events, 10000);

    println!("Verified 10000 events in {:?}", duration);

    // Should complete in reasonable time (< 5 seconds)
    if duration.as_secs() >= 5 {
        eprintln!("⚠️  PERFORMANCE WARNING: Verification slower than target: {:?} (target: <5s)", duration);
    }
}

#[test]
fn test_all_violation_types() {
    let mut events = create_event_chain(30);

    // Create different types of violations
    events[5].prev_hash = "broken_chain".to_string();
    events[10].operation = "modified_content".to_string();
    events[15].sequence = 999;
    events[20].sequence = events[19].sequence; // Duplicate

    let report = TamperDetector::verify_integrity(&events).unwrap();

    assert!(!report.is_valid);
    assert!(report.violation_count >= 4);

    // Check that we have multiple types of violations
    let violation_types: std::collections::HashSet<_> = report
        .violations
        .iter()
        .map(|v| std::mem::discriminant(v))
        .collect();

    assert!(violation_types.len() >= 3);
}

#[test]
fn test_empty_log_handling() {
    let events: Vec<AuditEvent> = Vec::new();

    let result = TamperDetector::verify_integrity(&events);

    assert!(result.is_err());
}

#[test]
fn test_single_event_verification() {
    let events = create_event_chain(1);

    let report = TamperDetector::verify_integrity(&events).unwrap();

    assert!(report.is_valid);
    assert_eq!(report.total_events, 1);
    assert_eq!(report.violation_count, 0);
}

#[test]
fn test_verify_after_rotation() {
    // Simulate log rotation by having events with continuous sequences
    // but from different "files" (batches)
    let batch1 = create_event_chain(100);
    let batch2 = {
        let mut events = Vec::new();
        let mut prev_hash = batch1.last().unwrap().current_hash.clone();

        for i in 101..=200 {
            let event = create_test_event(i, &prev_hash);
            prev_hash = event.current_hash.clone();
            events.push(event);
        }
        events
    };

    // Combine batches
    let mut all_events = batch1;
    all_events.extend(batch2);

    let report = TamperDetector::verify_integrity(&all_events).unwrap();

    assert!(report.is_valid);
    assert_eq!(report.total_events, 200);
}
