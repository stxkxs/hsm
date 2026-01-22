use audit::{AuditEvent, EventType, OperationResult, TamperDetector};
use chrono::Utc;

#[test]
fn test_timing_breakdown() {
    println!("Starting timing test...");

    // Create events
    let start = std::time::Instant::now();
    let mut events = Vec::new();
    let mut prev_hash = "0".repeat(64);

    for i in 1..=1000 {
        // Start with 1000
        let event = AuditEvent::builder()
            .sequence(i)
            .event_type(EventType::Sign)
            .operation("test_op")
            .namespace("test")
            .client_id("client_1")
            .result(OperationResult::Success)
            .timestamp(Utc::now())
            .prev_hash(&prev_hash)
            .build()
            .unwrap();
        prev_hash = event.current_hash.clone();
        events.push(event);
    }
    let creation_time = start.elapsed();
    println!("Created 1000 events in {:?}", creation_time);

    // Verify
    let start = std::time::Instant::now();
    let report = TamperDetector::verify_integrity(&events).unwrap();
    let verify_time = start.elapsed();

    println!(
        "Verified {} events in {:?}",
        report.total_events, verify_time
    );
    assert!(report.is_valid);
}
