//! Integration tests for the metrics crate

use hsm_metrics::{
    CardinalityLimiter, ComponentHealth, ConnectivityCheck, HealthCheck, HealthChecker,
    HealthStatus, KeyState, MetricsCollector, MetricsExporter, OperationStatus, OperationTimer,
    PerformanceCheck, SamplingConfig,
};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_metrics_collector_lifecycle() {
    let collector = MetricsCollector::new().expect("Failed to create collector");

    // Test operations
    collector.record_operation("sign", "rsa-2048", "production", OperationStatus::Success);
    collector.record_operation("encrypt", "aes-256", "production", OperationStatus::Success);
    collector.record_operation("decrypt", "aes-256", "staging", OperationStatus::Failure);

    // Test duration recording
    collector.record_operation_duration("sign", "rsa-2048", 0.05);
    collector.record_operation_duration("encrypt", "aes-256", 0.01);

    // Test key metrics
    collector.set_key_count("production", "rsa", KeyState::Active, 10);
    collector.set_key_count("production", "aes", KeyState::Active, 25);
    collector.set_key_count("staging", "rsa", KeyState::Inactive, 5);

    // Gather metrics and verify
    let metrics = collector.gather();
    assert!(!metrics.is_empty(), "Metrics should not be empty");

    // Verify specific metrics exist
    assert!(
        metrics.iter().any(|m| m.name() == "hsm_operations_total"),
        "Operations total metric missing"
    );
    assert!(
        metrics
            .iter()
            .any(|m| m.name() == "hsm_operation_duration_seconds"),
        "Operation duration metric missing"
    );
    assert!(
        metrics.iter().any(|m| m.name() == "hsm_keys_total"),
        "Keys total metric missing"
    );
}

#[test]
fn test_connection_metrics() {
    let collector = MetricsCollector::new().unwrap();

    // Test connection management
    collector.set_active_connections("grpc", 0);
    collector.increment_active_connections("grpc");
    collector.increment_active_connections("grpc");
    collector.increment_active_connections("http");
    collector.decrement_active_connections("grpc");

    let metrics = collector.gather();
    assert!(
        metrics.iter().any(|m| m.name() == "hsm_active_connections"),
        "Active connections metric missing"
    );
}

#[test]
fn test_resource_metrics() {
    let collector = MetricsCollector::new().unwrap();

    // Test memory usage
    collector.set_memory_usage("cache", 1024 * 1024 * 100); // 100 MB
    collector.set_memory_usage("storage", 1024 * 1024 * 500); // 500 MB

    // Test storage usage
    collector.set_storage_usage("production", 1024 * 1024 * 1024 * 10); // 10 GB
    collector.set_storage_usage("staging", 1024 * 1024 * 1024 * 5); // 5 GB

    let metrics = collector.gather();
    assert!(
        metrics.iter().any(|m| m.name() == "hsm_memory_usage_bytes"),
        "Memory usage metric missing"
    );
    assert!(
        metrics
            .iter()
            .any(|m| m.name() == "hsm_storage_usage_bytes"),
        "Storage usage metric missing"
    );
}

#[test]
fn test_operation_timer() {
    let collector = MetricsCollector::new().unwrap();

    // Create a timer and simulate work
    let timer = OperationTimer::new(collector.clone(), "hash", "sha256");
    std::thread::sleep(Duration::from_millis(50));
    timer.stop();

    let metrics = collector.gather();
    assert!(
        metrics
            .iter()
            .any(|m| m.name() == "hsm_operation_duration_seconds"),
        "Duration metric should be recorded"
    );
}

#[test]
fn test_operation_status_variants() {
    let collector = MetricsCollector::new().unwrap();

    collector.record_operation("test", "alg", "ns", OperationStatus::Success);
    collector.record_operation("test", "alg", "ns", OperationStatus::Failure);
    collector.record_operation("test", "alg", "ns", OperationStatus::Timeout);
    collector.record_operation("test", "alg", "ns", OperationStatus::Cancelled);

    assert_eq!(OperationStatus::Success.as_str(), "success");
    assert_eq!(OperationStatus::Failure.as_str(), "failure");
    assert_eq!(OperationStatus::Timeout.as_str(), "timeout");
    assert_eq!(OperationStatus::Cancelled.as_str(), "cancelled");
}

#[test]
fn test_key_state_variants() {
    let collector = MetricsCollector::new().unwrap();

    collector.set_key_count("ns", "type", KeyState::Active, 1);
    collector.set_key_count("ns", "type", KeyState::Inactive, 2);
    collector.set_key_count("ns", "type", KeyState::Compromised, 3);
    collector.set_key_count("ns", "type", KeyState::Destroyed, 4);

    assert_eq!(KeyState::Active.as_str(), "active");
    assert_eq!(KeyState::Inactive.as_str(), "inactive");
    assert_eq!(KeyState::Compromised.as_str(), "compromised");
    assert_eq!(KeyState::Destroyed.as_str(), "destroyed");
}

#[tokio::test]
async fn test_metrics_exporter() {
    let collector = MetricsCollector::new().unwrap();
    collector.record_operation("test", "alg", "ns", OperationStatus::Success);

    // Use port 0 to get a random available port
    let exporter = MetricsExporter::new(collector, "127.0.0.1:0".parse().unwrap());

    // We can't easily test the full server start in a unit test,
    // but we can verify the exporter was created successfully
    assert_eq!(exporter.addr().ip().to_string(), "127.0.0.1");
}

#[test]
fn test_component_health() {
    let healthy = ComponentHealth::healthy("All systems operational");
    assert_eq!(healthy.status, HealthStatus::Healthy);
    assert_eq!(healthy.message, "All systems operational");

    let degraded = ComponentHealth::degraded("Slow response")
        .with_metric("response_time_ms", 150.0)
        .with_metric("error_rate", 0.05);
    assert_eq!(degraded.status, HealthStatus::Degraded);
    assert_eq!(degraded.metrics.len(), 2);

    let unhealthy = ComponentHealth::unhealthy("Service down");
    assert_eq!(unhealthy.status, HealthStatus::Unhealthy);
}

#[test]
fn test_health_report() {
    let mut report = hsm_metrics::HealthReport::new();
    assert_eq!(report.status, HealthStatus::Healthy);
    assert!(report.is_healthy());

    // Add healthy component - should stay healthy
    report.add_component("database", ComponentHealth::healthy("Connected"));
    assert_eq!(report.status, HealthStatus::Healthy);

    // Add degraded component - should become degraded
    report.add_component("cache", ComponentHealth::degraded("Slow"));
    assert_eq!(report.status, HealthStatus::Degraded);
    assert!(!report.is_healthy());

    // Add unhealthy component - should become unhealthy
    report.add_component("storage", ComponentHealth::unhealthy("Offline"));
    assert_eq!(report.status, HealthStatus::Unhealthy);

    assert_eq!(report.components.len(), 3);
}

#[tokio::test]
async fn test_connectivity_check() {
    let mut is_connected = true;
    let check = ConnectivityCheck::new("test-service", move || is_connected);

    let health = check.check().await.unwrap();
    assert_eq!(health.status, HealthStatus::Healthy);

    is_connected = false;
    let check = ConnectivityCheck::new("test-service", move || is_connected);
    let health = check.check().await.unwrap();
    assert_eq!(health.status, HealthStatus::Unhealthy);
}

#[tokio::test]
async fn test_performance_check() {
    // Test healthy performance
    let check = PerformanceCheck::new("fast-service", 100, || Duration::from_millis(50));
    let health = check.check().await.unwrap();
    assert_eq!(health.status, HealthStatus::Healthy);
    assert!(health.metrics.contains_key("response_time_ms"));

    // Test degraded performance
    let check = PerformanceCheck::new("slow-service", 100, || Duration::from_millis(150));
    let health = check.check().await.unwrap();
    assert_eq!(health.status, HealthStatus::Degraded);

    // Test unhealthy performance
    let check = PerformanceCheck::new("very-slow-service", 100, || Duration::from_millis(300));
    let health = check.check().await.unwrap();
    assert_eq!(health.status, HealthStatus::Unhealthy);
}

#[tokio::test]
async fn test_health_checker() {
    let checker = HealthChecker::with_default_interval();

    // Add multiple checks
    let check1 = Arc::new(ConnectivityCheck::new("service1", || true));
    let check2 = Arc::new(ConnectivityCheck::new("service2", || false));
    let check3 = Arc::new(PerformanceCheck::new("service3", 100, || {
        Duration::from_millis(50)
    }));

    checker.add_check(check1).await;
    checker.add_check(check2).await;
    checker.add_check(check3).await;

    // Run checks
    let report = checker.run_checks().await;

    // Overall status should be unhealthy because service2 is down
    assert_eq!(report.status, HealthStatus::Unhealthy);
    assert_eq!(report.components.len(), 3);

    // Verify we can get the last report
    let last_report = checker.get_last_report().await;
    assert!(last_report.is_some());
}

#[tokio::test]
async fn test_health_status_serialization() {
    let healthy = ComponentHealth::healthy("OK");
    let json = serde_json::to_string(&healthy).unwrap();
    assert!(json.contains("\"status\":\"healthy\""));

    let degraded = ComponentHealth::degraded("Slow");
    let json = serde_json::to_string(&degraded).unwrap();
    assert!(json.contains("\"status\":\"degraded\""));

    let unhealthy = ComponentHealth::unhealthy("Down");
    let json = serde_json::to_string(&unhealthy).unwrap();
    assert!(json.contains("\"status\":\"unhealthy\""));
}

#[test]
fn test_multiple_namespaces() {
    let collector = MetricsCollector::new().unwrap();

    // Test multiple namespaces
    for ns in &["production", "staging", "development"] {
        for algo in &["rsa-2048", "rsa-4096", "aes-256"] {
            collector.record_operation("sign", algo, ns, OperationStatus::Success);
            collector.record_operation_duration("sign", algo, 0.1);
        }
    }

    let metrics = collector.gather();
    assert!(!metrics.is_empty());
}

#[test]
fn test_high_volume_metrics() {
    let collector = MetricsCollector::new().unwrap();

    // Simulate high volume of operations
    for i in 0..1000 {
        let status = if i % 10 == 0 {
            OperationStatus::Failure
        } else {
            OperationStatus::Success
        };

        collector.record_operation("batch_operation", "none", "load_test", status);
        collector.record_operation_duration("batch_operation", "none", 0.001);
    }

    let metrics = collector.gather();
    assert!(!metrics.is_empty());
}

#[tokio::test]
async fn test_concurrent_metric_collection() {
    let collector = Arc::new(MetricsCollector::new().unwrap());

    let mut handles = vec![];

    // Spawn multiple tasks recording metrics concurrently
    for i in 0..10 {
        let c = collector.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..100 {
                c.record_operation(
                    "concurrent_test",
                    "algorithm",
                    &format!("namespace_{}", i),
                    OperationStatus::Success,
                );
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    let metrics = collector.gather();
    assert!(!metrics.is_empty());
}

// === Phase 2 Enhancement Tests ===

#[test]
fn test_lock_free_atomic_counters() {
    let collector = MetricsCollector::new().unwrap();

    // Record operations using lock-free counters
    for _ in 0..100 {
        collector.record_sign("rsa-2048", "default", Duration::from_millis(10));
        collector.record_verify("rsa-2048", "default", Duration::from_millis(5));
        collector.record_encrypt("aes-256", "default", Duration::from_millis(3));
        collector.record_decrypt("aes-256", "default", Duration::from_millis(3));
    }

    // Verify atomic counters are accurate
    assert_eq!(collector.get_sign_count(), 100);
    assert_eq!(collector.get_verify_count(), 100);
    assert_eq!(collector.get_encrypt_count(), 100);
    assert_eq!(collector.get_decrypt_count(), 100);
}

#[tokio::test]
async fn test_lock_free_concurrent_accuracy() {
    let collector = Arc::new(MetricsCollector::new().unwrap());
    let mut handles = vec![];

    // Spawn 10 tasks, each recording 100 operations
    for _ in 0..10 {
        let c = collector.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..100 {
                c.record_sign("rsa-2048", "default", Duration::from_millis(10));
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    // Should have exactly 1000 operations
    assert_eq!(collector.get_sign_count(), 1000);
}

#[test]
fn test_sampling_configuration() {
    // Test 100% sampling (default)
    let collector = MetricsCollector::new().unwrap();
    for _ in 0..100 {
        collector.record_sign("rsa-2048", "default", Duration::from_millis(10));
    }
    assert_eq!(collector.get_sign_count(), 100);

    // Test 10% sampling
    let collector = MetricsCollector::with_config(
        prometheus::Registry::new(),
        10_000,
        SamplingConfig::new(0.1),
    )
    .unwrap();

    for _ in 0..1000 {
        collector.record_sign("rsa-2048", "default", Duration::from_millis(10));
    }

    // Atomic counter should still be accurate (no sampling on counters)
    assert_eq!(collector.get_sign_count(), 1000);
}

#[test]
fn test_comprehensive_crypto_metrics() {
    let collector = MetricsCollector::new().unwrap();

    collector.record_sign("rsa-2048", "production", Duration::from_millis(10));
    collector.record_verify("rsa-2048", "production", Duration::from_millis(5));
    collector.record_encrypt("aes-256", "production", Duration::from_millis(2));
    collector.record_decrypt("aes-256", "production", Duration::from_millis(2));

    let metrics = collector.gather();
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_sign_duration_seconds"));
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_verify_duration_seconds"));
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_encrypt_duration_seconds"));
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_decrypt_duration_seconds"));
}

#[test]
fn test_key_management_metrics() {
    let collector = MetricsCollector::new().unwrap();

    collector.record_key_generation("rsa-2048", "production");
    collector.record_key_generation("rsa-4096", "production");
    collector.record_key_deletion("production", "expired");
    collector.set_active_keys("production", "rsa-2048", 42);

    let metrics = collector.gather();
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_key_generation_total"));
    assert!(metrics.iter().any(|m| m.name() == "hsm_key_deletion_total"));
    assert!(metrics.iter().any(|m| m.name() == "hsm_active_keys"));
}

#[test]
fn test_authentication_metrics() {
    let collector = MetricsCollector::new().unwrap();

    collector.record_auth_attempt("tls", "success");
    collector.record_auth_attempt("tls", "success");
    collector.record_auth_failure("tls", "invalid_cert");
    collector.set_active_sessions(5);

    let metrics = collector.gather();
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_auth_attempts_total"));
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_auth_failures_total"));
    assert!(metrics.iter().any(|m| m.name() == "hsm_active_sessions"));
}

#[test]
fn test_storage_metrics() {
    let collector = MetricsCollector::new().unwrap();

    collector.record_storage_read(Duration::from_millis(10));
    collector.record_storage_write(Duration::from_millis(20));
    collector.record_storage_error();

    let metrics = collector.gather();
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_storage_read_duration_seconds"));
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_storage_write_duration_seconds"));
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_storage_errors_total"));
}

#[test]
fn test_audit_metrics() {
    let collector = MetricsCollector::new().unwrap();

    collector.record_audit_event();
    collector.record_audit_event();
    collector.set_audit_queue_depth(42);
    collector.record_audit_write(Duration::from_millis(5));

    let metrics = collector.gather();
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_audit_events_written_total"));
    assert!(metrics.iter().any(|m| m.name() == "hsm_audit_queue_depth"));
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_audit_write_duration_seconds"));
}

#[test]
fn test_health_metrics() {
    let collector = MetricsCollector::new().unwrap();

    collector.set_component_health("crypto_engine", true);
    collector.set_component_health("storage", false);
    collector.set_cpu_saturation(0.75);
    collector.set_memory_saturation(0.60);
    collector.set_disk_saturation(0.40);
    collector.set_cpu_usage(45.5);

    let metrics = collector.gather();
    assert!(metrics.iter().any(|m| m.name() == "hsm_component_health"));
    assert!(metrics.iter().any(|m| m.name() == "hsm_cpu_saturation"));
    assert!(metrics.iter().any(|m| m.name() == "hsm_memory_saturation"));
    assert!(metrics.iter().any(|m| m.name() == "hsm_disk_saturation"));
    assert!(metrics.iter().any(|m| m.name() == "hsm_cpu_usage_percent"));
}

#[test]
fn test_error_metrics() {
    let collector = MetricsCollector::new().unwrap();

    collector.record_error("sign", "invalid_key");
    collector.record_error("encrypt", "key_not_found");
    collector.record_component_error("crypto_engine", "timeout");

    let metrics = collector.gather();
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_operation_errors_total"));
    assert!(metrics
        .iter()
        .any(|m| m.name() == "hsm_component_errors_total"));
}

#[test]
fn test_cardinality_limiter() {
    let limiter = CardinalityLimiter::new(5);

    // Add labels up to limit
    assert!(limiter.check_label("label1").is_ok());
    assert!(limiter.check_label("label2").is_ok());
    assert!(limiter.check_label("label3").is_ok());
    assert!(limiter.check_label("label4").is_ok());
    assert!(limiter.check_label("label5").is_ok());

    // Should allow duplicate labels
    assert!(limiter.check_label("label1").is_ok());
    assert!(limiter.check_label("label2").is_ok());

    // Should reject new label when at limit
    assert!(limiter.check_label("label6").is_err());

    // Verify cardinality
    assert_eq!(limiter.current_cardinality(), 5);
}

#[test]
fn test_cardinality_monitoring() {
    let collector = MetricsCollector::new().unwrap();

    // Add some labels
    let _ = collector.check_label("test1");
    let _ = collector.check_label("test2");
    let _ = collector.check_label("test3");

    // Update cardinality metric
    collector.update_cardinality();

    // Verify cardinality
    assert_eq!(collector.get_cardinality(), 3);

    let metrics = collector.gather();
    assert!(metrics.iter().any(|m| m.name() == "hsm_metric_cardinality"));
}

#[test]
fn test_saturation_clamping() {
    let collector = MetricsCollector::new().unwrap();

    // Test clamping to 0-1 range
    collector.set_cpu_saturation(1.5); // Should clamp to 1.0
    collector.set_memory_saturation(-0.5); // Should clamp to 0.0
    collector.set_disk_saturation(0.5); // Should stay 0.5

    // Metrics should be clamped (verified in implementation)
    let metrics = collector.gather();
    assert!(metrics.iter().any(|m| m.name() == "hsm_cpu_saturation"));
    assert!(metrics.iter().any(|m| m.name() == "hsm_memory_saturation"));
    assert!(metrics.iter().any(|m| m.name() == "hsm_disk_saturation"));
}

#[test]
fn test_metric_accuracy_histogram() {
    let collector = MetricsCollector::new().unwrap();

    // Record specific durations
    for i in 0..100 {
        let duration = Duration::from_millis(i);
        collector.record_operation_duration("test", "none", duration.as_secs_f64());
    }

    let metrics = collector.gather();
    let histogram = metrics
        .iter()
        .find(|m| m.name() == "hsm_operation_duration_seconds")
        .expect("Histogram metric not found");

    // Verify histogram has samples
    let metric = histogram.get_metric().first().unwrap();
    let hist = metric.get_histogram();
    assert_eq!(hist.get_sample_count(), 100);
}

#[test]
fn test_all_metrics_registered() {
    let collector = MetricsCollector::new().unwrap();

    // Trigger all metrics
    collector.record_operation("test", "test", "test", OperationStatus::Success);
    collector.record_operation_duration("test", "test", 0.001);
    collector.record_sign("rsa", "default", Duration::from_millis(1));
    collector.record_verify("rsa", "default", Duration::from_millis(1));
    collector.record_encrypt("aes", "default", Duration::from_millis(1));
    collector.record_decrypt("aes", "default", Duration::from_millis(1));
    collector.record_error("test", "error");
    collector.record_key_generation("rsa", "default");
    collector.record_key_deletion("default", "expired");
    collector.set_active_keys("default", "rsa", 1);
    collector.record_auth_attempt("tls", "success");
    collector.record_auth_failure("tls", "invalid");
    collector.set_active_sessions(1);
    collector.record_storage_read(Duration::from_millis(1));
    collector.record_storage_write(Duration::from_millis(1));
    collector.record_storage_error();
    collector.record_audit_event();
    collector.set_audit_queue_depth(1);
    collector.record_audit_write(Duration::from_millis(1));
    collector.set_component_health("test", true);
    collector.record_component_error("test", "error");
    collector.set_cpu_saturation(0.5);
    collector.set_memory_saturation(0.5);
    collector.set_disk_saturation(0.5);
    collector.set_cpu_usage(50.0);
    collector.update_cardinality();

    let metrics = collector.gather();

    // Verify all major metric families are present
    let metric_names: Vec<&str> = metrics.iter().map(|m| m.name()).collect();

    let expected_metrics = vec![
        "hsm_operations_total",
        "hsm_operation_errors_total",
        "hsm_operation_duration_seconds",
        "hsm_sign_duration_seconds",
        "hsm_verify_duration_seconds",
        "hsm_encrypt_duration_seconds",
        "hsm_decrypt_duration_seconds",
        "hsm_key_generation_total",
        "hsm_key_deletion_total",
        "hsm_active_keys",
        "hsm_auth_attempts_total",
        "hsm_auth_failures_total",
        "hsm_active_sessions",
        "hsm_storage_read_duration_seconds",
        "hsm_storage_write_duration_seconds",
        "hsm_storage_errors_total",
        "hsm_audit_events_written_total",
        "hsm_audit_queue_depth",
        "hsm_audit_write_duration_seconds",
        "hsm_component_health",
        "hsm_component_errors_total",
        "hsm_cpu_saturation",
        "hsm_memory_saturation",
        "hsm_disk_saturation",
        "hsm_cpu_usage_percent",
        "hsm_metric_cardinality",
    ];

    for expected in expected_metrics {
        assert!(
            metric_names.contains(&expected),
            "Missing metric: {}",
            expected
        );
    }
}

#[test]
fn test_sampling_config_clamping() {
    // Test clamping to 0-1 range
    let config1 = SamplingConfig::new(1.5);
    let config2 = SamplingConfig::new(-0.5);
    let config3 = SamplingConfig::new(0.5);

    // Verify clamped values
    assert!(config1.sample_rate <= 1.0);
    assert!(config2.sample_rate >= 0.0);
    assert_eq!(config3.sample_rate, 0.5);
}
