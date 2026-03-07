#![deny(unsafe_code)]
//! # HSM Metrics & Monitoring
//!
//! This crate provides comprehensive Prometheus metrics collection and health
//! monitoring for HSM operations, enabling observability and alerting.
//!
//! ## Features
//!
//! - **Prometheus Metrics**: Operations, latency histograms, key counts, error rates
//! - **HTTP Exporter**: `/metrics` endpoint for Prometheus scraping
//! - **Health Checks**: Component-level health status and connectivity monitoring
//! - **Cardinality Control**: Prevent metric explosion with label limiting
//! - **Sampling**: Reduce overhead for high-volume metrics
//!
//! ## Exposed Metrics
//!
//! | Metric Name | Type | Labels | Description |
//! |-------------|------|--------|-------------|
//! | `hsm_operations_total` | Counter | operation, algorithm, namespace, status | Total operations performed |
//! | `hsm_operation_duration_seconds` | Histogram | operation, algorithm | Operation latency distribution |
//! | `hsm_keys_total` | Gauge | algorithm, namespace, state | Current key count by state |
//! | `hsm_errors_total` | Counter | error_type, operation | Error counts by type |
//! | `hsm_sessions_active` | Gauge | namespace | Currently active sessions |
//! | `hsm_cache_hits_total` | Counter | cache_type | Cache hit count |
//! | `hsm_cache_misses_total` | Counter | cache_type | Cache miss count |
//! | `hsm_backup_last_success_timestamp` | Gauge | namespace | Unix timestamp of last successful backup |
//!
//! ## Quick Start
//!
//! ```no_run
//! use metrics::{MetricsCollector, MetricsExporter, OperationStatus};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create a metrics collector
//!     let collector = MetricsCollector::new().unwrap();
//!
//!     // Record cryptographic operations
//!     collector.record_operation("sign", "ed25519", "production", OperationStatus::Success);
//!     collector.record_operation_duration("sign", "ed25519", 0.00085); // 850μs
//!
//!     // Start the HTTP exporter on :9090/metrics
//!     let exporter = MetricsExporter::with_default_addr(collector);
//!     exporter.start().await.unwrap();
//! }
//! ```
//!
//! ## Recording Metrics
//!
//! ### Operation Timing with RAII Guard
//!
//! ```rust,ignore
//! use metrics::{MetricsCollector, OperationTimer};
//!
//! fn sign_message(collector: &MetricsCollector, message: &[u8]) -> Result<Vec<u8>, Error> {
//!     // Timer automatically records duration when dropped
//!     let _timer = OperationTimer::new(collector, "sign", "ed25519");
//!
//!     // ... perform signing operation ...
//!
//!     // Duration recorded automatically on drop
//! }
//! ```
//!
//! ### Key State Tracking
//!
//! ```rust,ignore
//! use metrics::{MetricsCollector, KeyState};
//!
//! // Track key lifecycle
//! collector.set_key_count("ed25519", "production", KeyState::Active, 150);
//! collector.set_key_count("ed25519", "production", KeyState::Inactive, 45);
//! collector.set_key_count("rsa-2048", "production", KeyState::Active, 20);
//! ```
//!
//! ### Error Recording
//!
//! ```rust,ignore
//! use metrics::MetricsCollector;
//!
//! // Record errors for alerting
//! collector.record_error("key_not_found", "sign");
//! collector.record_error("permission_denied", "decrypt");
//! collector.record_error("rate_limited", "encrypt");
//! ```
//!
//! ## Cardinality Limiting
//!
//! Prevent metric explosion from unbounded label values:
//!
//! ```rust,ignore
//! use metrics::{MetricsCollector, CardinalityLimiter};
//!
//! // Limit namespace cardinality to prevent abuse
//! let limiter = CardinalityLimiter::new()
//!     .with_max_namespaces(100)
//!     .with_max_key_ids(1000)
//!     .with_overflow_label("_other_");
//!
//! let collector = MetricsCollector::with_limiter(limiter).unwrap();
//! ```
//!
//! ## Health Checks
//!
//! Monitor component health for orchestration systems:
//!
//! ```rust,ignore
//! use metrics::{HealthChecker, HealthStatus, ComponentHealth};
//!
//! let health_checker = HealthChecker::new();
//!
//! // Register component health checks
//! health_checker.register("storage", || {
//!     // Check storage connectivity
//!     if storage.ping().is_ok() {
//!         ComponentHealth::healthy()
//!     } else {
//!         ComponentHealth::unhealthy("Storage unavailable")
//!     }
//! });
//!
//! health_checker.register("grpc", || {
//!     ComponentHealth::healthy()
//! });
//!
//! // Get overall health report
//! let report = health_checker.check_all();
//! match report.status {
//!     HealthStatus::Healthy => println!("All systems operational"),
//!     HealthStatus::Degraded => println!("Some components degraded"),
//!     HealthStatus::Unhealthy => println!("System unhealthy!"),
//! }
//! ```
//!
//! ## Prometheus Integration
//!
//! Example Prometheus scrape configuration:
//!
//! ```yaml
//! scrape_configs:
//!   - job_name: 'hsm'
//!     static_configs:
//!       - targets: ['hsm:9090']
//!     scrape_interval: 15s
//!     metrics_path: /metrics
//! ```
//!
//! ## Example Alerting Rules
//!
//! ```yaml
//! groups:
//!   - name: hsm-alerts
//!     rules:
//!       - alert: HSMHighErrorRate
//!         expr: rate(hsm_errors_total[5m]) > 0.01
//!         for: 5m
//!         labels:
//!           severity: warning
//!         annotations:
//!           summary: "High HSM error rate"
//!
//!       - alert: HSMSlowOperations
//!         expr: histogram_quantile(0.99, rate(hsm_operation_duration_seconds_bucket[5m])) > 0.1
//!         for: 5m
//!         labels:
//!           severity: warning
//!         annotations:
//!           summary: "HSM P99 latency above 100ms"
//! ```
//!
//! ## Performance Characteristics
//!
//! - **Metric Recording**: <10μs per operation
//! - **Memory Overhead**: ~1KB per unique label combination
//! - **Export Latency**: <50ms for 10,000 metric series

pub mod collector;
pub mod exporter;
pub mod health;

// Re-export main types for convenience
pub use collector::{
    CardinalityLimiter, KeyState, MetricsCollector, MetricsError, OperationStatus, OperationTimer,
    SamplingConfig,
};
pub use exporter::{ExporterError, MetricsExporter};
pub use health::{
    ComponentHealth, ConnectivityCheck, HealthCheck, HealthCheckError, HealthChecker, HealthReport,
    HealthStatus, PerformanceCheck,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify that main types are accessible
        let collector = MetricsCollector::new().unwrap();
        let _exporter = MetricsExporter::with_default_addr(collector);
    }
}
