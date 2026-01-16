//! HSM Metrics & Monitoring
//!
//! This crate provides comprehensive metrics collection and monitoring for HSM operations.
//! It includes:
//! - Prometheus metrics collection for operations, latency, keys, and system resources
//! - HTTP exporter for Prometheus scraping
//! - Health check system for monitoring component health
//! - Grafana dashboard for visualization
//!
//! # Examples
//!
//! ```no_run
//! use metrics::{MetricsCollector, MetricsExporter, OperationStatus};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create a metrics collector
//!     let collector = MetricsCollector::new().unwrap();
//!
//!     // Record some operations
//!     collector.record_operation("sign", "rsa", "default", OperationStatus::Success);
//!     collector.record_operation_duration("sign", "rsa", 0.123);
//!
//!     // Start the metrics exporter
//!     let exporter = MetricsExporter::with_default_addr(collector);
//!     exporter.start().await.unwrap();
//! }
//! ```

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
