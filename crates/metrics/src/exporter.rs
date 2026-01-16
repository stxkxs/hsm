//! Prometheus metrics exporter.
//!
//! This module provides an HTTP server for exporting metrics in Prometheus text format,
//! compatible with Prometheus scraping and other monitoring systems (Grafana, Datadog, etc.).
//!
//! # Prometheus Integration
//!
//! The exporter exposes an HTTP endpoint that Prometheus can scrape at regular intervals.
//! Metrics are encoded in the [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).
//!
//! ## Typical Architecture
//!
//! ```text
//! ┌─────────────┐
//! │  HSM Server │
//! │             │
//! │  ┌────────┐ │
//! │  │Metrics │ │
//! │  │Collect.│ │
//! │  └────┬───┘ │
//! └───────┼─────┘
//!         │
//!         ▼
//! ┌───────────────┐
//! │Metrics Exporter│  ◄─── :9090/metrics
//! └───────┬────────┘
//!         │
//!         │ (scrape every 15s)
//!         ▼
//! ┌───────────────┐
//! │  Prometheus   │  ◄─── Query & alert
//! └───────┬───────┘
//!         │
//!         ▼
//! ┌───────────────┐
//! │    Grafana    │  ◄─── Visualization
//! └───────────────┘
//! ```
//!
//! # Endpoints
//!
//! - **`/metrics`**: Prometheus metrics in text format
//! - **`/health`**: Simple health check endpoint
//!
//! # Examples
//!
//! ## Basic Setup
//!
//! ```no_run
//! use metrics::{MetricsCollector, MetricsExporter};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create metrics collector
//!     let collector = MetricsCollector::new()?;
//!
//!     // Create exporter (listens on 0.0.0.0:9090)
//!     let exporter = MetricsExporter::with_default_addr(collector);
//!
//!     println!("Metrics available at http://{}:9090/metrics", exporter.addr().ip());
//!
//!     // Start the exporter (blocks until shutdown)
//!     exporter.start().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Custom Port
//!
//! ```no_run
//! use metrics::{MetricsCollector, MetricsExporter};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let collector = MetricsCollector::new()?;
//!
//!     // Listen on custom port
//!     let addr: SocketAddr = "0.0.0.0:8080".parse()?;
//!     let exporter = MetricsExporter::new(collector, addr);
//!
//!     exporter.start().await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Background Server
//!
//! ```no_run
//! use metrics::{MetricsCollector, MetricsExporter};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let collector = MetricsCollector::new()?;
//!     let exporter = MetricsExporter::with_default_addr(collector.clone());
//!
//!     // Spawn exporter in background
//!     let exporter_handle = exporter.spawn();
//!
//!     // Continue using collector for metrics
//!     // collector.record_operation(...);
//!
//!     // Wait for exporter if needed
//!     exporter_handle.await??;
//!     Ok(())
//! }
//! ```
//!
//! # Prometheus Configuration
//!
//! ## prometheus.yml
//!
//! ```yaml
//! global:
//!   scrape_interval: 15s  # How often to scrape targets
//!   evaluation_interval: 15s  # How often to evaluate rules
//!
//! scrape_configs:
//!   - job_name: 'hsm'
//!     static_configs:
//!       - targets: ['localhost:9090']  # HSM metrics exporter
//!         labels:
//!           environment: 'production'
//!           service: 'hsm'
//! ```
//!
//! ## Kubernetes Service Discovery
//!
//! ```yaml
//! scrape_configs:
//!   - job_name: 'hsm-k8s'
//!     kubernetes_sd_configs:
//!       - role: pod
//!         namespaces:
//!           names:
//!             - hsm-system
//!     relabel_configs:
//!       - source_labels: [__meta_kubernetes_pod_label_app]
//!         action: keep
//!         regex: hsm
//!       - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
//!         action: keep
//!         regex: true
//!       - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_port]
//!         action: replace
//!         target_label: __address__
//!         regex: (.+)
//!         replacement: ${1}:9090
//! ```
//!
//! # Grafana Dashboards
//!
//! ## Example Queries
//!
//! **Request Rate**:
//! ```promql
//! rate(hsm_operations_total[5m])
//! ```
//!
//! **Error Rate**:
//! ```promql
//! rate(hsm_operation_errors_total[5m]) / rate(hsm_operations_total[5m])
//! ```
//!
//! **P95 Latency**:
//! ```promql
//! histogram_quantile(0.95, rate(hsm_operation_duration_seconds_bucket[5m]))
//! ```
//!
//! **Active Keys by Namespace**:
//! ```promql
//! hsm_active_keys{namespace="production"}
//! ```
//!
//! ## Dashboard Panels
//!
//! Recommended panels for HSM monitoring:
//!
//! 1. **Overview**:
//!    - Total operations/sec
//!    - Error rate %
//!    - P50/P95/P99 latency
//!    - Active connections
//!
//! 2. **Operations**:
//!    - Operations by type (sign, verify, encrypt, decrypt)
//!    - Batch operation performance
//!    - Operation errors by type
//!
//! 3. **Keys**:
//!    - Total keys by namespace
//!    - Active keys
//!    - Key generation rate
//!    - Key operations per key
//!
//! 4. **System**:
//!    - Memory usage
//!    - CPU usage
//!    - Storage usage
//!    - Connection count
//!
//! 5. **Health**:
//!    - Component health status
//!    - Circuit breaker state
//!    - Audit queue depth
//!
//! # Production Deployment
//!
//! ## Security
//!
//! - **Network Policy**: Restrict metrics port (9090) to Prometheus only
//! - **No Authentication**: Metrics are typically unauthenticated (internal network)
//! - **Sensitive Data**: Ensure no PII or secrets in metric labels
//!
//! ## Performance
//!
//! - **Scrape Interval**: 15-30s is typical (adjust based on granularity needs)
//! - **Cardinality**: Monitor metric cardinality to prevent memory issues
//! - **Retention**: Configure Prometheus retention based on storage capacity
//!
//! ## High Availability
//!
//! - **Federation**: Use Prometheus federation for multi-cluster setups
//! - **Redundancy**: Run multiple Prometheus replicas
//! - **Remote Write**: Send to remote storage (Thanos, Cortex, Mimir)
//!
//! # Troubleshooting
//!
//! ## Metrics Not Appearing
//!
//! 1. Check exporter is running: `curl http://localhost:9090/health`
//! 2. Check metrics endpoint: `curl http://localhost:9090/metrics`
//! 3. Verify Prometheus scrape config
//! 4. Check Prometheus targets page: http://prometheus:9090/targets
//!
//! ## High Cardinality
//!
//! If Prometheus memory usage is high:
//!
//! 1. Check metric cardinality: `prometheus --query 'topk(10, count by (__name__)({__name__=~".+"}))'`
//! 2. Review label usage in collectors
//! 3. Apply cardinality limits (see [`crate::collector::CardinalityLimiter`])
//! 4. Use relabel_configs to drop high-cardinality labels
//!
//! ## Slow Queries
//!
//! - Reduce time range
//! - Use recording rules for complex queries
//! - Aggregate before querying (use `sum`, `avg`, etc.)
//! - Consider downsampling for long-term storage

use crate::collector::MetricsCollector;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use prometheus::TextEncoder;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExporterError {
    #[error("Failed to start server: {0}")]
    ServerStart(String),
    #[error("Failed to encode metrics: {0}")]
    Encoding(#[from] prometheus::Error),
}

pub type Result<T> = std::result::Result<T, ExporterError>;

/// Prometheus metrics exporter
#[derive(Clone)]
pub struct MetricsExporter {
    collector: MetricsCollector,
    addr: SocketAddr,
}

impl MetricsExporter {
    /// Create a new metrics exporter
    pub fn new(collector: MetricsCollector, addr: SocketAddr) -> Self {
        Self { collector, addr }
    }

    /// Create an exporter with default address (0.0.0.0:9090)
    pub fn with_default_addr(collector: MetricsCollector) -> Self {
        Self::new(collector, "0.0.0.0:9090".parse().unwrap())
    }

    /// Get the configured address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Build the router for the HTTP server
    fn build_router(&self) -> Router {
        Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .with_state(Arc::new(self.collector.clone()))
    }

    /// Start the metrics exporter server
    pub async fn start(self) -> Result<()> {
        let app = self.build_router();
        let listener = tokio::net::TcpListener::bind(self.addr)
            .await
            .map_err(|e| ExporterError::ServerStart(e.to_string()))?;

        axum::serve(listener, app)
            .await
            .map_err(|e| ExporterError::ServerStart(e.to_string()))?;

        Ok(())
    }

    /// Start the server in the background and return a handle
    pub fn spawn(self) -> tokio::task::JoinHandle<Result<()>> {
        tokio::spawn(async move { self.start().await })
    }
}

/// Handler for /metrics endpoint
async fn metrics_handler(State(collector): State<Arc<MetricsCollector>>) -> Response {
    let encoder = TextEncoder::new();
    let metric_families = collector.gather();

    match encoder.encode_to_string(&metric_families) {
        Ok(encoded) => (StatusCode::OK, encoded).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to encode metrics: {}", e),
        )
            .into_response(),
    }
}

/// Handler for /health endpoint
async fn health_handler() -> Response {
    (StatusCode::OK, "OK").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::OperationStatus;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_exporter_creation() {
        let collector = MetricsCollector::new().unwrap();
        let exporter = MetricsExporter::with_default_addr(collector);
        assert_eq!(exporter.addr().port(), 9090);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let collector = MetricsCollector::new().unwrap();
        collector.record_operation("test", "none", "default", OperationStatus::Success);

        let exporter = MetricsExporter::new(collector.clone(), "127.0.0.1:0".parse().unwrap());

        let app = exporter.build_router();

        // Test /metrics endpoint
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let collector = MetricsCollector::new().unwrap();
        let exporter = MetricsExporter::with_default_addr(collector);

        let app = exporter.build_router();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
