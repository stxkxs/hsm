//! Metrics collection for HSM operations
//!
//! This module provides comprehensive metrics collection for all HSM operations,
//! including operation counters, latency histograms, and system metrics.

use prometheus::{
    proto::MetricFamily, Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec, Opts,
    Registry,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MetricsError {
    #[error("Failed to register metric: {0}")]
    Registration(#[from] prometheus::Error),
    #[error("Metric not found: {0}")]
    NotFound(String),
    #[error("Cardinality limit exceeded: {max} max, attempted to add label '{label}'")]
    CardinalityExceeded { max: usize, label: String },
}

pub type Result<T> = std::result::Result<T, MetricsError>;

/// Cardinality limiter to prevent metric explosion.
///
/// # The Cardinality Problem
///
/// In Prometheus-style metrics, each unique combination of label values creates a new time series.
/// High-cardinality labels (like user IDs, request IDs, IP addresses) can create millions of series,
/// causing:
///
/// - **Memory Exhaustion**: Prometheus stores all series in memory
/// - **Query Slowdown**: More series = slower queries
/// - **Storage Bloat**: Disk usage grows linearly with cardinality
/// - **Cost Increase**: Cloud monitoring costs are often per-series
///
/// # How This Limiter Works
///
/// The limiter tracks unique label combinations and rejects new labels after hitting the limit:
///
/// ```text
/// Label Stream:
/// - "namespace=prod" → New label, count=1 ✓
/// - "namespace=dev" → New label, count=2 ✓
/// - "namespace=staging" → New label, count=3 ✓
/// ... (up to max_cardinality)
/// - "namespace=test" → Limit reached, rejected ✗
/// ```
///
/// # Recommended Limits
///
/// - **Low-cardinality labels**: No limit needed
///   - Examples: operation_type (sign/verify/encrypt/decrypt)
///   - Typical values: 4-10 unique values
///
/// - **Medium-cardinality labels**: Limit to 100-1000
///   - Examples: namespace, key_type, error_code
///   - Typical values: 10-100 unique values
///
/// - **High-cardinality labels**: Avoid or heavily limit (10-100)
///   - Examples: key_id (if many keys), user_id
///   - Typical values: 1000+ unique values
///   - Better approach: Use aggregation or sampling
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// use hsm_metrics::CardinalityLimiter;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Limit to 1000 unique namespace values
/// let limiter = CardinalityLimiter::new(1000);
///
/// // Check if label is allowed
/// limiter.check_label("production")?;  // OK
/// limiter.check_label("development")?;  // OK
///
/// // ... 998 more labels ...
///
/// // This will fail if limit exceeded
/// match limiter.check_label("namespace-1001") {
///     Ok(_) => println!("Label accepted"),
///     Err(e) => println!("Label rejected: {}", e),
/// }
///
/// // Check current usage
/// println!("Current cardinality: {}", limiter.current_cardinality());
/// # Ok(())
/// # }
/// ```
///
/// # Best Practices
///
/// - **Set Conservative Limits**: Start low (100-500), increase if needed
/// - **Monitor Cardinality**: Track `current_cardinality()` as a metric
/// - **Use Fixed Labels**: Prefer bounded label sets (e.g., environment, region)
/// - **Aggregate High-Cardinality Data**: Log detailed info, metric aggregates
/// - **Sample When Necessary**: Use [`SamplingConfig`] for extreme cardinality
#[derive(Clone)]
pub struct CardinalityLimiter {
    max_cardinality: usize,
    current_labels: Arc<RwLock<HashSet<String>>>,
}

impl CardinalityLimiter {
    /// Creates a new cardinality limiter with the specified maximum.
    ///
    /// # Arguments
    ///
    /// * `max_cardinality` - Maximum number of unique label values allowed
    ///
    /// # Examples
    ///
    /// ```
    /// use hsm_metrics::CardinalityLimiter;
    ///
    /// let limiter = CardinalityLimiter::new(1000);
    /// ```
    pub fn new(max_cardinality: usize) -> Self {
        Self {
            max_cardinality,
            current_labels: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Checks if a label value is allowed (under the cardinality limit).
    ///
    /// # Arguments
    ///
    /// * `label` - The label value to check
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the label is allowed (either already seen or under limit)
    /// - `Err(MetricsError::CardinalityExceeded)` if adding this label would exceed the limit
    ///
    /// # Examples
    ///
    /// ```
    /// use hsm_metrics::CardinalityLimiter;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let limiter = CardinalityLimiter::new(2);
    ///
    /// limiter.check_label("value1")?;  // OK - first value
    /// limiter.check_label("value1")?;  // OK - already seen
    /// limiter.check_label("value2")?;  // OK - second value
    ///
    /// // This will fail - would be third unique value
    /// assert!(limiter.check_label("value3").is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn check_label(&self, label: &str) -> Result<()> {
        let labels = self.current_labels.read().unwrap();
        if labels.contains(label) {
            return Ok(());
        }
        drop(labels);

        let mut labels = self.current_labels.write().unwrap();
        if labels.len() >= self.max_cardinality {
            return Err(MetricsError::CardinalityExceeded {
                max: self.max_cardinality,
                label: label.to_string(),
            });
        }

        labels.insert(label.to_string());
        Ok(())
    }

    /// Coerce a label value into the bounded set: returns the input if it's already tracked
    /// or fits under the cardinality cap, otherwise returns the `overflow` sentinel.
    ///
    /// Use this instead of [`check_label`] when you want guarantees against unbounded
    /// Prometheus series growth: rejected labels collapse into a single overflow bucket
    /// rather than producing errors.
    ///
    /// [`check_label`]: Self::check_label
    pub fn bound<'a>(&self, label: &'a str, overflow: &'a str) -> &'a str {
        // Fast path: label already tracked.
        if self.current_labels.read().unwrap().contains(label) {
            return label;
        }
        let mut labels = self.current_labels.write().unwrap();
        if labels.contains(label) {
            return label;
        }
        if labels.len() >= self.max_cardinality {
            return overflow;
        }
        labels.insert(label.to_string());
        label
    }

    /// Returns the current number of unique labels seen.
    ///
    /// # Examples
    ///
    /// ```
    /// use hsm_metrics::CardinalityLimiter;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let limiter = CardinalityLimiter::new(100);
    ///
    /// assert_eq!(limiter.current_cardinality(), 0);
    ///
    /// limiter.check_label("value1")?;
    /// assert_eq!(limiter.current_cardinality(), 1);
    ///
    /// limiter.check_label("value1")?;  // Same value, no increase
    /// assert_eq!(limiter.current_cardinality(), 1);
    ///
    /// limiter.check_label("value2")?;
    /// assert_eq!(limiter.current_cardinality(), 2);
    /// # Ok(())
    /// # }
    /// ```
    pub fn current_cardinality(&self) -> usize {
        self.current_labels.read().unwrap().len()
    }
}

/// Sampling configuration for high-volume metrics.
///
/// When metrics have extremely high cardinality or volume, sampling reduces overhead
/// by only recording a fraction of events.
///
/// # Use Cases
///
/// - **High-frequency operations**: Operations that occur 1000+ times per second
/// - **Detailed tracing**: Per-request metrics where aggregates suffice
/// - **Cost reduction**: Reduce Prometheus storage and query costs
/// - **Performance**: Minimize metric collection overhead
///
/// # Trade-offs
///
/// - **Accuracy**: Sampled metrics are estimates, not exact counts
/// - **Rare events**: May miss infrequent errors or anomalies
/// - **Aggregation**: Works best for metrics that aggregate well (averages, percentiles)
///
/// # Examples
///
/// No sampling (100% of events recorded):
///
/// ```
/// use hsm_metrics::SamplingConfig;
///
/// let config = SamplingConfig::new(1.0);  // 100%
/// ```
///
/// Sample 10% of events:
///
/// ```
/// use hsm_metrics::SamplingConfig;
///
/// let config = SamplingConfig::new(0.1);  // 10%
///
/// // Use in hot path:
/// if config.should_sample() {
///     // Record metric (happens ~10% of the time)
/// }
/// ```
///
/// Dynamic sampling (increase for errors):
///
/// ```
/// use hsm_metrics::SamplingConfig;
///
/// let success_sampling = SamplingConfig::new(0.01);  // 1% for successes
/// let error_sampling = SamplingConfig::new(1.0);     // 100% for errors
///
/// // if operation.is_success() && success_sampling.should_sample() { ... }
/// // else if operation.is_error() && error_sampling.should_sample() { ... }
/// ```
#[derive(Clone)]
pub struct SamplingConfig {
    /// Sample rate between 0.0 (never sample) and 1.0 (always sample).
    pub sample_rate: f64,
}

impl SamplingConfig {
    pub fn new(sample_rate: f64) -> Self {
        Self {
            sample_rate: sample_rate.clamp(0.0, 1.0),
        }
    }

    pub fn should_sample(&self) -> bool {
        use rand::Rng;
        rand::thread_rng().gen::<f64>() < self.sample_rate
    }
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self::new(1.0) // No sampling by default
    }
}

/// Main metrics collector for HSM operations with comprehensive coverage
#[derive(Clone)]
pub struct MetricsCollector {
    registry: Arc<Registry>,

    // Lock-free atomic counters for high-performance operations
    sign_operations_atomic: Arc<AtomicU64>,
    verify_operations_atomic: Arc<AtomicU64>,
    encrypt_operations_atomic: Arc<AtomicU64>,
    decrypt_operations_atomic: Arc<AtomicU64>,

    // Comprehensive operation counters
    operations_total: CounterVec,
    operation_errors: CounterVec,

    // Latency histograms
    operation_duration: HistogramVec,

    // Crypto operation specific metrics
    sign_duration: HistogramVec,
    verify_duration: HistogramVec,
    encrypt_duration: HistogramVec,
    decrypt_duration: HistogramVec,

    // Key management metrics
    keys_total: GaugeVec,
    key_generation_total: CounterVec,
    key_deletion_total: CounterVec,
    active_keys_gauge: GaugeVec,

    // Authentication metrics
    auth_attempts: CounterVec,
    auth_failures: CounterVec,
    active_sessions: Gauge,

    // Storage metrics
    storage_read_duration: Histogram,
    storage_write_duration: Histogram,
    storage_errors: Counter,

    // Audit metrics
    audit_events_written: Counter,
    audit_queue_depth: Gauge,
    audit_write_duration: Histogram,

    // System metrics
    active_connections: GaugeVec,
    memory_usage: GaugeVec,
    storage_usage: GaugeVec,
    cpu_usage: Gauge,

    // Health metrics
    component_health: GaugeVec,
    cpu_saturation: Gauge,
    memory_saturation: Gauge,
    disk_saturation: Gauge,
    component_errors: CounterVec,

    // Cardinality control
    cardinality_limiter: CardinalityLimiter,
    cardinality_gauge: Gauge,

    // Sampling configuration
    sampling_config: SamplingConfig,
}

impl MetricsCollector {
    /// Create a new metrics collector with default registry and configuration
    pub fn new() -> Result<Self> {
        Self::with_config(Registry::new(), 10_000, SamplingConfig::default())
    }

    /// Create a new metrics collector with a custom registry
    pub fn with_registry(registry: Registry) -> Result<Self> {
        Self::with_config(registry, 10_000, SamplingConfig::default())
    }

    /// Create a new metrics collector with custom configuration
    pub fn with_config(
        registry: Registry,
        max_cardinality: usize,
        sampling_config: SamplingConfig,
    ) -> Result<Self> {
        // Operation counters
        let operations_total = CounterVec::new(
            Opts::new("hsm_operations_total", "Total number of HSM operations"),
            &["operation", "algorithm", "namespace", "status"],
        )?;

        let operation_errors = CounterVec::new(
            Opts::new(
                "hsm_operation_errors_total",
                "Total number of operation errors",
            ),
            &["operation", "error_type"],
        )?;

        // Latency histograms
        let operation_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "hsm_operation_duration_seconds",
                "Duration of HSM operations in seconds",
            )
            .buckets(vec![
                0.000_001, 0.000_010, 0.000_050, 0.000_100, 0.000_500, 0.001, 0.005, 0.01, 0.025,
                0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["operation", "algorithm"],
        )?;

        // Crypto-specific histograms
        let sign_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "hsm_sign_duration_seconds",
                "Duration of signature operations",
            )
            .buckets(vec![
                0.000_001, 0.000_010, 0.000_050, 0.000_100, 0.000_500, 0.001, 0.005, 0.01, 0.025,
                0.05,
            ]),
            &["algorithm", "namespace"],
        )?;

        let verify_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "hsm_verify_duration_seconds",
                "Duration of signature verification operations",
            )
            .buckets(vec![
                0.000_001, 0.000_010, 0.000_050, 0.000_100, 0.000_500, 0.001, 0.005, 0.01, 0.025,
                0.05,
            ]),
            &["algorithm", "namespace"],
        )?;

        let encrypt_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "hsm_encrypt_duration_seconds",
                "Duration of encryption operations",
            )
            .buckets(vec![
                0.000_001, 0.000_010, 0.000_050, 0.000_100, 0.000_500, 0.001, 0.005, 0.01, 0.025,
                0.05,
            ]),
            &["algorithm", "namespace"],
        )?;

        let decrypt_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "hsm_decrypt_duration_seconds",
                "Duration of decryption operations",
            )
            .buckets(vec![
                0.000_001, 0.000_010, 0.000_050, 0.000_100, 0.000_500, 0.001, 0.005, 0.01, 0.025,
                0.05,
            ]),
            &["algorithm", "namespace"],
        )?;

        // Key management metrics
        let keys_total = GaugeVec::new(
            Opts::new("hsm_keys_total", "Total number of keys in HSM"),
            &["namespace", "type", "state"],
        )?;

        let key_generation_total = CounterVec::new(
            Opts::new("hsm_key_generation_total", "Total number of keys generated"),
            &["algorithm", "namespace"],
        )?;

        let key_deletion_total = CounterVec::new(
            Opts::new("hsm_key_deletion_total", "Total number of keys deleted"),
            &["namespace", "reason"],
        )?;

        let active_keys_gauge = GaugeVec::new(
            Opts::new("hsm_active_keys", "Number of active keys"),
            &["namespace", "algorithm"],
        )?;

        // Authentication metrics
        let auth_attempts = CounterVec::new(
            Opts::new("hsm_auth_attempts_total", "Total authentication attempts"),
            &["method", "status"],
        )?;

        let auth_failures = CounterVec::new(
            Opts::new("hsm_auth_failures_total", "Total authentication failures"),
            &["method", "reason"],
        )?;

        let active_sessions = Gauge::new(
            "hsm_active_sessions",
            "Number of active authentication sessions",
        )?;

        // Storage metrics
        let storage_read_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "hsm_storage_read_duration_seconds",
                "Storage read operation duration",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]),
        )?;

        let storage_write_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "hsm_storage_write_duration_seconds",
                "Storage write operation duration",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]),
        )?;

        let storage_errors = Counter::new("hsm_storage_errors_total", "Total storage errors")?;

        // Audit metrics
        let audit_events_written = Counter::new(
            "hsm_audit_events_written_total",
            "Total audit events written",
        )?;

        let audit_queue_depth = Gauge::new("hsm_audit_queue_depth", "Current audit queue depth")?;

        let audit_write_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "hsm_audit_write_duration_seconds",
                "Audit write operation duration",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1]),
        )?;

        // System metrics
        let active_connections = GaugeVec::new(
            Opts::new(
                "hsm_active_connections",
                "Number of active connections to HSM",
            ),
            &["type"],
        )?;

        let memory_usage = GaugeVec::new(
            Opts::new("hsm_memory_usage_bytes", "Memory usage in bytes"),
            &["component"],
        )?;

        let storage_usage = GaugeVec::new(
            Opts::new("hsm_storage_usage_bytes", "Storage usage in bytes"),
            &["namespace"],
        )?;

        let cpu_usage = Gauge::new("hsm_cpu_usage_percent", "CPU usage percentage")?;

        // Health metrics
        let component_health = GaugeVec::new(
            Opts::new(
                "hsm_component_health",
                "Component health status (0=unhealthy, 1=healthy)",
            ),
            &["component"],
        )?;

        let cpu_saturation = Gauge::new("hsm_cpu_saturation", "CPU saturation (0-1)")?;

        let memory_saturation = Gauge::new("hsm_memory_saturation", "Memory saturation (0-1)")?;

        let disk_saturation = Gauge::new("hsm_disk_saturation", "Disk saturation (0-1)")?;

        let component_errors = CounterVec::new(
            Opts::new("hsm_component_errors_total", "Total component errors"),
            &["component", "error_type"],
        )?;

        // Cardinality monitoring
        let cardinality_gauge =
            Gauge::new("hsm_metric_cardinality", "Current metric label cardinality")?;

        // Register all metrics
        registry.register(Box::new(operations_total.clone()))?;
        registry.register(Box::new(operation_errors.clone()))?;
        registry.register(Box::new(operation_duration.clone()))?;
        registry.register(Box::new(sign_duration.clone()))?;
        registry.register(Box::new(verify_duration.clone()))?;
        registry.register(Box::new(encrypt_duration.clone()))?;
        registry.register(Box::new(decrypt_duration.clone()))?;
        registry.register(Box::new(keys_total.clone()))?;
        registry.register(Box::new(key_generation_total.clone()))?;
        registry.register(Box::new(key_deletion_total.clone()))?;
        registry.register(Box::new(active_keys_gauge.clone()))?;
        registry.register(Box::new(auth_attempts.clone()))?;
        registry.register(Box::new(auth_failures.clone()))?;
        registry.register(Box::new(active_sessions.clone()))?;
        registry.register(Box::new(storage_read_duration.clone()))?;
        registry.register(Box::new(storage_write_duration.clone()))?;
        registry.register(Box::new(storage_errors.clone()))?;
        registry.register(Box::new(audit_events_written.clone()))?;
        registry.register(Box::new(audit_queue_depth.clone()))?;
        registry.register(Box::new(audit_write_duration.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(memory_usage.clone()))?;
        registry.register(Box::new(storage_usage.clone()))?;
        registry.register(Box::new(cpu_usage.clone()))?;
        registry.register(Box::new(component_health.clone()))?;
        registry.register(Box::new(cpu_saturation.clone()))?;
        registry.register(Box::new(memory_saturation.clone()))?;
        registry.register(Box::new(disk_saturation.clone()))?;
        registry.register(Box::new(component_errors.clone()))?;
        registry.register(Box::new(cardinality_gauge.clone()))?;

        Ok(Self {
            registry: Arc::new(registry),
            sign_operations_atomic: Arc::new(AtomicU64::new(0)),
            verify_operations_atomic: Arc::new(AtomicU64::new(0)),
            encrypt_operations_atomic: Arc::new(AtomicU64::new(0)),
            decrypt_operations_atomic: Arc::new(AtomicU64::new(0)),
            operations_total,
            operation_errors,
            operation_duration,
            sign_duration,
            verify_duration,
            encrypt_duration,
            decrypt_duration,
            keys_total,
            key_generation_total,
            key_deletion_total,
            active_keys_gauge,
            auth_attempts,
            auth_failures,
            active_sessions,
            storage_read_duration,
            storage_write_duration,
            storage_errors,
            audit_events_written,
            audit_queue_depth,
            audit_write_duration,
            active_connections,
            memory_usage,
            storage_usage,
            cpu_usage,
            component_health,
            cpu_saturation,
            memory_saturation,
            disk_saturation,
            component_errors,
            cardinality_limiter: CardinalityLimiter::new(max_cardinality),
            cardinality_gauge,
            sampling_config,
        })
    }

    /// Sentinel label used when a high-cardinality value exceeds the cap.
    const OVERFLOW_LABEL: &'static str = "_other_";

    /// Coerce a namespace label into the bounded set.
    ///
    /// Untrusted input (namespace, key_id) flows into Prometheus label values; without bounding,
    /// an attacker — or a buggy client — can explode metric cardinality and OOM the scrape pipeline.
    /// Excess labels collapse into a single `_other_` bucket.
    fn bounded_ns<'a>(&self, namespace: &'a str) -> &'a str {
        self.cardinality_limiter
            .bound(namespace, Self::OVERFLOW_LABEL)
    }

    /// Record an operation
    pub fn record_operation(
        &self,
        operation: &str,
        algorithm: &str,
        namespace: &str,
        status: OperationStatus,
    ) {
        let ns = self.bounded_ns(namespace);
        self.operations_total
            .with_label_values(&[operation, algorithm, ns, status.as_str()])
            .inc();
    }

    /// Record operation duration
    pub fn record_operation_duration(&self, operation: &str, algorithm: &str, duration_secs: f64) {
        self.operation_duration
            .with_label_values(&[operation, algorithm])
            .observe(duration_secs);
    }

    /// Record a sign operation with lock-free atomic counter
    pub fn record_sign(&self, algorithm: &str, namespace: &str, duration: std::time::Duration) {
        // Lock-free atomic increment
        self.sign_operations_atomic.fetch_add(1, Ordering::Relaxed);

        // Record duration with sampling for high-volume ops
        if self.sampling_config.should_sample() {
            let ns = self.bounded_ns(namespace);
            self.sign_duration
                .with_label_values(&[algorithm, ns])
                .observe(duration.as_secs_f64());
        }
    }

    /// Record a verify operation with lock-free atomic counter
    pub fn record_verify(&self, algorithm: &str, namespace: &str, duration: std::time::Duration) {
        self.verify_operations_atomic
            .fetch_add(1, Ordering::Relaxed);

        if self.sampling_config.should_sample() {
            let ns = self.bounded_ns(namespace);
            self.verify_duration
                .with_label_values(&[algorithm, ns])
                .observe(duration.as_secs_f64());
        }
    }

    /// Record an encrypt operation with lock-free atomic counter
    pub fn record_encrypt(&self, algorithm: &str, namespace: &str, duration: std::time::Duration) {
        self.encrypt_operations_atomic
            .fetch_add(1, Ordering::Relaxed);

        if self.sampling_config.should_sample() {
            let ns = self.bounded_ns(namespace);
            self.encrypt_duration
                .with_label_values(&[algorithm, ns])
                .observe(duration.as_secs_f64());
        }
    }

    /// Record a decrypt operation with lock-free atomic counter
    pub fn record_decrypt(&self, algorithm: &str, namespace: &str, duration: std::time::Duration) {
        self.decrypt_operations_atomic
            .fetch_add(1, Ordering::Relaxed);

        if self.sampling_config.should_sample() {
            let ns = self.bounded_ns(namespace);
            self.decrypt_duration
                .with_label_values(&[algorithm, ns])
                .observe(duration.as_secs_f64());
        }
    }

    /// Get lock-free operation counts
    pub fn get_sign_count(&self) -> u64 {
        self.sign_operations_atomic.load(Ordering::Relaxed)
    }

    pub fn get_verify_count(&self) -> u64 {
        self.verify_operations_atomic.load(Ordering::Relaxed)
    }

    pub fn get_encrypt_count(&self) -> u64 {
        self.encrypt_operations_atomic.load(Ordering::Relaxed)
    }

    pub fn get_decrypt_count(&self) -> u64 {
        self.decrypt_operations_atomic.load(Ordering::Relaxed)
    }

    /// Record an operation error
    pub fn record_error(&self, operation: &str, error_type: &str) {
        self.operation_errors
            .with_label_values(&[operation, error_type])
            .inc();
    }

    /// Record key generation
    pub fn record_key_generation(&self, algorithm: &str, namespace: &str) {
        let ns = self.bounded_ns(namespace);
        self.key_generation_total
            .with_label_values(&[algorithm, ns])
            .inc();
    }

    /// Record key deletion
    pub fn record_key_deletion(&self, namespace: &str, reason: &str) {
        let ns = self.bounded_ns(namespace);
        self.key_deletion_total
            .with_label_values(&[ns, reason])
            .inc();
    }

    /// Set active keys count
    pub fn set_active_keys(&self, namespace: &str, algorithm: &str, count: i64) {
        let ns = self.bounded_ns(namespace);
        self.active_keys_gauge
            .with_label_values(&[ns, algorithm])
            .set(count as f64);
    }

    /// Record authentication attempt
    pub fn record_auth_attempt(&self, method: &str, status: &str) {
        self.auth_attempts
            .with_label_values(&[method, status])
            .inc();
    }

    /// Record authentication failure
    pub fn record_auth_failure(&self, method: &str, reason: &str) {
        self.auth_failures
            .with_label_values(&[method, reason])
            .inc();
    }

    /// Set active sessions count
    pub fn set_active_sessions(&self, count: i64) {
        self.active_sessions.set(count as f64);
    }

    /// Record storage read duration
    pub fn record_storage_read(&self, duration: std::time::Duration) {
        self.storage_read_duration.observe(duration.as_secs_f64());
    }

    /// Record storage write duration
    pub fn record_storage_write(&self, duration: std::time::Duration) {
        self.storage_write_duration.observe(duration.as_secs_f64());
    }

    /// Record storage error
    pub fn record_storage_error(&self) {
        self.storage_errors.inc();
    }

    /// Record audit event written
    pub fn record_audit_event(&self) {
        self.audit_events_written.inc();
    }

    /// Set audit queue depth
    pub fn set_audit_queue_depth(&self, depth: i64) {
        self.audit_queue_depth.set(depth as f64);
    }

    /// Record audit write duration
    pub fn record_audit_write(&self, duration: std::time::Duration) {
        self.audit_write_duration.observe(duration.as_secs_f64());
    }

    /// Set CPU usage percentage
    pub fn set_cpu_usage(&self, percent: f64) {
        self.cpu_usage.set(percent);
    }

    /// Set component health (0=unhealthy, 1=healthy)
    pub fn set_component_health(&self, component: &str, healthy: bool) {
        self.component_health
            .with_label_values(&[component])
            .set(if healthy { 1.0 } else { 0.0 });
    }

    /// Set saturation metrics (0-1)
    pub fn set_cpu_saturation(&self, saturation: f64) {
        self.cpu_saturation.set(saturation.clamp(0.0, 1.0));
    }

    pub fn set_memory_saturation(&self, saturation: f64) {
        self.memory_saturation.set(saturation.clamp(0.0, 1.0));
    }

    pub fn set_disk_saturation(&self, saturation: f64) {
        self.disk_saturation.set(saturation.clamp(0.0, 1.0));
    }

    /// Record component error
    pub fn record_component_error(&self, component: &str, error_type: &str) {
        self.component_errors
            .with_label_values(&[component, error_type])
            .inc();
    }

    /// Update cardinality metric
    pub fn update_cardinality(&self) {
        let cardinality = self.cardinality_limiter.current_cardinality();
        self.cardinality_gauge.set(cardinality as f64);
    }

    /// Get current cardinality
    pub fn get_cardinality(&self) -> usize {
        self.cardinality_limiter.current_cardinality()
    }

    /// Check if a label is allowed (for cardinality control)
    pub fn check_label(&self, label: &str) -> Result<()> {
        self.cardinality_limiter.check_label(label)
    }

    /// Set key count
    pub fn set_key_count(&self, namespace: &str, key_type: &str, state: KeyState, count: i64) {
        self.keys_total
            .with_label_values(&[namespace, key_type, state.as_str()])
            .set(count as f64);
    }

    /// Set active connections
    pub fn set_active_connections(&self, conn_type: &str, count: i64) {
        self.active_connections
            .with_label_values(&[conn_type])
            .set(count as f64);
    }

    /// Increment active connections
    pub fn increment_active_connections(&self, conn_type: &str) {
        self.active_connections
            .with_label_values(&[conn_type])
            .inc();
    }

    /// Decrement active connections
    pub fn decrement_active_connections(&self, conn_type: &str) {
        self.active_connections
            .with_label_values(&[conn_type])
            .dec();
    }

    /// Set memory usage
    pub fn set_memory_usage(&self, component: &str, bytes: i64) {
        self.memory_usage
            .with_label_values(&[component])
            .set(bytes as f64);
    }

    /// Set storage usage
    pub fn set_storage_usage(&self, namespace: &str, bytes: i64) {
        self.storage_usage
            .with_label_values(&[namespace])
            .set(bytes as f64);
    }

    /// Get the registry for exporting metrics
    pub fn registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }

    /// Gather all metrics
    pub fn gather(&self) -> Vec<MetricFamily> {
        self.registry.gather()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new().expect("Failed to create default metrics collector")
    }
}

/// Status of an operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStatus {
    Success,
    Failure,
    Timeout,
    Cancelled,
}

impl OperationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
        }
    }
}

/// State of a key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Active,
    Inactive,
    Compromised,
    Destroyed,
}

impl KeyState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Compromised => "compromised",
            Self::Destroyed => "destroyed",
        }
    }
}

/// Helper to measure operation duration
pub struct OperationTimer {
    start: std::time::Instant,
    collector: MetricsCollector,
    operation: String,
    algorithm: String,
}

impl OperationTimer {
    /// Create a new operation timer
    pub fn new(
        collector: MetricsCollector,
        operation: impl Into<String>,
        algorithm: impl Into<String>,
    ) -> Self {
        Self {
            start: std::time::Instant::now(),
            collector,
            operation: operation.into(),
            algorithm: algorithm.into(),
        }
    }

    /// Stop the timer and record the duration
    pub fn stop(self) {
        let duration = self.start.elapsed();
        self.collector.record_operation_duration(
            &self.operation,
            &self.algorithm,
            duration.as_secs_f64(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new().unwrap();

        // Record some data to ensure metrics appear
        collector.record_operation("test", "test", "test", OperationStatus::Success);

        let metrics = collector.gather();
        // Verify metrics are registered
        assert!(!metrics.is_empty(), "Expected metrics to be gathered");
    }

    #[test]
    fn test_record_operation() {
        let collector = MetricsCollector::new().unwrap();
        collector.record_operation("sign", "rsa", "default", OperationStatus::Success);

        let metrics = collector.gather();
        assert!(metrics.iter().any(|m| m.name() == "hsm_operations_total"));
    }

    #[test]
    fn test_record_duration() {
        let collector = MetricsCollector::new().unwrap();
        collector.record_operation_duration("sign", "rsa", 0.123);

        let metrics = collector.gather();
        assert!(metrics
            .iter()
            .any(|m| m.name() == "hsm_operation_duration_seconds"));
    }

    #[test]
    fn test_set_key_count() {
        let collector = MetricsCollector::new().unwrap();
        collector.set_key_count("default", "rsa", KeyState::Active, 42);

        let metrics = collector.gather();
        assert!(metrics.iter().any(|m| m.name() == "hsm_keys_total"));
    }

    #[test]
    fn test_active_connections() {
        let collector = MetricsCollector::new().unwrap();
        collector.set_active_connections("grpc", 5);
        collector.increment_active_connections("grpc");
        collector.decrement_active_connections("grpc");

        let metrics = collector.gather();
        assert!(metrics.iter().any(|m| m.name() == "hsm_active_connections"));
    }

    #[test]
    fn test_operation_timer() {
        let collector = MetricsCollector::new().unwrap();
        let timer = OperationTimer::new(collector.clone(), "encrypt", "aes");
        std::thread::sleep(std::time::Duration::from_millis(10));
        timer.stop();

        let metrics = collector.gather();
        assert!(metrics
            .iter()
            .any(|m| m.name() == "hsm_operation_duration_seconds"));
    }
}
