# Module 6: Metrics & Monitoring - Phase 2 Enhancements

## Current Status
- ✅ 896 lines of code
- ✅ Compiles successfully
- ✅ Basic Prometheus integration
- ✅ Counter and histogram metrics

## Performance Enhancements

### 1. Lock-Free Metrics (Priority: CRITICAL)
**Goal**: < 10μs overhead per metric update

**Tasks**:
- [ ] Use atomic operations for counters
- [ ] Implement lock-free histograms
- [ ] Optimize gauge updates
- [ ] Profile metric overhead
- [ ] Benchmark metric collection performance

**Lock-free implementation**:
```rust
use std::sync::atomic::{AtomicU64, Ordering};
use prometheus::{Counter, Histogram};

pub struct Metrics {
    // Lock-free counter using atomics
    sign_operations: AtomicU64,
    verify_operations: AtomicU64,

    // Prometheus metrics (internally optimized)
    sign_duration: Histogram,
    verify_duration: Histogram,
}

impl Metrics {
    pub fn record_sign(&self, duration: Duration) {
        // Atomic increment (lock-free)
        self.sign_operations.fetch_add(1, Ordering::Relaxed);

        // Record duration (prometheus uses internal optimization)
        self.sign_duration.observe(duration.as_secs_f64());
    }
}
```

**Target**: < 10μs overhead per metric operation

### 2. Sampling for High-Volume Metrics (Priority: HIGH)
**Goal**: Reduce overhead on hot paths

**Tasks**:
- [ ] Implement metric sampling
- [ ] Add configurable sample rates
- [ ] Use reservoir sampling for histograms
- [ ] Profile sampling accuracy
- [ ] Benchmark overhead reduction

**Sampling**:
```rust
use rand::Rng;

pub struct SampledMetrics {
    sample_rate: f64,  // e.g., 0.1 = 10% sampling
    histogram: Histogram,
}

impl SampledMetrics {
    pub fn record_with_sampling(&self, value: f64) {
        // Sample 10% of high-volume operations
        if rand::thread_rng().gen::<f64>() < self.sample_rate {
            self.histogram.observe(value);
        }
    }
}
```

**Expected gain**: 90% overhead reduction with 10% sampling

### 3. Batch Metric Updates (Priority: MEDIUM)
**Goal**: Reduce metric collection overhead

**Tasks**:
- [ ] Batch metric updates
- [ ] Use thread-local aggregation
- [ ] Flush batches periodically
- [ ] Profile batching effectiveness
- [ ] Benchmark batch vs individual updates

### 4. Metric Aggregation (Priority: MEDIUM)
**Goal**: Efficient multi-dimensional metrics

**Tasks**:
- [ ] Pre-aggregate common queries
- [ ] Add metric labels efficiently
- [ ] Use metric families for related metrics
- [ ] Optimize label cardinality
- [ ] Benchmark aggregation performance

**Efficient labels**:
```rust
use prometheus::{HistogramVec, Opts};

pub struct KeyMetrics {
    // Efficient label-based metrics
    operation_duration: HistogramVec,
}

impl KeyMetrics {
    pub fn new() -> Self {
        let operation_duration = HistogramVec::new(
            HistogramOpts::new("operation_duration_seconds", "Operation duration"),
            &["operation", "algorithm", "namespace"],  // Indexed labels
        ).unwrap();

        Self { operation_duration }
    }

    pub fn record(&self, op: &str, algo: &str, ns: &str, duration: f64) {
        // Fast label lookup with caching
        self.operation_duration
            .with_label_values(&[op, algo, ns])
            .observe(duration);
    }
}
```

### 5. Metric Export Optimization (Priority: MEDIUM)
**Goal**: Fast Prometheus scraping

**Tasks**:
- [ ] Optimize metric serialization
- [ ] Add metric caching
- [ ] Implement incremental exports
- [ ] Profile export performance
- [ ] Benchmark scrape latency

## Feature Enhancements

### 1. Comprehensive Metric Coverage (Priority: HIGH)
**Goal**: Monitor all critical operations

**Tasks**:
- [ ] Add metrics for all crypto operations
- [ ] Add key lifecycle metrics
- [ ] Add authentication metrics
- [ ] Add storage metrics
- [ ] Add audit log metrics

**Comprehensive metrics**:
```rust
pub struct HsmMetrics {
    // Crypto operations
    sign_count: CounterVec,
    sign_errors: CounterVec,
    sign_duration: HistogramVec,

    verify_count: CounterVec,
    verify_errors: CounterVec,
    verify_duration: HistogramVec,

    encrypt_count: CounterVec,
    decrypt_count: CounterVec,

    // Key management
    key_generation_count: CounterVec,
    key_deletion_count: CounterVec,
    active_keys_gauge: GaugeVec,

    // Authentication
    auth_attempts: CounterVec,
    auth_failures: CounterVec,
    active_sessions: Gauge,

    // Storage
    storage_read_duration: Histogram,
    storage_write_duration: Histogram,
    storage_errors: Counter,

    // Audit
    audit_events_written: Counter,
    audit_queue_depth: Gauge,
    audit_write_duration: Histogram,

    // System
    cpu_usage: Gauge,
    memory_usage: Gauge,
    goroutine_count: Gauge,
}
```

### 2. Custom Metric Types (Priority: MEDIUM)
**Goal**: Support domain-specific metrics

**Tasks**:
- [ ] Add percentile metrics (p50, p95, p99)
- [ ] Add rate metrics (ops/sec)
- [ ] Add error rate metrics
- [ ] Add availability metrics
- [ ] Add SLI/SLO tracking

**SLI metrics**:
```rust
pub struct SliMetrics {
    // Availability: % of successful requests
    availability: Gauge,

    // Latency: p99 latency
    p99_latency: Gauge,

    // Error rate: errors per second
    error_rate: Gauge,
}

impl SliMetrics {
    pub fn update(&mut self, window: Duration) {
        let stats = self.compute_window_stats(window);

        self.availability.set(stats.success_rate);
        self.p99_latency.set(stats.p99_latency);
        self.error_rate.set(stats.errors_per_sec);
    }
}
```

### 3. Alerting Integration (Priority: HIGH)
**Goal**: Proactive issue detection

**Tasks**:
- [ ] Add Prometheus alerting rules
- [ ] Define critical alerts
- [ ] Add warning alerts
- [ ] Test alert firing
- [ ] Document alert runbooks

**Alert rules**:
```yaml
# prometheus_rules.yml
groups:
  - name: hsm_critical
    interval: 10s
    rules:
      - alert: HighErrorRate
        expr: rate(operation_errors_total[5m]) > 0.01
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "HSM error rate above threshold"

      - alert: HighLatency
        expr: histogram_quantile(0.99, operation_duration_seconds) > 1.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "HSM p99 latency above 1s"

      - alert: AuditQueueFull
        expr: audit_queue_depth > 1000
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Audit queue is filling up"
```

### 4. Dashboard Generation (Priority: MEDIUM)
**Goal**: Pre-built Grafana dashboards

**Tasks**:
- [ ] Create Grafana dashboard JSON
- [ ] Add operation metrics panel
- [ ] Add latency distribution panel
- [ ] Add error rate panel
- [ ] Add system resource panel

### 5. Tracing Integration (Priority: MEDIUM)
**Goal**: Distributed tracing support

**Tasks**:
- [ ] Add OpenTelemetry integration
- [ ] Implement trace spans
- [ ] Add trace context propagation
- [ ] Integrate with Jaeger/Zipkin
- [ ] Test tracing overhead

**Tracing**:
```rust
use opentelemetry::trace::{Tracer, Span};

pub async fn sign_with_tracing(
    &self,
    tracer: &impl Tracer,
    req: SignRequest,
) -> Result<SignResponse> {
    let mut span = tracer.start("sign_operation");
    span.set_attribute("key_id", req.key_id.clone());
    span.set_attribute("algorithm", format!("{:?}", req.algorithm));

    let result = self.sign_internal(req).await;

    if let Err(ref e) = result {
        span.record_error(e);
    }

    span.end();
    result
}
```

## Reliability Enhancements

### 1. Metric Durability (Priority: MEDIUM)
**Goal**: Persist critical metrics

**Tasks**:
- [ ] Add metric persistence
- [ ] Implement metric recovery on restart
- [ ] Add metric checkpointing
- [ ] Test recovery behavior
- [ ] Document persistence guarantees

### 2. Health Metrics (Priority: HIGH)
**Goal**: Monitor HSM health

**Tasks**:
- [ ] Add health check metrics
- [ ] Monitor component availability
- [ ] Track dependency health
- [ ] Add saturation metrics
- [ ] Implement USE method (Utilization, Saturation, Errors)

**Health metrics**:
```rust
pub struct HealthMetrics {
    // Component health (0 = unhealthy, 1 = healthy)
    crypto_engine_health: Gauge,
    storage_health: Gauge,
    audit_health: Gauge,

    // Resource saturation (0-1)
    cpu_saturation: Gauge,
    memory_saturation: Gauge,
    disk_saturation: Gauge,

    // Error counts
    component_errors: CounterVec,
}
```

### 3. Metric Validation (Priority: MEDIUM)
**Goal**: Ensure metric accuracy

**Tasks**:
- [ ] Add metric consistency checks
- [ ] Validate metric ranges
- [ ] Add metric unit tests
- [ ] Test metric accuracy
- [ ] Document metric definitions

### 4. Cardinality Control (Priority: HIGH)
**Goal**: Prevent metric explosion

**Tasks**:
- [ ] Limit label cardinality
- [ ] Add cardinality monitoring
- [ ] Implement label allowlists
- [ ] Detect high-cardinality labels
- [ ] Add cardinality alerts

**Cardinality control**:
```rust
pub struct CardinalityLimiter {
    max_cardinality: usize,
    current_labels: HashSet<String>,
}

impl CardinalityLimiter {
    pub fn check_label(&mut self, label: &str) -> Result<()> {
        if self.current_labels.contains(label) {
            return Ok(());
        }

        if self.current_labels.len() >= self.max_cardinality {
            return Err(MetricsError::CardinalityExceeded {
                max: self.max_cardinality,
                label: label.to_string(),
            });
        }

        self.current_labels.insert(label.to_string());
        Ok(())
    }
}
```

## Testing Enhancements

### 1. Metric Accuracy Tests (Priority: HIGH)
**Goal**: Verify metrics are correct

**Tasks**:
- [ ] Test counter increments
- [ ] Test histogram recording
- [ ] Test gauge updates
- [ ] Verify metric labels
- [ ] Test metric aggregation

**Accuracy test**:
```rust
#[tokio::test]
async fn test_sign_metrics_accuracy() {
    let metrics = Metrics::new();

    // Perform 100 sign operations
    for _ in 0..100 {
        metrics.record_sign(Duration::from_millis(10));
    }

    // Verify counter
    let count = metrics.sign_operations.load(Ordering::Relaxed);
    assert_eq!(count, 100);

    // Verify histogram
    let histogram = metrics.sign_duration.clone();
    assert_eq!(histogram.get_sample_count(), 100);
}
```

### 2. Performance Tests (Priority: HIGH)
**Goal**: Verify low overhead

**Tasks**:
- [ ] Benchmark metric update latency
- [ ] Test overhead under load
- [ ] Verify sampling effectiveness
- [ ] Profile metric collection
- [ ] Test export performance

### 3. Integration Tests (Priority: MEDIUM)
**Goal**: End-to-end metric flow

**Tasks**:
- [ ] Test Prometheus scraping
- [ ] Verify metric format
- [ ] Test alert rules
- [ ] Test dashboard rendering
- [ ] Test tracing integration

## Success Metrics

**Performance**:
- ✅ Metric update overhead: < 10μs p99
- ✅ Scrape latency: < 100ms
- ✅ Memory overhead: < 50MB for 10k metrics
- ✅ CPU overhead: < 1% for metric collection

**Coverage**:
- ✅ All critical operations have metrics
- ✅ Latency histograms for all operations
- ✅ Error counters for all error types
- ✅ Health metrics for all components

**Reliability**:
- ✅ Metrics accurate in all tests
- ✅ Cardinality controlled (< 10k labels)
- ✅ Alerts fire correctly
- ✅ > 90% test coverage

## Claude Agent Instructions

1. Read this enhancement plan
2. Run existing tests to verify baseline
3. Implement lock-free metric updates
4. Add comprehensive metric coverage
5. Add Prometheus alerting rules
6. Create Grafana dashboards
7. Verify performance targets (low overhead)
8. Test metric accuracy
9. Achieve all success metrics
