# Module 6: Metrics & Monitoring - Implementation Plan

## Agent Mission
Build a comprehensive metrics and monitoring system using Prometheus to track all HSM operations, performance, and health.

## File Structure
```
crates/metrics/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── collector.rs           # Metrics collection
│   ├── exporter.rs            # Prometheus exporter
│   ├── health.rs              # Health checks
│   └── dashboards/
│       └── grafana.json       # Grafana dashboard
└── tests/
    └── metrics_tests.rs
```

## Key Metrics
```rust
// Operation counters
hsm_operations_total{operation, algorithm, namespace, status}

// Latency histograms
hsm_operation_duration_seconds{operation, algorithm}

// Key metrics
hsm_keys_total{namespace, type, state}

// System metrics
hsm_active_connections
hsm_memory_usage_bytes
hsm_storage_usage_bytes
```

## Dependencies
```toml
[dependencies]
prometheus = "0.13"
axum = "0.7"  # For HTTP metrics endpoint
tokio = "1.35"
```

## Timeline
- Day 1: Prometheus setup + basic metrics
- Day 2: Custom metrics + collectors
- Day 3: Health checks + dashboards
- Day 4: Testing + validation
