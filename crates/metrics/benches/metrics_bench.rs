use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use metrics::{MetricsCollector, OperationStatus, SamplingConfig};
use std::time::Duration;

fn bench_lock_free_counters(c: &mut Criterion) {
    let collector = MetricsCollector::new().unwrap();
    let duration = Duration::from_micros(100);

    c.bench_function("record_sign_atomic", |b| {
        b.iter(|| {
            collector.record_sign(
                black_box("rsa-2048"),
                black_box("default"),
                black_box(duration),
            )
        })
    });

    c.bench_function("record_verify_atomic", |b| {
        b.iter(|| {
            collector.record_verify(
                black_box("rsa-2048"),
                black_box("default"),
                black_box(duration),
            )
        })
    });

    c.bench_function("record_encrypt_atomic", |b| {
        b.iter(|| {
            collector.record_encrypt(
                black_box("aes-256"),
                black_box("default"),
                black_box(duration),
            )
        })
    });

    c.bench_function("record_decrypt_atomic", |b| {
        b.iter(|| {
            collector.record_decrypt(
                black_box("aes-256"),
                black_box("default"),
                black_box(duration),
            )
        })
    });
}

fn bench_sampling_rates(c: &mut Criterion) {
    let mut group = c.benchmark_group("sampling");

    for sample_rate in [1.0, 0.5, 0.1, 0.01].iter() {
        let collector = MetricsCollector::with_config(
            prometheus::Registry::new(),
            10_000,
            SamplingConfig::new(*sample_rate),
        )
        .unwrap();

        let duration = Duration::from_micros(100);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}%", (sample_rate * 100.0) as i32)),
            sample_rate,
            |b, _| {
                b.iter(|| {
                    collector.record_sign(
                        black_box("rsa-2048"),
                        black_box("default"),
                        black_box(duration),
                    )
                })
            },
        );
    }

    group.finish();
}

fn bench_operation_recording(c: &mut Criterion) {
    let collector = MetricsCollector::new().unwrap();

    c.bench_function("record_operation", |b| {
        b.iter(|| {
            collector.record_operation(
                black_box("sign"),
                black_box("rsa-2048"),
                black_box("default"),
                black_box(OperationStatus::Success),
            )
        })
    });

    c.bench_function("record_operation_duration", |b| {
        b.iter(|| {
            collector.record_operation_duration(
                black_box("sign"),
                black_box("rsa-2048"),
                black_box(0.123),
            )
        })
    });
}

fn bench_comprehensive_metrics(c: &mut Criterion) {
    let collector = MetricsCollector::new().unwrap();
    let duration = Duration::from_micros(100);

    c.bench_function("record_error", |b| {
        b.iter(|| collector.record_error(black_box("sign"), black_box("invalid_key")))
    });

    c.bench_function("record_key_generation", |b| {
        b.iter(|| collector.record_key_generation(black_box("rsa-2048"), black_box("default")))
    });

    c.bench_function("record_auth_attempt", |b| {
        b.iter(|| collector.record_auth_attempt(black_box("tls"), black_box("success")))
    });

    c.bench_function("record_storage_read", |b| {
        b.iter(|| collector.record_storage_read(black_box(duration)))
    });

    c.bench_function("record_audit_event", |b| {
        b.iter(|| collector.record_audit_event())
    });
}

fn bench_cardinality_control(c: &mut Criterion) {
    let collector = MetricsCollector::new().unwrap();

    c.bench_function("check_label_hit", |b| {
        // Pre-populate
        let _ = collector.check_label("test_label");

        b.iter(|| {
            let _ = collector.check_label(black_box("test_label"));
        })
    });

    c.bench_function("check_label_miss", |b| {
        let mut counter = 0;
        b.iter(|| {
            counter += 1;
            let _ = collector.check_label(black_box(&format!("label_{}", counter)));
        })
    });

    c.bench_function("get_cardinality", |b| {
        b.iter(|| black_box(collector.get_cardinality()))
    });
}

fn bench_metric_collection(c: &mut Criterion) {
    let collector = MetricsCollector::new().unwrap();

    // Pre-populate with some metrics
    for i in 0..100 {
        collector.record_operation(
            "sign",
            "rsa-2048",
            &format!("namespace_{}", i % 10),
            OperationStatus::Success,
        );
    }

    c.bench_function("gather_metrics", |b| {
        b.iter(|| black_box(collector.gather()))
    });
}

fn bench_concurrent_access(c: &mut Criterion) {
    use std::sync::Arc;

    let collector = Arc::new(MetricsCollector::new().unwrap());
    let duration = Duration::from_micros(100);

    c.bench_function("concurrent_sign_recording", |b| {
        b.iter(|| {
            let c = collector.clone();
            std::thread::spawn(move || {
                c.record_sign(
                    black_box("rsa-2048"),
                    black_box("default"),
                    black_box(duration),
                )
            });
        })
    });
}

fn bench_health_metrics(c: &mut Criterion) {
    let collector = MetricsCollector::new().unwrap();

    c.bench_function("set_component_health", |b| {
        b.iter(|| collector.set_component_health(black_box("crypto_engine"), black_box(true)))
    });

    c.bench_function("set_saturation_metrics", |b| {
        b.iter(|| {
            collector.set_cpu_saturation(black_box(0.5));
            collector.set_memory_saturation(black_box(0.6));
            collector.set_disk_saturation(black_box(0.7));
        })
    });
}

criterion_group!(
    benches,
    bench_lock_free_counters,
    bench_sampling_rates,
    bench_operation_recording,
    bench_comprehensive_metrics,
    bench_cardinality_control,
    bench_metric_collection,
    bench_concurrent_access,
    bench_health_metrics,
);

criterion_main!(benches);
