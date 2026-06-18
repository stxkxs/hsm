use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use hsm_config::{manager::ConfigManager, HsmConfig};
use std::hint::black_box;
use std::io::Write;
use std::sync::Arc;
use tempfile::NamedTempFile;

const TEST_CONFIG: &str = r#"
[server]
host = "127.0.0.1"
port = 8080
max_connections = 1000
timeout_seconds = 30
tls_enabled = false
worker_threads = 4

[storage]
backend = "file"
data_dir = "/tmp/hsm/data"
cache_size_bytes = 104857600
wal_enabled = true
sync_mode = "normal"
max_file_size_bytes = 10485760
backup_interval_seconds = 0

[security]
key_derivation_iterations = 100000
encryption_at_rest = true
encryption_algorithm = "aes256gcm"
key_size_bits = 256
session_timeout_seconds = 3600
max_auth_attempts = 3
lockout_duration_seconds = 300
audit_log_enabled = true
require_strong_passwords = true
min_password_length = 12

[logging]
level = "info"
format = "json"
output = "console"
max_file_size_bytes = 10485760
max_backup_files = 10
colored = false
include_timestamps = true
include_module_path = true

[metrics]
enabled = true
format = "prometheus"
listen_addr = "127.0.0.1"
listen_port = 9090
collection_interval_seconds = 60
enable_histograms = true
histogram_buckets = [0.001, 0.01, 0.1, 1.0, 10.0]
retention_seconds = 3600
"#;

fn benchmark_config_read(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", TEST_CONFIG).unwrap();

    let manager =
        runtime.block_on(async { ConfigManager::from_file(temp_file.path()).await.unwrap() });

    c.bench_function("config_read_cached", |b| {
        b.iter(|| {
            let config = manager.get();
            black_box(config.server.port);
        });
    });
}

fn benchmark_config_read_concurrent(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", TEST_CONFIG).unwrap();

    let manager = runtime
        .block_on(async { Arc::new(ConfigManager::from_file(temp_file.path()).await.unwrap()) });

    let mut group = c.benchmark_group("config_read_concurrent");

    for thread_count in [1, 2, 4, 8].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(thread_count),
            thread_count,
            |b, &thread_count| {
                b.iter(|| {
                    let handles: Vec<_> = (0..thread_count)
                        .map(|_| {
                            let manager = manager.clone();
                            std::thread::spawn(move || {
                                for _ in 0..100 {
                                    let config = manager.get();
                                    black_box(config.server.port);
                                }
                            })
                        })
                        .collect();

                    for handle in handles {
                        handle.join().unwrap();
                    }
                });
            },
        );
    }
    group.finish();
}

fn benchmark_config_reload(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", TEST_CONFIG).unwrap();

    let manager =
        runtime.block_on(async { ConfigManager::from_file(temp_file.path()).await.unwrap() });

    c.bench_function("config_reload", |b| {
        b.iter(|| {
            runtime.block_on(async {
                manager.reload().await.unwrap();
            });
        });
    });
}

fn benchmark_config_default_creation(c: &mut Criterion) {
    c.bench_function("config_default_creation", |b| {
        b.iter(|| {
            let config = HsmConfig::default();
            black_box(config);
        });
    });
}

fn benchmark_config_validation(c: &mut Criterion) {
    use validator::Validate;

    let config = HsmConfig::default();

    c.bench_function("config_validation", |b| {
        b.iter(|| {
            let _: () = config.validate().unwrap();
            black_box(());
        });
    });
}

fn benchmark_config_clone(c: &mut Criterion) {
    let config = HsmConfig::default();

    c.bench_function("config_clone", |b| {
        b.iter(|| {
            let cloned = config.clone();
            black_box(cloned);
        });
    });
}

fn benchmark_config_arc_clone(c: &mut Criterion) {
    let config = Arc::new(HsmConfig::default());

    c.bench_function("config_arc_clone", |b| {
        b.iter(|| {
            let cloned = config.clone();
            black_box(cloned);
        });
    });
}

criterion_group!(
    benches,
    benchmark_config_read,
    benchmark_config_read_concurrent,
    benchmark_config_reload,
    benchmark_config_default_creation,
    benchmark_config_validation,
    benchmark_config_clone,
    benchmark_config_arc_clone,
);

criterion_main!(benches);
