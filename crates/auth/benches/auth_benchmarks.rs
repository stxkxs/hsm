// Performance benchmarks for authentication and authorization
// Targets:
// - Certificate validation: < 5ms p99 (< 100μs cached)
// - Permission checks: < 100μs p99
// - Session lookup: < 50μs p99
// - Concurrent sessions: > 10,000

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hsm_auth::*;
use rcgen::{CertificateParams, DistinguishedName, DnType};
use std::time::Duration;

// Helper to generate test certificates
fn generate_test_certs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();
    let ca_pem = ca_cert.serialize_pem().unwrap().into_bytes();

    // Server cert
    let mut server_params = CertificateParams::default();
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "Test Server");

    let server_cert = rcgen::Certificate::from_params(server_params).unwrap();
    let server_cert_pem = server_cert
        .serialize_pem_with_signer(&ca_cert)
        .unwrap()
        .into_bytes();
    let server_key_pem = server_cert.serialize_private_key_pem().into_bytes();

    (ca_pem, server_cert_pem, server_key_pem)
}

fn generate_client_cert(ca_cert: &rcgen::Certificate, common_name: &str) -> Vec<u8> {
    let mut client_params = CertificateParams::default();
    client_params.distinguished_name = DistinguishedName::new();
    client_params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    client_params.distinguished_name.push(
        DnType::OrganizationalUnitName,
        format!("namespace={}", "default"),
    );
    client_params
        .distinguished_name
        .push(DnType::OrganizationName, "roles=user");

    let client_cert = rcgen::Certificate::from_params(client_params).unwrap();
    client_cert
        .serialize_pem_with_signer(ca_cert)
        .unwrap()
        .into_bytes()
}

// Benchmark 1: Certificate validation (with and without caching)
fn bench_cert_validation(c: &mut Criterion) {
    let (ca_pem, _, _) = generate_test_certs();
    let ca_cert = rcgen::Certificate::from_params({
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
    })
    .unwrap();

    let validator = CertificateValidator::new(&ca_pem).unwrap();
    let client_cert_pem = generate_client_cert(&ca_cert, "benchmark-client");

    let mut group = c.benchmark_group("certificate_validation");
    group.measurement_time(Duration::from_secs(10));

    // First validation (cold cache)
    group.bench_function("cold_cache", |b| {
        b.iter(|| {
            let _ = validator.validate(black_box(&client_cert_pem));
        });
    });

    // Warm up cache
    let _ = validator.validate(&client_cert_pem);

    // Cached validation (should be < 100μs)
    group.bench_function("warm_cache", |b| {
        b.iter(|| {
            let _ = validator.validate(black_box(&client_cert_pem));
        });
    });

    group.finish();
}

// Benchmark 2: Permission checks with bitflags
fn bench_permission_checks(c: &mut Criterion) {
    let policy = RbacPolicy::new();
    policy.grant_permission(&Role::User, &Permission::Sign);
    policy.grant_permission(&Role::User, &Permission::Encrypt);

    let mut group = c.benchmark_group("permission_checks");

    // Single permission check (target: < 100μs)
    group.bench_function("single_check", |b| {
        b.iter(|| {
            let _ = policy.can_any(black_box(&vec![Role::User]), black_box(&Permission::Sign));
        });
    });

    // Multiple permission checks
    group.bench_function("multiple_checks", |b| {
        b.iter(|| {
            for perm in &[Permission::Sign, Permission::Encrypt, Permission::Decrypt] {
                let _ = policy.can_any(black_box(&vec![Role::User]), black_box(perm));
            }
        });
    });

    group.finish();
}

// Benchmark 3: Session operations
fn bench_session_operations(c: &mut Criterion) {
    let session_manager = SessionManager::new(3600);
    let identity = ClientIdentity::new(
        "bench-client".to_string(),
        None,
        "default".to_string(),
        vec![Role::User],
        "123456".to_string(),
    );

    let mut group = c.benchmark_group("session_operations");

    // Session creation
    group.bench_function("create_session", |b| {
        b.iter(|| {
            let _ = session_manager.create_session(black_box(identity.clone()));
        });
    });

    // Session lookup (target: < 50μs)
    let result = session_manager.create_session(identity.clone());
    group.bench_function("lookup_session", |b| {
        b.iter(|| {
            let _ = session_manager.get_session(black_box(&result.session.id));
        });
    });

    // Session validation (target: < 50μs)
    group.bench_function("validate_session", |b| {
        b.iter(|| {
            let _ = session_manager.validate_session(black_box(&result.session.id));
        });
    });

    // Session validation with token (new benchmark)
    group.bench_function("validate_session_with_token", |b| {
        b.iter(|| {
            let _ = session_manager.validate_session_with_token(
                black_box(&result.session.id),
                black_box(&result.token),
            );
        });
    });

    group.finish();
}

// Benchmark 4: Namespace lookups
fn bench_namespace_operations(c: &mut Criterion) {
    let namespace_manager = NamespaceManager::new();
    namespace_manager.create_namespace("test-ns").unwrap();

    let identity = ClientIdentity::new(
        "bench-client".to_string(),
        None,
        "test-ns".to_string(),
        vec![Role::User],
        "123456".to_string(),
    );

    let mut group = c.benchmark_group("namespace_operations");

    // Namespace access check (target: < 50μs)
    group.bench_function("has_access", |b| {
        b.iter(|| {
            let _ = namespace_manager.has_access(black_box(&identity), black_box("test-ns"));
        });
    });

    group.finish();
}

// Benchmark 5: Rate limiting
fn bench_rate_limiting(c: &mut Criterion) {
    let rate_limiter = RateLimiter::new();
    let identity = ClientIdentity::new(
        "bench-client".to_string(),
        None,
        "default".to_string(),
        vec![Role::User],
        "123456".to_string(),
    );

    let mut group = c.benchmark_group("rate_limiting");

    group.bench_function("check_rate_limit", |b| {
        b.iter(|| {
            let _ = rate_limiter.check(black_box(&identity), black_box("default"));
        });
    });

    group.finish();
}

// Benchmark 6: Concurrent session stress test
fn bench_concurrent_sessions(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;

    let mut group = c.benchmark_group("concurrent_sessions");
    group.sample_size(10); // Reduce sample size for heavy tests

    for session_count in [100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(session_count),
            session_count,
            |b, &count| {
                b.iter(|| {
                    let session_manager = Arc::new(SessionManager::new(3600));
                    let mut handles = vec![];

                    // Create sessions concurrently
                    for i in 0..count {
                        let manager = Arc::clone(&session_manager);
                        let handle = thread::spawn(move || {
                            let identity = ClientIdentity::new(
                                format!("client-{}", i),
                                None,
                                "default".to_string(),
                                vec![Role::User],
                                format!("{}", i),
                            );
                            manager.create_session(identity);
                        });
                        handles.push(handle);
                    }

                    for handle in handles {
                        handle.join().unwrap();
                    }

                    black_box(session_manager.active_session_count());
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_cert_validation,
    bench_permission_checks,
    bench_session_operations,
    bench_namespace_operations,
    bench_rate_limiting,
    bench_concurrent_sessions
);

criterion_main!(benches);
