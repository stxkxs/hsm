//! End-to-end coverage for the request/retry path against a real HTTP server.
//!
//! `HsmClient::request` used to retry by recursively awaiting itself, which does
//! not compile without boxing. It is now an iterative loop, so these tests pin
//! down the behaviour that rewrite has to preserve: retryable statuses are
//! retried up to `max_retries`, non-retryable statuses fail immediately, the
//! circuit breaker opens after enough failures, and a successful response is
//! decoded.

use hsm_client::{CircuitState, ClientConfig, HsmClient, HsmError, KeyState, ListKeysOptions};
use std::collections::HashMap;
use std::time::Duration;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(base_url: String, max_retries: u32) -> ClientConfig {
    ClientConfig {
        base_url,
        session_id: Some("sess".into()),
        session_token: Some("tok".into()),
        timeout: Duration::from_secs(5),
        headers: HashMap::new(),
        retry: Some(hsm_client::RetryConfig {
            max_retries,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            jitter: 0.1,
            retry_on_status: vec![429, 502, 503, 504],
        }),
    }
}

#[tokio::test]
async fn retryable_status_is_retried_then_succeeds() {
    let server = MockServer::start().await;

    // Two 503s, then a 200. The retry loop must make all three attempts.
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
            "error": "SERVICE_UNAVAILABLE", "message": "warming up"
        })))
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "ok", "version": "1.2.3", "uptime_seconds": 42
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = HsmClient::new(config(server.uri(), 3));
    let health = client.health().await.expect("should succeed after retries");

    assert_eq!(health.status, "ok");
    assert_eq!(health.version, "1.2.3");
    assert_eq!(health.uptime_seconds, 42);
    server.verify().await;
}

#[tokio::test]
async fn retries_stop_at_max_retries_and_return_the_last_error() {
    let server = MockServer::start().await;

    // max_retries = 2 => attempt 0 retries, attempt 1 retries, attempt 2 gives up.
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
            "error": "SERVICE_UNAVAILABLE", "message": "still down"
        })))
        .expect(3)
        .mount(&server)
        .await;

    let client = HsmClient::new(config(server.uri(), 2));
    let err = client.health().await.expect_err("should exhaust retries");

    match err {
        HsmError::Server {
            message,
            status_code,
        } => {
            assert_eq!(status_code, 503);
            assert_eq!(message, "still down");
        }
        other => panic!("expected a server error, got {other:?}"),
    }
    server.verify().await;
}

#[tokio::test]
async fn non_retryable_status_fails_on_the_first_attempt() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/keys/abc"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "UNAUTHORIZED", "message": "Authentication failed"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = HsmClient::new(config(server.uri(), 3));
    let err = client.get_key("abc").await.expect_err("401 must not retry");

    assert!(matches!(err, HsmError::Authentication { .. }));
    assert_eq!(err.status_code(), Some(401));
    server.verify().await;
}

#[tokio::test]
async fn circuit_opens_after_repeated_failures_and_short_circuits() {
    let server = MockServer::start().await;

    // The breaker opens after 5 recorded failures. With max_retries = 0 each call
    // records exactly one failure, so the sixth call never reaches the network.
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "error": "INTERNAL_ERROR", "message": "boom"
        })))
        .expect(5)
        .mount(&server)
        .await;

    let client = HsmClient::new(config(server.uri(), 0));
    for _ in 0..5 {
        assert!(client.health().await.is_err());
    }
    assert_eq!(client.circuit_state(), CircuitState::Open);

    let err = client.health().await.expect_err("circuit should be open");
    assert!(matches!(err, HsmError::CircuitOpen));
    server.verify().await;

    client.reset_circuit_breaker();
    assert_eq!(client.circuit_state(), CircuitState::Closed);
}

#[tokio::test]
async fn key_id_is_percent_encoded_into_the_path() {
    let server = MockServer::start().await;

    // A key id containing `/`, a space and `?` must arrive as one path segment,
    // not as extra segments or a query string.
    Mock::given(method("GET"))
        .and(path("/keys/team%2Fkey%20one%3Fx"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "key_id": "team/key one?x",
            "algorithm": "ED25519",
            "purpose": "SIGN",
            "namespace": "default",
            "created_at": "2026-07-31T00:00:00Z",
            "active": true
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = HsmClient::new(config(server.uri(), 0));
    let meta = client
        .get_key("team/key one?x")
        .await
        .expect("encoded path should route to the mock");

    assert_eq!(meta.key_id, "team/key one?x");
    server.verify().await;
}

#[tokio::test]
async fn list_keys_sends_the_wire_value_for_the_state_filter() {
    let server = MockServer::start().await;

    // Not `state=Active` (the Debug rendering), which the API rejects.
    Mock::given(method("GET"))
        .and(path("/keys"))
        .and(query_param("state", "ACTIVE"))
        .and(query_param("namespace", "prod team"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": [], "total": 0
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = HsmClient::new(config(server.uri(), 0));
    let listed = client
        .list_keys(Some(ListKeysOptions {
            namespace: Some("prod team".into()),
            state: Some(KeyState::Active),
            ..Default::default()
        }))
        .await
        .expect("list should match the mock");

    assert_eq!(listed.total, 0);
    server.verify().await;
}

#[tokio::test]
async fn request_timeout_is_reported_as_timeout_not_network() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;

    let mut cfg = config(server.uri(), 0);
    cfg.timeout = Duration::from_millis(50);
    let client = HsmClient::new(cfg);

    // `HsmError::Timeout` exists and is documented; before, every transport
    // failure — timeouts included — was flattened into `HsmError::Network`.
    let err = client.health().await.expect_err("should time out");
    assert!(matches!(err, HsmError::Timeout), "got {err:?}");
    assert_eq!(client.circuit_state(), CircuitState::Closed);
}

#[tokio::test]
async fn empty_success_body_is_accepted_for_delete() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/keys/k1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = HsmClient::new(config(server.uri(), 0));
    client
        .delete_key("k1")
        .await
        .expect("204 should deserialize");
    server.verify().await;
}
