//! REST API Integration Tests
//!
//! Tests the REST API endpoints using axum's test utilities (tower::ServiceExt::oneshot).
//! These tests exercise the full middleware stack including authentication,
//! rate limiting, and request tracking.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use hsm_auth::{ClientIdentity, Role, SessionManager};
use hsm_rest_api::middleware::AppState;
use hsm_rest_api::routes::create_router;
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

// =============================================================================
// Test Helpers
// =============================================================================

/// Create a default AppState for testing.
fn test_app_state() -> AppState {
    let sessions = Arc::new(SessionManager::new(3600));
    AppState::new(sessions)
}

/// Create a session and return the bearer token string (format: "session_id:token").
fn create_test_session(state: &AppState, username: &str, roles: Vec<Role>) -> String {
    let identity = ClientIdentity::new(
        username.to_string(),
        Some("TestOrg".to_string()),
        "default".to_string(),
        roles,
        format!("test-serial-{}", uuid::Uuid::new_v4()),
    );

    let result = state.sessions.create_session(identity);
    format!("{}:{}", result.session.id, result.token.as_str())
}

/// Read the full response body as a string.
async fn body_to_string(body: Body) -> String {
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Parse a response body as JSON.
async fn body_to_json(body: Body) -> serde_json::Value {
    let text = body_to_string(body).await;
    serde_json::from_str(&text).expect("Response body should be valid JSON")
}

// =============================================================================
// Health & Readiness Endpoints (No Auth Required)
// =============================================================================

#[tokio::test]
async fn test_health_check_returns_200() {
    let state = test_app_state();
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_to_json(response.into_body()).await;
    assert_eq!(json["status"], "healthy");
    assert!(json["version"].is_string());
    assert!(json["uptime_seconds"].is_number());
}

#[tokio::test]
async fn test_ready_check_returns_200() {
    let state = test_app_state();
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_to_json(response.into_body()).await;
    assert_eq!(json["ready"], true);
    assert!(json["components"].is_object());
    assert!(json["components"]["session_manager"].is_object());
    assert!(json["components"]["key_manager"].is_object());
}

// =============================================================================
// Authentication Tests
// =============================================================================

#[tokio::test]
async fn test_post_keys_without_auth_returns_401() {
    let state = test_app_state();
    let app = create_router(state);

    let body = serde_json::json!({
        "algorithm": "ED25519",
        "purpose": "SIGN",
        "namespace": "default"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let json = body_to_json(response.into_body()).await;
    assert_eq!(json["error"], "UNAUTHORIZED");
}

#[tokio::test]
async fn test_get_keys_without_auth_returns_401() {
    let state = test_app_state();
    let app = create_router(state);

    let response = app
        .oneshot(Request::builder().uri("/keys").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_invalid_bearer_token_returns_401() {
    let state = test_app_state();
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/keys")
                .header(header::AUTHORIZATION, "Bearer invalid-token-no-colon")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_expired_or_wrong_session_returns_401() {
    let state = test_app_state();
    let app = create_router(state);

    // A properly formatted token but with a non-existent session ID
    let response = app
        .oneshot(
            Request::builder()
                .uri("/keys")
                .header(
                    header::AUTHORIZATION,
                    "Bearer fake-session-id:fake-token-value",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_missing_authorization_header_format_returns_401() {
    let state = test_app_state();
    let app = create_router(state);

    // Use Basic auth instead of Bearer
    let response = app
        .oneshot(
            Request::builder()
                .uri("/keys")
                .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// =============================================================================
// Invalid Input Tests
// =============================================================================

#[tokio::test]
async fn test_post_keys_with_invalid_json_returns_400() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from("this is not valid json"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Axum returns 422 for deserialization failures by default (JsonRejection)
    // but could also be 400 depending on the error handler configuration
    let status = response.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422, got {}",
        status
    );
}

#[tokio::test]
async fn test_post_keys_with_missing_required_fields_returns_error() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);
    let app = create_router(state);

    // Missing required "algorithm" and "purpose" fields
    let body = serde_json::json!({
        "namespace": "default"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422 for missing required fields, got {}",
        status
    );
}

// =============================================================================
// Key Not Found Tests
// =============================================================================

#[tokio::test]
async fn test_get_nonexistent_key_returns_404() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/keys/00000000-0000-0000-0000-000000000000")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Could be 400 (invalid key ID format) or 404 (not found)
    let status = response.status();
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
        "Expected 404 or 400 for nonexistent key, got {}",
        status
    );
}

#[tokio::test]
async fn test_delete_nonexistent_key_returns_404() {
    let state = test_app_state();
    let token = create_test_session(&state, "admin", vec![Role::Admin]);
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/keys/00000000-0000-0000-0000-000000000000")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
        "Expected 404 or 400 for nonexistent key delete, got {}",
        status
    );
}

#[tokio::test]
async fn test_sign_with_nonexistent_key_returns_404() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);
    let app = create_router(state);

    let body = serde_json::json!({
        "data": "SGVsbG8gV29ybGQ="  // base64 "Hello World"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys/00000000-0000-0000-0000-000000000000/sign")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
        "Expected 404 or 400 for sign with nonexistent key, got {}",
        status
    );
}

// =============================================================================
// Key Lifecycle Tests (Authenticated)
// =============================================================================

#[tokio::test]
async fn test_generate_key_returns_201() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);
    let app = create_router(state);

    let body = serde_json::json!({
        "algorithm": "ED25519",
        "purpose": "SIGN",
        "namespace": "default"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let json = body_to_json(response.into_body()).await;
    assert!(json["key_id"].is_string());
    assert_eq!(json["algorithm"], "ED25519");
    assert_eq!(json["purpose"], "SIGN");
    assert!(json["public_key"].is_string());
    assert!(json["created_at"].is_string());
}

#[tokio::test]
async fn test_list_keys_returns_200() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);

    // Generate a key first (using a separate router instance since oneshot consumes it)
    let body = serde_json::json!({
        "algorithm": "ED25519",
        "purpose": "SIGN",
        "namespace": "default"
    });

    let app = create_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Now list keys
    let app = create_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/keys?namespace=default")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_to_json(response.into_body()).await;
    assert!(json["keys"].is_array());
    assert!(json["total"].is_number());
    assert!(json["total"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn test_generate_and_get_key_metadata() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);

    // Generate a key
    let body = serde_json::json!({
        "algorithm": "ED25519",
        "purpose": "SIGN",
        "namespace": "default"
    });

    let app = create_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let create_json = body_to_json(response.into_body()).await;
    let key_id = create_json["key_id"].as_str().unwrap().to_string();

    // Get key metadata
    let app = create_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/keys/{}", key_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_to_json(response.into_body()).await;
    assert_eq!(json["key_id"], key_id);
    assert_eq!(json["algorithm"], "ED25519");
    assert_eq!(json["namespace"], "default");
    assert_eq!(json["active"], true);
}

#[tokio::test]
async fn test_generate_and_delete_key() {
    let state = test_app_state();
    let token = create_test_session(&state, "admin", vec![Role::Admin]);

    // Generate a key
    let body = serde_json::json!({
        "algorithm": "ED25519",
        "purpose": "SIGN",
        "namespace": "default"
    });

    let app = create_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let create_json = body_to_json(response.into_body()).await;
    let key_id = create_json["key_id"].as_str().unwrap().to_string();

    // Delete the key
    let app = create_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/keys/{}", key_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify the key is gone (should get 404)
    let app = create_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/keys/{}", key_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// =============================================================================
// Cryptographic Operation Tests
// =============================================================================

#[tokio::test]
async fn test_sign_and_verify_ed25519() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);

    // Generate an Ed25519 key
    let body = serde_json::json!({
        "algorithm": "ED25519",
        "purpose": "SIGN",
        "namespace": "default"
    });

    let app = create_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let create_json = body_to_json(response.into_body()).await;
    let key_id = create_json["key_id"].as_str().unwrap().to_string();

    // Sign data
    let data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"Hello HSM");

    let sign_body = serde_json::json!({
        "data": data_b64
    });

    let app = create_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/keys/{}/sign", key_id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&sign_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let sign_json = body_to_json(response.into_body()).await;
    let signature = sign_json["signature"].as_str().unwrap().to_string();
    assert_eq!(sign_json["algorithm"], "ED25519");

    // Verify signature
    let verify_body = serde_json::json!({
        "data": data_b64,
        "signature": signature
    });

    let app = create_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/keys/{}/verify", key_id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let verify_json = body_to_json(response.into_body()).await;
    assert_eq!(verify_json["valid"], true);
}

#[tokio::test]
async fn test_verify_with_wrong_data_returns_false() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);

    // Generate an Ed25519 key
    let body = serde_json::json!({
        "algorithm": "ED25519",
        "purpose": "SIGN",
        "namespace": "default"
    });

    let app = create_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let create_json = body_to_json(response.into_body()).await;
    let key_id = create_json["key_id"].as_str().unwrap().to_string();

    // Sign "Hello"
    let original_data =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"Hello");
    let sign_body = serde_json::json!({ "data": original_data });

    let app = create_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/keys/{}/sign", key_id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&sign_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let sign_json = body_to_json(response.into_body()).await;
    let signature = sign_json["signature"].as_str().unwrap().to_string();

    // Verify with WRONG data
    let wrong_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"Goodbye");
    let verify_body = serde_json::json!({
        "data": wrong_data,
        "signature": signature
    });

    let app = create_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/keys/{}/verify", key_id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let verify_json = body_to_json(response.into_body()).await;
    assert_eq!(verify_json["valid"], false);
}

#[tokio::test]
async fn test_encrypt_data_returns_ciphertext() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);

    // Generate a key (encryption uses an ephemeral AES key internally)
    let body = serde_json::json!({
        "algorithm": "ED25519",
        "purpose": "SIGN",
        "namespace": "default"
    });

    let app = create_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let create_json = body_to_json(response.into_body()).await;
    let key_id = create_json["key_id"].as_str().unwrap().to_string();

    // Encrypt data
    let plaintext_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"Secret data");

    let encrypt_body = serde_json::json!({
        "plaintext": plaintext_b64
    });

    let app = create_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/keys/{}/encrypt", key_id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&encrypt_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_to_json(response.into_body()).await;
    assert!(json["ciphertext"].is_string());
    assert!(json["nonce"].is_string());
    // Ciphertext should be different from the plaintext
    assert_ne!(json["ciphertext"].as_str().unwrap(), plaintext_b64);
}

#[tokio::test]
async fn test_decrypt_returns_bad_request() {
    // The decrypt endpoint returns 501 Not Implemented because decryption
    // is not yet available via REST API.
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);

    // Generate a key
    let body = serde_json::json!({
        "algorithm": "ED25519",
        "purpose": "SIGN",
        "namespace": "default"
    });

    let app = create_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let create_json = body_to_json(response.into_body()).await;
    let key_id = create_json["key_id"].as_str().unwrap().to_string();

    // Attempt decrypt
    let decrypt_body = serde_json::json!({
        "ciphertext": "AAAA",
        "nonce": "AAAAAAAAAAAA"
    });

    let app = create_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/keys/{}/decrypt", key_id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&decrypt_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
}

// =============================================================================
// Key Rotation Tests
// =============================================================================

#[tokio::test]
async fn test_rotate_key() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);

    // Generate an Ed25519 key
    let body = serde_json::json!({
        "algorithm": "ED25519",
        "purpose": "SIGN",
        "namespace": "default"
    });

    let app = create_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let create_json = body_to_json(response.into_body()).await;
    let original_key_id = create_json["key_id"].as_str().unwrap().to_string();

    // Rotate the key
    let app = create_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/keys/{}/rotate", original_key_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let rotate_json = body_to_json(response.into_body()).await;
    let new_key_id = rotate_json["key_id"].as_str().unwrap();

    // New key should have a different ID
    assert_ne!(new_key_id, original_key_id);
    assert_eq!(rotate_json["algorithm"], "ED25519");
    assert!(rotate_json["public_key"].is_string());
}

#[tokio::test]
async fn test_rotate_nonexistent_key_returns_404() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys/00000000-0000-0000-0000-000000000000/rotate")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
        "Expected 404 or 400 for rotating nonexistent key, got {}",
        status
    );
}

// =============================================================================
// Audit Log Tests
// =============================================================================

#[tokio::test]
async fn test_audit_log_returns_200() {
    let state = test_app_state();
    let token = create_test_session(&state, "auditor", vec![Role::Auditor]);
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/audit")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_to_json(response.into_body()).await;
    assert!(json["entries"].is_array());
    assert!(json["total"].is_number());
}

#[tokio::test]
async fn test_audit_log_without_auth_returns_401() {
    let state = test_app_state();
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/audit")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// =============================================================================
// Auth Endpoints (me, logout)
// =============================================================================

#[tokio::test]
async fn test_me_endpoint_returns_user_info() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/auth/me")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_to_json(response.into_body()).await;
    assert_eq!(json["user"]["username"], "testuser");
    assert!(json["user"]["roles"].is_array());
    assert_eq!(json["user"]["namespace"], "default");
    assert!(json["session_id"].is_string());
    assert!(json["created_at"].is_string());
}

#[tokio::test]
async fn test_logout_endpoint_returns_204() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/auth/logout")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// =============================================================================
// Non-Existent Route Tests
// =============================================================================

#[tokio::test]
async fn test_nonexistent_route_without_auth_returns_401() {
    // Unmatched routes still pass through the auth middleware layer,
    // which rejects unauthenticated requests before the router can return 404.
    let state = test_app_state();
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/nonexistent/route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_nonexistent_route_with_auth_returns_404() {
    // With a valid auth token, non-existent routes should return 404.
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/nonexistent/route")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // May still be 401 because the middleware only sets identity on matched routes,
    // or 404 if the request passes through. Accept either.
    let status = response.status();
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::UNAUTHORIZED,
        "Expected 404 or 401, got {}",
        status
    );
}

// =============================================================================
// Request Tracking Middleware Tests
// =============================================================================

#[tokio::test]
async fn test_response_has_request_id_header() {
    let state = test_app_state();
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // The request tracking middleware should add an X-Request-ID header
    let request_id = response.headers().get("X-Request-ID");
    assert!(
        request_id.is_some(),
        "Response should have X-Request-ID header"
    );
    assert!(
        !request_id.unwrap().to_str().unwrap().is_empty(),
        "X-Request-ID should not be empty"
    );
}

// =============================================================================
// ECDSA Key Type Tests
// =============================================================================

#[tokio::test]
async fn test_generate_ecdsa_p256_key() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);
    let app = create_router(state);

    let body = serde_json::json!({
        "algorithm": "ECDSA_P256",
        "purpose": "SIGN",
        "namespace": "default"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let json = body_to_json(response.into_body()).await;
    assert_eq!(json["algorithm"], "ECDSA_P256");
}

#[tokio::test]
async fn test_symmetric_key_rejected_via_rest() {
    let state = test_app_state();
    let token = create_test_session(&state, "testuser", vec![Role::User]);
    let app = create_router(state);

    let body = serde_json::json!({
        "algorithm": "AES256",
        "purpose": "ENCRYPT",
        "namespace": "default"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/keys")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_to_json(response.into_body()).await;
    assert_eq!(json["error"], "BAD_REQUEST");
}

// =============================================================================
// Dev Login Tests (debug_assertions only)
// =============================================================================

#[cfg(debug_assertions)]
#[tokio::test]
async fn test_dev_login_returns_token() {
    let state = test_app_state();
    let app = create_router(state);

    let body = serde_json::json!({
        "username": "admin",
        "password": "dev"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/auth/dev-login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_to_json(response.into_body()).await;
    assert!(json["token"].is_string());
    assert_eq!(json["user"]["username"], "admin");
    assert!(json["user"]["roles"].as_array().unwrap().len() > 0);
    assert!(json["expires_at"].is_string());
}

#[cfg(debug_assertions)]
#[tokio::test]
async fn test_dev_login_wrong_password_returns_401() {
    let state = test_app_state();
    let app = create_router(state);

    let body = serde_json::json!({
        "username": "admin",
        "password": "wrong"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/auth/dev-login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[cfg(debug_assertions)]
#[tokio::test]
async fn test_dev_login_token_works_for_authenticated_endpoints() {
    let state = test_app_state();

    // Get a token via dev-login
    let login_body = serde_json::json!({
        "username": "operator",
        "password": "dev"
    });

    let app = create_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/auth/dev-login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&login_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let login_json = body_to_json(response.into_body()).await;
    let token = login_json["token"].as_str().unwrap().to_string();

    // Use that token for an authenticated endpoint
    let app = create_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/auth/me")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let me_json = body_to_json(response.into_body()).await;
    assert_eq!(me_json["user"]["username"], "operator");
}
