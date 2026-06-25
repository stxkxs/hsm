//! REST API Routes
//!
//! Route definitions and router configuration.

use crate::handlers;
use crate::middleware::{
    auth_middleware, per_client_rate_limit_middleware, rate_limit_middleware,
    request_tracking_middleware, AppState,
};
use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, post, put},
    Router,
};

/// Maximum accepted request body size. HSM operations (key specs, signatures,
/// small payloads) are well under this; an explicit bound caps the memory a
/// single request can force the server to buffer.
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024; // 1 MiB
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;

/// Create the REST API router
pub fn create_router(state: AppState) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/ready", get(handlers::ready_check));

    #[cfg(debug_assertions)]
    let public_routes = public_routes.route("/auth/dev-login", post(handlers::dev_login));

    // Key management routes
    let key_routes = Router::new()
        .route("/", post(handlers::generate_key))
        .route("/", get(handlers::list_keys))
        .route("/{key_id}", get(handlers::get_key))
        .route("/{key_id}", delete(handlers::delete_key))
        .route("/{key_id}/rotate", post(handlers::rotate_key));

    // Cryptographic operation routes
    let crypto_routes = Router::new()
        .route("/{key_id}/sign", post(handlers::sign_data))
        .route("/{key_id}/verify", post(handlers::verify_signature))
        .route("/{key_id}/encrypt", post(handlers::encrypt_data))
        .route("/{key_id}/decrypt", post(handlers::decrypt_data));

    // Audit routes
    let audit_routes = Router::new().route("/", get(handlers::get_audit_log));

    // Auth routes (authenticated)
    let auth_routes = Router::new()
        .route("/me", get(handlers::me))
        .route("/logout", post(handlers::logout));

    // Namespace management routes (multi-tenancy isolation boundary)
    let namespace_routes = Router::new()
        .route("/", get(handlers::list_namespaces))
        .route("/", post(handlers::create_namespace))
        .route("/{name}", get(handlers::get_namespace))
        .route("/{name}", delete(handlers::delete_namespace));

    // Webhook management routes (event-notification registrations)
    let webhook_routes = Router::new()
        .route("/", get(handlers::list_webhooks))
        .route("/", post(handlers::create_webhook))
        .route("/{id}", get(handlers::get_webhook))
        .route("/{id}", put(handlers::update_webhook))
        .route("/{id}", delete(handlers::delete_webhook))
        .route("/{id}/test", post(handlers::test_webhook));

    // Combine authenticated routes
    let authenticated_routes = Router::new()
        .nest("/keys", key_routes)
        .nest("/keys", crypto_routes)
        .nest("/audit", audit_routes)
        .nest("/auth", auth_routes)
        .nest("/namespaces", namespace_routes)
        .nest("/webhooks", webhook_routes)
        // Inner layer: per-identity/per-namespace rate limiting. Added before the
        // auth layer so it runs AFTER authentication (the identity must already be
        // in the request extensions).
        .layer(middleware::from_fn_with_state(
            state.clone(),
            per_client_rate_limit_middleware,
        ))
        // Outer layer: authentication. Runs first and populates the identity.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Build the full router with middleware stack:
    // 1. Request body-size limit (bounds buffered memory per request)
    // 2. Request timeout (30s)
    // 3. Global rate limiting (pre-auth DoS protection)
    // 4. Request tracking (logging, metrics)
    Router::new()
        .merge(public_routes)
        .merge(authenticated_routes)
        .layer(
            ServiceBuilder::new()
                .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
                .layer(TimeoutLayer::with_status_code(
                    axum::http::StatusCode::REQUEST_TIMEOUT,
                    Duration::from_secs(30),
                ))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    rate_limit_middleware,
                ))
                .layer(middleware::from_fn(request_tracking_middleware)),
        )
        .with_state(state)
}

/// Create a router with CORS configured for development
pub fn create_router_with_cors(state: AppState, allowed_origins: Vec<String>) -> Router {
    let cors = if allowed_origins.contains(&"*".to_string()) {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let origins: Vec<_> = allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();

        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
            ])
    };

    create_router(state).layer(cors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hsm_auth::SessionManager;
    use std::sync::Arc;

    #[test]
    fn test_router_creation() {
        let sessions = Arc::new(SessionManager::new(3600));
        let state = AppState::new(sessions);
        let _router = create_router(state);
        // Router creation should not panic
    }

    #[tokio::test]
    async fn body_size_limit_rejects_oversized_requests() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let sessions = Arc::new(SessionManager::new(3600));
        let app = create_router(AppState::new(sessions));

        // A body larger than the configured limit, sent to a body-reading public
        // route, is rejected with 413 before the handler runs.
        let oversized = vec![b'x'; MAX_REQUEST_BODY_BYTES + 1];
        let request = Request::builder()
            .method("POST")
            .uri("/auth/dev-login")
            .header("content-type", "application/json")
            .body(Body::from(oversized))
            .expect("request");

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
