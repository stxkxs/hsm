//! REST API Routes
//!
//! Route definitions and router configuration.

use crate::handlers;
use crate::middleware::{
    auth_middleware, rate_limit_middleware, request_tracking_middleware, AppState,
};
use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
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

    // Combine authenticated routes
    let authenticated_routes = Router::new()
        .nest("/keys", key_routes)
        .nest("/keys", crypto_routes)
        .nest("/audit", audit_routes)
        .nest("/auth", auth_routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Build the full router with middleware stack:
    // 1. Request timeout (30s)
    // 2. Rate limiting
    // 3. Request tracking (logging, metrics)
    Router::new()
        .merge(public_routes)
        .merge(authenticated_routes)
        .layer(
            ServiceBuilder::new()
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
}
