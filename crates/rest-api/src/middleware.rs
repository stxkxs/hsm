//! REST API Middleware
//!
//! Middleware for authentication, request tracking, and rate limiting.

use crate::error::ApiError;
use axum::{
    extract::{Request, State},
    http::{header, HeaderValue},
    middleware::Next,
    response::Response,
};
use hsm_audit::AsyncAuditLogger;
use hsm_auth::{
    AclManager, ClientIdentity, NamespaceManager, RateLimiter, RbacPolicy, SessionManager,
    SessionToken,
};
use hsm_key_manager::{DefaultKeyManager, KeyManager};
use hsm_webhooks::WebhookRegistry;
use std::sync::Arc;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    /// Session manager for authentication
    pub sessions: Arc<SessionManager>,
    /// Key manager for key operations
    pub key_manager: Arc<dyn KeyManager>,
    /// Rate limiter for request throttling
    pub rate_limiter: Arc<RateLimiter>,
    /// RBAC policy engine — maps roles to permissions (authorization layer 2).
    pub rbac: Arc<RbacPolicy>,
    /// Namespace manager — enforces tenant isolation (authorization layer 1).
    pub namespaces: Arc<NamespaceManager>,
    /// Per-key ACL manager — fine-grained key access control (authorization layer 3).
    pub acls: Arc<AclManager>,
    /// Webhook registry — stores event-notification registrations served by the
    /// `/webhooks` routes and consulted by the dispatcher on lifecycle events.
    pub webhooks: Arc<WebhookRegistry>,
    /// Tamper-evident audit logger. When present, every crypto and
    /// key-lifecycle operation is logged fail-closed before the response is
    /// returned. `None` only in lightweight unit tests that do not exercise
    /// the audit path.
    pub audit: Option<Arc<AsyncAuditLogger>>,
    /// Start time for uptime calculation
    pub start_time: std::time::Instant,
}

impl AppState {
    /// Create new application state
    pub fn new(sessions: Arc<SessionManager>) -> Self {
        Self {
            sessions,
            key_manager: Arc::new(DefaultKeyManager::new()),
            rate_limiter: Arc::new(RateLimiter::new()),
            rbac: Arc::new(RbacPolicy::new()),
            namespaces: Arc::new(NamespaceManager::new()),
            acls: Arc::new(AclManager::new()),
            webhooks: Arc::new(WebhookRegistry::new()),
            audit: None,
            start_time: std::time::Instant::now(),
        }
    }

    /// Create new application state with custom key manager
    pub fn with_key_manager(
        sessions: Arc<SessionManager>,
        key_manager: Arc<dyn KeyManager>,
    ) -> Self {
        Self {
            sessions,
            key_manager,
            rate_limiter: Arc::new(RateLimiter::new()),
            rbac: Arc::new(RbacPolicy::new()),
            namespaces: Arc::new(NamespaceManager::new()),
            acls: Arc::new(AclManager::new()),
            webhooks: Arc::new(WebhookRegistry::new()),
            audit: None,
            start_time: std::time::Instant::now(),
        }
    }

    /// Attach a tamper-evident audit logger to this state.
    ///
    /// Once attached, mutating and cryptographic handlers log every operation
    /// fail-closed (an audit-write failure fails the request).
    pub fn with_audit_logger(mut self, audit: Arc<AsyncAuditLogger>) -> Self {
        self.audit = Some(audit);
        self
    }
}

/// Extract session token from Authorization header
pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
}

/// Authentication middleware
///
/// Validates the session token from the Authorization header.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Skip auth for health endpoints
    let path = request.uri().path();
    if path == "/health" || path == "/ready" {
        return Ok(next.run(request).await);
    }

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    // Extract bearer token
    let token_str = extract_bearer_token(auth_header)
        .ok_or_else(|| ApiError::Unauthorized("Invalid Authorization header format".to_string()))?;

    // Parse token (format: session_id:token)
    let parts: Vec<&str> = token_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(ApiError::Unauthorized("Invalid token format".to_string()));
    }

    let session_id = parts[0];
    let token = SessionToken::from_string(parts[1].to_string());

    // Validate session with token
    let session = state
        .sessions
        .validate_session_with_token(session_id, &token)
        .map_err(|_| ApiError::Unauthorized("Session validation failed".to_string()))?;

    // Store identity in request extensions for handlers
    request.extensions_mut().insert(session.identity);

    // Increment metrics
    metrics::counter!("rest_api.requests.authenticated").increment(1);

    Ok(next.run(request).await)
}

/// Request tracking middleware
///
/// Adds request ID and tracks request duration.
pub async fn request_tracking_middleware(request: Request, next: Next) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    let start = std::time::Instant::now();

    // Run the request
    let mut response = next.run(request).await;

    let duration = start.elapsed();

    // Add request ID to response headers
    response.headers_mut().insert(
        "X-Request-ID",
        request_id
            .parse()
            .unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );

    // Record metrics
    metrics::histogram!("rest_api.request.duration_ms", "method" => method.to_string(), "path" => path.clone())
        .record(duration.as_millis() as f64);

    metrics::counter!("rest_api.requests.total", "method" => method.to_string(), "status" => response.status().as_u16().to_string())
        .increment(1);

    tracing::info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        status = %response.status().as_u16(),
        duration_ms = %duration.as_millis(),
        "Request completed"
    );

    response
}

/// Rate limiting middleware
///
/// Applies global rate limiting using a token bucket algorithm.
/// Returns 429 Too Many Requests when the limit is exceeded.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Skip rate limiting for health/ready endpoints
    let path = request.uri().path();
    if path == "/health" || path == "/ready" {
        return Ok(next.run(request).await);
    }

    state
        .rate_limiter
        .check_global()
        .map_err(|_| ApiError::RateLimitExceeded)?;

    Ok(next.run(request).await)
}

/// Extract client identity from request extensions
pub fn get_identity(request: &Request) -> Option<&ClientIdentity> {
    request.extensions().get::<ClientIdentity>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(extract_bearer_token("Bearer abc123"), Some("abc123"));
        assert_eq!(extract_bearer_token("bearer abc123"), Some("abc123"));
        assert_eq!(extract_bearer_token("Basic abc123"), None);
        assert_eq!(extract_bearer_token("abc123"), None);
    }
}
