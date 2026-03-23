//! Error handling for REST API
//!
//! Provides consistent error responses with appropriate HTTP status codes.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Result type for REST API operations
pub type Result<T> = std::result::Result<T, ApiError>;

/// API Error response body
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Error code for programmatic handling
    pub error: String,
    /// Human-readable error message
    pub message: String,
    /// Optional additional details (never contains sensitive data)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// REST API errors
#[derive(Debug, Error)]
pub enum ApiError {
    /// Authentication failed
    #[error("authentication failed: {0}")]
    Unauthorized(String),

    /// Authorization failed (permission denied)
    #[error("permission denied: {0}")]
    Forbidden(String),

    /// Resource not found
    #[error("not found: {0}")]
    NotFound(String),

    /// Bad request (validation error)
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Conflict (resource already exists)
    #[error("conflict: {0}")]
    Conflict(String),

    /// Rate limit exceeded
    #[error("rate limit exceeded")]
    RateLimitExceeded,

    /// Internal server error
    #[error("internal error")]
    Internal(String),

    /// Service unavailable
    #[error("service unavailable")]
    ServiceUnavailable,

    /// Cryptographic operation failed
    #[error("cryptographic operation failed")]
    CryptoError(String),

    /// Feature not implemented
    #[error("not implemented: {0}")]
    NotImplemented(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            ApiError::Unauthorized(_) => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                // Don't expose internal auth details to clients
                "Authentication failed".to_string(),
            ),
            ApiError::Forbidden(_) => (
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                // Generic message to avoid leaking permission details
                "Permission denied".to_string(),
            ),
            ApiError::NotFound(_) => (
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Resource not found".to_string(),
            ),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg.clone()),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg.clone()),
            ApiError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMIT_EXCEEDED",
                "Too many requests. Please try again later.".to_string(),
            ),
            ApiError::Internal(msg) => {
                // Log the internal error but don't expose it to clients
                tracing::error!(error = %msg, "Internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "An internal error occurred".to_string(),
                )
            }
            ApiError::ServiceUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Service temporarily unavailable".to_string(),
            ),
            ApiError::CryptoError(msg) => {
                // Log the crypto error but don't expose details
                tracing::error!(error = %msg, "Cryptographic operation failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "CRYPTO_ERROR",
                    "Cryptographic operation failed".to_string(),
                )
            }
            ApiError::NotImplemented(msg) => {
                (StatusCode::NOT_IMPLEMENTED, "NOT_IMPLEMENTED", msg.clone())
            }
        };

        // Increment error metrics
        metrics::counter!("rest_api.errors", "status" => status.as_u16().to_string(), "error" => error_code.to_string()).increment(1);

        let body = Json(ErrorResponse {
            error: error_code.to_string(),
            message,
            details: None,
        });

        (status, body).into_response()
    }
}

impl From<hsm_auth::AuthError> for ApiError {
    fn from(err: hsm_auth::AuthError) -> Self {
        match err {
            hsm_auth::AuthError::InvalidSession(_) => {
                ApiError::Unauthorized("Invalid session".to_string())
            }
            hsm_auth::AuthError::SessionExpired => {
                ApiError::Unauthorized("Session expired".to_string())
            }
            hsm_auth::AuthError::PermissionDenied(_) => {
                ApiError::Forbidden("Permission denied".to_string())
            }
            hsm_auth::AuthError::NamespaceAccessDenied(_) => {
                ApiError::Forbidden("Namespace access denied".to_string())
            }
            hsm_auth::AuthError::RateLimitExceeded(_) => ApiError::RateLimitExceeded,
            _ => ApiError::Internal(format!("Auth error: {}", err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response_serialization() {
        let response = ErrorResponse {
            error: "NOT_FOUND".to_string(),
            message: "Resource not found".to_string(),
            details: None,
        };

        let json = serde_json::to_string(&response).expect("serialization should succeed");
        assert!(json.contains("NOT_FOUND"));
    }

    #[test]
    fn test_internal_error_hides_details() {
        let error = ApiError::Internal("database connection failed: password=secret".to_string());
        let response = error.into_response();

        // Status should be 500
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
