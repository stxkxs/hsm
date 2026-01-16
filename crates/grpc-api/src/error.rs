use thiserror::Error;
use tonic::Status;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key type: {0}")]
    InvalidKeyType(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Key manager error: {0}")]
    KeyManagerError(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Key policy violation: {0}")]
    PolicyViolation(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),
}

impl From<ApiError> for Status {
    fn from(error: ApiError) -> Self {
        use tracing::error;

        // Log full error details internally for debugging
        error!("API Error: {:?}", error);

        // Return sanitized errors to clients to prevent information leakage
        match error {
            ApiError::KeyNotFound(_) => {
                // Don't leak key ID in error message
                Status::not_found("Key not found")
            }
            ApiError::InvalidKeyType(_) => Status::invalid_argument("Invalid key type"),
            ApiError::AuthenticationFailed(_) => {
                // Use generic message to prevent enumeration attacks
                Status::unauthenticated("Authentication failed")
            }
            ApiError::AuthorizationFailed(_) => {
                // Don't leak resource details
                Status::permission_denied("Access denied")
            }
            ApiError::InvalidRequest(msg) => {
                // Only pass through validation messages (already sanitized)
                Status::invalid_argument(msg)
            }
            ApiError::CryptoError(_) => {
                // Never leak crypto implementation details
                Status::internal("Cryptographic operation failed")
            }
            ApiError::KeyManagerError(_) => {
                // Don't leak internal state
                Status::internal("Key management operation failed")
            }
            ApiError::InternalError(_) => {
                // Generic internal error
                Status::internal("Internal server error")
            }
            ApiError::DatabaseError(_) => {
                // Don't leak database details
                Status::unavailable("Service temporarily unavailable")
            }
            ApiError::PolicyViolation(_) => {
                // Don't leak policy details
                Status::permission_denied("Operation not permitted")
            }
            ApiError::RateLimitExceeded => Status::resource_exhausted("Rate limit exceeded"),
            ApiError::ResourceExhausted(_) => Status::resource_exhausted("Resource limit exceeded"),
        }
    }
}

impl From<hsm_key_manager::Error> for ApiError {
    fn from(error: hsm_key_manager::Error) -> Self {
        match error {
            hsm_key_manager::Error::KeyNotFound(key_id) => {
                ApiError::KeyNotFound(key_id.to_string())
            }
            hsm_key_manager::Error::UnsupportedKeyType(key_type) => {
                ApiError::InvalidKeyType(format!("{:?}", key_type))
            }
            hsm_key_manager::Error::MaxOperationsReached(key_id) => {
                ApiError::PolicyViolation(format!("Max operations reached for key {}", key_id))
            }
            _ => ApiError::KeyManagerError(error.to_string()),
        }
    }
}

impl From<hsm_crypto_engine::CryptoError> for ApiError {
    fn from(error: hsm_crypto_engine::CryptoError) -> Self {
        ApiError::CryptoError(error.to_string())
    }
}

impl From<hsm_auth::AuthError> for ApiError {
    fn from(error: hsm_auth::AuthError) -> Self {
        match error {
            hsm_auth::AuthError::PermissionDenied(msg) => ApiError::AuthorizationFailed(msg),
            hsm_auth::AuthError::NamespaceAccessDenied(msg) => ApiError::AuthorizationFailed(msg),
            hsm_auth::AuthError::InvalidSession(msg) => ApiError::AuthenticationFailed(msg),
            hsm_auth::AuthError::SessionExpired => {
                ApiError::AuthenticationFailed("Session expired".to_string())
            }
            hsm_auth::AuthError::InvalidCertificate(msg) => ApiError::AuthenticationFailed(msg),
            hsm_auth::AuthError::CertificateExpired => {
                ApiError::AuthenticationFailed("Certificate expired".to_string())
            }
            _ => ApiError::InternalError(error.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;
