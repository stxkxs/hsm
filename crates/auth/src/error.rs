use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("Certificate validation failed: {0}")]
    CertificateValidationFailed(String),

    #[error("Certificate expired")]
    CertificateExpired,

    #[error("Certificate not yet valid")]
    CertificateNotYetValid,

    #[error("Invalid certificate chain")]
    InvalidCertificateChain,

    #[error("Client identity not found in certificate")]
    IdentityNotFound,

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Access denied to namespace: {0}")]
    NamespaceAccessDenied(String),

    #[error("Invalid session: {0}")]
    InvalidSession(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Role not found: {0}")]
    RoleNotFound(String),

    #[error("Invalid ACL: {0}")]
    InvalidAcl(String),

    #[error("TLS configuration error: {0}")]
    TlsConfigError(String),

    #[error("Certificate parsing error: {0}")]
    CertificateParsingError(String),

    #[error("Certificate revoked")]
    CertificateRevoked,

    #[error("Certificate pinning failed")]
    CertificatePinningFailed,

    #[error("Invalid key usage")]
    InvalidKeyUsage,

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Circuit breaker open")]
    CircuitBreakerOpen,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;
