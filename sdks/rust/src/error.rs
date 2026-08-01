//! HSM Client Errors

use thiserror::Error;

/// Result type for HSM operations.
pub type Result<T> = std::result::Result<T, HsmError>;

/// HSM error types.
#[derive(Debug, Error)]
pub enum HsmError {
    /// Authentication failed.
    #[error("Authentication failed: {message}")]
    Authentication { message: String },

    /// Authorization failed.
    #[error("Authorization failed: {message}")]
    Authorization { message: String },

    /// Resource not found.
    #[error("{resource} not found: {id}")]
    NotFound { resource: String, id: String },

    /// Validation error.
    #[error("Validation error: {message}")]
    Validation {
        message: String,
        field: Option<String>,
    },

    /// Rate limit exceeded.
    #[error("Rate limit exceeded: {message}")]
    RateLimit {
        message: String,
        retry_after: Option<u32>,
    },

    /// Network error.
    #[error("Network error: {message}")]
    Network {
        message: String,
        #[source]
        source: Option<reqwest::Error>,
    },

    /// Timeout error.
    #[error("Request timed out")]
    Timeout,

    /// Server error.
    #[error("Server error ({status_code}): {message}")]
    Server { message: String, status_code: u16 },

    /// Cryptographic error.
    #[error("Crypto error: {message}")]
    Crypto { message: String },

    /// Session error.
    #[error("Session error: {message}")]
    Session { message: String },

    /// Circuit breaker is open.
    #[error("Circuit breaker is open")]
    CircuitOpen,

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// HTTP client error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

impl HsmError {
    /// Create an authentication error.
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }

    /// Create an authorization error.
    pub fn authorization(message: impl Into<String>) -> Self {
        Self::Authorization {
            message: message.into(),
        }
    }

    /// Create a not found error.
    pub fn not_found(resource: impl Into<String>, id: impl Into<String>) -> Self {
        Self::NotFound {
            resource: resource.into(),
            id: id.into(),
        }
    }

    /// Create a validation error.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
            field: None,
        }
    }

    /// Create a validation error with field.
    pub fn validation_field(message: impl Into<String>, field: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
            field: Some(field.into()),
        }
    }

    /// Create a rate limit error.
    pub fn rate_limit(message: impl Into<String>, retry_after: Option<u32>) -> Self {
        Self::RateLimit {
            message: message.into(),
            retry_after,
        }
    }

    /// Create a network error.
    pub fn network(message: impl Into<String>) -> Self {
        Self::Network {
            message: message.into(),
            source: None,
        }
    }

    /// Create a server error.
    pub fn server(message: impl Into<String>, status_code: u16) -> Self {
        Self::Server {
            message: message.into(),
            status_code,
        }
    }

    /// Create a crypto error.
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto {
            message: message.into(),
        }
    }

    /// Create a session error.
    pub fn session(message: impl Into<String>) -> Self {
        Self::Session {
            message: message.into(),
        }
    }

    /// Get the HTTP status code if applicable.
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Authentication { .. } => Some(401),
            Self::Authorization { .. } => Some(403),
            Self::NotFound { .. } => Some(404),
            Self::Validation { .. } => Some(400),
            Self::RateLimit { .. } => Some(429),
            Self::Server { status_code, .. } => Some(*status_code),
            Self::Session { .. } => Some(401),
            _ => None,
        }
    }
}

/// Parse an error response from the server.
pub fn parse_error_response(status_code: u16, body: &serde_json::Value) -> HsmError {
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown error")
        .to_string();

    match status_code {
        400 => HsmError::validation(message),
        401 => HsmError::authentication(message),
        403 => HsmError::authorization(message),
        404 => HsmError::not_found("Resource", "unknown"),
        429 => {
            let retry_after = body
                .get("retry_after")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);
            HsmError::rate_limit(message, retry_after)
        }
        _ if status_code >= 500 => HsmError::server(message, status_code),
        _ => HsmError::Server {
            message,
            status_code,
        },
    }
}
