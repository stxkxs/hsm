//! Bridge monitor errors

use thiserror::Error;

/// Bridge monitor error types
#[derive(Error, Debug)]
pub enum BridgeError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Chain connection error
    #[error("Chain connection error: {0}")]
    ChainConnection(String),

    /// Event processing error
    #[error("Event processing error: {0}")]
    EventProcessing(String),

    /// Policy violation
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    /// Anomaly detected
    #[error("Anomaly detected: {0}")]
    AnomalyDetected(String),

    /// Bridge paused
    #[error("Bridge paused: {0}")]
    BridgePaused(String),

    /// HTTP error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for bridge operations
pub type Result<T> = std::result::Result<T, BridgeError>;
