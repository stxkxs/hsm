//! Error types for the WASM policy engine.

use thiserror::Error;

/// Result type for policy operations.
pub type Result<T> = std::result::Result<T, PolicyError>;

/// Errors that can occur during policy operations.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Policy not found.
    #[error("Policy not found: {0}")]
    NotFound(String),

    /// Invalid policy bytecode.
    #[error("Invalid policy bytecode: {0}")]
    InvalidBytecode(String),

    /// Policy compilation failed.
    #[error("Policy compilation failed: {0}")]
    CompilationFailed(String),

    /// Policy execution failed.
    #[error("Policy execution failed: {0}")]
    ExecutionFailed(String),

    /// Policy returned invalid result.
    #[error("Policy returned invalid result: {0}")]
    InvalidResult(String),

    /// Resource limit exceeded.
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    /// Gas limit exceeded.
    #[error("Gas limit exceeded: used {used}, limit {limit}")]
    GasLimitExceeded { used: u64, limit: u64 },

    /// Memory limit exceeded.
    #[error("Memory limit exceeded: used {used} bytes, limit {limit} bytes")]
    MemoryLimitExceeded { used: usize, limit: usize },

    /// Execution timeout.
    #[error("Execution timeout: exceeded {0} ms")]
    Timeout(u64),

    /// Missing required export.
    #[error("Missing required export: {0}")]
    MissingExport(String),

    /// Invalid export signature.
    #[error("Invalid export signature for '{name}': expected {expected}, got {actual}")]
    InvalidExportSignature {
        name: String,
        expected: String,
        actual: String,
    },

    /// Host function error.
    #[error("Host function error: {0}")]
    HostError(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Storage error.
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Policy already exists.
    #[error("Policy already exists: {0}")]
    AlreadyExists(String),

    /// Invalid policy ID.
    #[error("Invalid policy ID: {0}")]
    InvalidPolicyId(String),

    /// ABI version mismatch.
    #[error("ABI version mismatch: policy uses v{policy}, engine supports v{engine}")]
    AbiVersionMismatch { policy: u32, engine: u32 },

    /// Policy is disabled.
    #[error("Policy is disabled: {0}")]
    PolicyDisabled(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<wasmtime::Error> for PolicyError {
    fn from(err: wasmtime::Error) -> Self {
        PolicyError::ExecutionFailed(err.to_string())
    }
}

impl From<serde_json::Error> for PolicyError {
    fn from(err: serde_json::Error) -> Self {
        PolicyError::SerializationError(err.to_string())
    }
}

impl From<std::io::Error> for PolicyError {
    fn from(err: std::io::Error) -> Self {
        PolicyError::StorageError(err.to_string())
    }
}
