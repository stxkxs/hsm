//! Input validation for gRPC requests.
//!
//! This module provides comprehensive input validation to protect against:
//! - **Denial of Service (DoS)**: Size limits prevent memory exhaustion
//! - **Injection Attacks**: Format validation prevents malicious inputs
//! - **Resource Exhaustion**: Batch limits prevent unbounded processing
//!
//! # Security Design
//!
//! All limits are designed to balance security and usability:
//! - Small enough to prevent abuse
//! - Large enough for legitimate use cases
//! - Enforced before any processing begins
//!
//! # Validation Strategy
//!
//! 1. **Early Rejection**: Validate inputs before expensive operations
//! 2. **Clear Error Messages**: Help developers debug without exposing internals
//! 3. **Consistent Limits**: Same limits across all endpoints for predictability

use tonic::Status;

/// Maximum size for key identifiers (256 bytes).
///
/// # Security Rationale
///
/// - Prevents memory exhaustion from oversized identifiers
/// - UUID (36 bytes) + namespace prefix (100 bytes) + overhead fits comfortably
/// - Limits attack surface for parser vulnerabilities
pub const MAX_KEY_ID_SIZE: usize = 256;

/// Maximum size for namespace names (256 bytes).
///
/// # Security Rationale
///
/// - Prevents memory exhaustion from large namespace strings
/// - Allows reasonable naming like "production-us-west-2-payment-service"
/// - Enforced character set (alphanumeric + hyphens/underscores) prevents injection
pub const MAX_NAMESPACE_SIZE: usize = 256;

/// Maximum size for messages, signatures, and ciphertext (10 MB).
///
/// # Security Rationale
///
/// - Prevents DoS via large message amplification
/// - Supports reasonable document sizes (e.g., PDF signing)
/// - Limits memory usage per request to manageable levels
/// - Enforced per-item (not batch total) for predictable resource usage
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10MB

/// Maximum number of items in batch operations (1000).
///
/// # Security Rationale
///
/// - Prevents unbounded processing and timeout attacks
/// - Allows efficient batch operations (e.g., 1000 signatures in one request)
/// - Combined with MAX_MESSAGE_SIZE, limits total request to ~10GB worst case
/// - Protects against CPU exhaustion from large batch crypto operations
pub const MAX_BATCH_SIZE: usize = 1000;

/// Maximum size for algorithm names (64 bytes).
///
/// # Security Rationale
///
/// - Prevents buffer overflow in algorithm lookup
/// - All standard algorithms fit: "ECDSA_P256_SHA256" = 18 bytes
/// - Rejects suspiciously long or malformed algorithm strings
pub const MAX_ALGORITHM_NAME_SIZE: usize = 64;

/// Maximum number of metadata entries (100).
///
/// # Security Rationale
///
/// - Prevents metadata map size attacks
/// - Sufficient for reasonable tagging (e.g., owner, project, env, region)
/// - Limits iteration overhead during request processing
pub const MAX_METADATA_ENTRIES: usize = 100;

/// Maximum size for metadata keys (256 bytes).
///
/// # Security Rationale
///
/// - Prevents oversized keys in metadata maps
/// - Allows descriptive names like "creator_email_address"
/// - Protects hash map performance from pathological keys
pub const MAX_METADATA_KEY_SIZE: usize = 256;

/// Maximum size for metadata values (1 KB).
///
/// # Security Rationale
///
/// - Prevents large metadata from consuming memory
/// - Supports reasonable values (emails, URLs, short descriptions)
/// - With 100 max entries, total metadata < 100KB per request
pub const MAX_METADATA_VALUE_SIZE: usize = 1024;

/// Validates key ID format and size.
///
/// # Security
///
/// Enforces [`MAX_KEY_ID_SIZE`] to prevent:
/// - Memory exhaustion from oversized identifiers
/// - Parser vulnerabilities from malformed inputs
///
/// # Arguments
///
/// * `key_id` - The key identifier to validate
///
/// # Errors
///
/// Returns [`Status::InvalidArgument`] if:
/// - `key_id` is empty
/// - `key_id` exceeds [`MAX_KEY_ID_SIZE`] bytes
///
/// # Examples
///
/// ```
/// use grpc_api::validation::validate_key_id;
///
/// // Valid key ID
/// assert!(validate_key_id(b"my-key-123").is_ok());
///
/// // Empty key ID - rejected
/// assert!(validate_key_id(b"").is_err());
///
/// // Oversized key ID - rejected
/// let large_id = vec![0u8; 300];
/// assert!(validate_key_id(&large_id).is_err());
/// ```
pub fn validate_key_id(key_id: &[u8]) -> Result<(), Status> {
    if key_id.is_empty() {
        return Err(Status::invalid_argument("key_id is required"));
    }
    if key_id.len() > MAX_KEY_ID_SIZE {
        return Err(Status::invalid_argument(format!(
            "key_id too large: {} > {}",
            key_id.len(),
            MAX_KEY_ID_SIZE
        )));
    }
    Ok(())
}

/// Validates namespace format and enforces security constraints.
///
/// # Security
///
/// Enforces [`MAX_NAMESPACE_SIZE`] and strict character set to prevent:
/// - Path traversal attacks (no `/`, `\`, `..`)
/// - Command injection (no shell metacharacters)
/// - SQL injection (no quotes, semicolons)
/// - Directory traversal (restricted to alphanumeric + `-` + `_`)
///
/// # Arguments
///
/// * `namespace` - The namespace to validate
///
/// # Errors
///
/// Returns [`Status::InvalidArgument`] if:
/// - `namespace` is empty
/// - `namespace` exceeds [`MAX_NAMESPACE_SIZE`] bytes
/// - `namespace` contains non-alphanumeric characters (except hyphens and underscores)
///
/// # Allowed Characters
///
/// - Uppercase letters: `A-Z`
/// - Lowercase letters: `a-z`
/// - Digits: `0-9`
/// - Hyphens: `-`
/// - Underscores: `_`
///
/// # Examples
///
/// ```
/// use grpc_api::validation::validate_namespace;
///
/// // Valid namespaces
/// assert!(validate_namespace("production").is_ok());
/// assert!(validate_namespace("test-env_2024").is_ok());
///
/// // Invalid - special characters
/// assert!(validate_namespace("prod/keys").is_err());
/// assert!(validate_namespace("test@namespace").is_err());
///
/// // Invalid - empty
/// assert!(validate_namespace("").is_err());
/// ```
pub fn validate_namespace(namespace: &str) -> Result<(), Status> {
    if namespace.is_empty() {
        return Err(Status::invalid_argument("namespace is required"));
    }
    if namespace.len() > MAX_NAMESPACE_SIZE {
        return Err(Status::invalid_argument(format!(
            "namespace too large: {} > {}",
            namespace.len(),
            MAX_NAMESPACE_SIZE
        )));
    }

    // Namespace must be alphanumeric with hyphens and underscores
    if !namespace
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Status::invalid_argument(
            "namespace must be alphanumeric with hyphens/underscores only",
        ));
    }

    Ok(())
}

/// Validates data size for cryptographic operations.
///
/// # Security
///
/// Enforces [`MAX_MESSAGE_SIZE`] to prevent:
/// - Memory exhaustion from large messages
/// - CPU exhaustion from processing huge data
/// - Amplification attacks (small request → large processing)
///
/// # Arguments
///
/// * `data` - The data to validate
/// * `operation` - Operation name for error messages (e.g., "sign", "encrypt")
///
/// # Errors
///
/// Returns [`Status::InvalidArgument`] if:
/// - `data` is empty
/// - `data` exceeds [`MAX_MESSAGE_SIZE`] (10 MB)
///
/// # Examples
///
/// ```
/// use grpc_api::validation::validate_data_size;
///
/// // Valid message
/// let message = b"Hello, world!";
/// assert!(validate_data_size(message, "sign").is_ok());
///
/// // Empty data - rejected
/// assert!(validate_data_size(b"", "encrypt").is_err());
/// ```
pub fn validate_data_size(data: &[u8], operation: &str) -> Result<(), Status> {
    if data.is_empty() {
        return Err(Status::invalid_argument(format!(
            "{} data is required",
            operation
        )));
    }
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(Status::invalid_argument(format!(
            "{} data too large: {} > {}",
            operation,
            data.len(),
            MAX_MESSAGE_SIZE
        )));
    }
    Ok(())
}

/// Validates cryptographic algorithm name.
///
/// # Security
///
/// Enforces [`MAX_ALGORITHM_NAME_SIZE`] to prevent:
/// - Buffer overflow in algorithm lookup tables
/// - DoS via algorithm string processing
///
/// # Arguments
///
/// * `algorithm` - The algorithm name to validate (e.g., "RSA_2048", "ECDSA_P256")
///
/// # Errors
///
/// Returns [`Status::InvalidArgument`] if:
/// - `algorithm` is empty
/// - `algorithm` exceeds [`MAX_ALGORITHM_NAME_SIZE`] (64 bytes)
///
/// # Examples
///
/// ```
/// use grpc_api::validation::validate_algorithm;
///
/// // Valid algorithms
/// assert!(validate_algorithm("RSA_2048").is_ok());
/// assert!(validate_algorithm("ECDSA_P256_SHA256").is_ok());
///
/// // Empty algorithm - rejected
/// assert!(validate_algorithm("").is_err());
/// ```
pub fn validate_algorithm(algorithm: &str) -> Result<(), Status> {
    if algorithm.is_empty() {
        return Err(Status::invalid_argument("algorithm is required"));
    }
    if algorithm.len() > MAX_ALGORITHM_NAME_SIZE {
        return Err(Status::invalid_argument(format!(
            "algorithm name too large: {} > {}",
            algorithm.len(),
            MAX_ALGORITHM_NAME_SIZE
        )));
    }
    Ok(())
}

/// Validates batch operation size.
///
/// # Security
///
/// Enforces [`MAX_BATCH_SIZE`] to prevent:
/// - CPU exhaustion from processing huge batches
/// - Memory exhaustion from allocating large result arrays
/// - Timeout attacks via unbounded iteration
///
/// # Arguments
///
/// * `size` - Number of items in the batch
/// * `operation` - Operation name for error messages (e.g., "sign", "encrypt")
///
/// # Errors
///
/// Returns [`Status::InvalidArgument`] if:
/// - `size` is 0 (empty batch)
/// - `size` exceeds [`MAX_BATCH_SIZE`] (1000 items)
///
/// # Examples
///
/// ```
/// use grpc_api::validation::validate_batch_size;
///
/// // Valid batch sizes
/// assert!(validate_batch_size(10, "sign").is_ok());
/// assert!(validate_batch_size(1000, "encrypt").is_ok());
///
/// // Empty batch - rejected
/// assert!(validate_batch_size(0, "verify").is_err());
///
/// // Too large - rejected
/// assert!(validate_batch_size(2000, "decrypt").is_err());
/// ```
pub fn validate_batch_size(size: usize, operation: &str) -> Result<(), Status> {
    if size == 0 {
        return Err(Status::invalid_argument(format!(
            "{} batch cannot be empty",
            operation
        )));
    }
    if size > MAX_BATCH_SIZE {
        return Err(Status::invalid_argument(format!(
            "{} batch too large: {} > {}",
            operation, size, MAX_BATCH_SIZE
        )));
    }
    Ok(())
}

/// Validates metadata key-value map.
///
/// # Security
///
/// Enforces limits on metadata to prevent:
/// - Memory exhaustion from large metadata maps
/// - DoS via hash collision attacks
/// - Storage bloat from excessive tagging
///
/// Limits enforced:
/// - Total entries: [`MAX_METADATA_ENTRIES`] (100)
/// - Key size: [`MAX_METADATA_KEY_SIZE`] (256 bytes)
/// - Value size: [`MAX_METADATA_VALUE_SIZE`] (1 KB)
///
/// # Arguments
///
/// * `metadata` - The metadata map to validate
///
/// # Errors
///
/// Returns [`Status::InvalidArgument`] if:
/// - More than [`MAX_METADATA_ENTRIES`] entries
/// - Any key exceeds [`MAX_METADATA_KEY_SIZE`]
/// - Any value exceeds [`MAX_METADATA_VALUE_SIZE`]
///
/// # Examples
///
/// ```
/// use grpc_api::validation::validate_metadata;
/// use std::collections::HashMap;
///
/// // Valid metadata
/// let mut metadata = HashMap::new();
/// metadata.insert("owner".to_string(), "alice@example.com".to_string());
/// metadata.insert("env".to_string(), "production".to_string());
/// assert!(validate_metadata(&metadata).is_ok());
///
/// // Too many entries - rejected
/// let mut large_metadata = HashMap::new();
/// for i in 0..=100 {
///     large_metadata.insert(format!("key{}", i), "value".to_string());
/// }
/// assert!(validate_metadata(&large_metadata).is_err());
/// ```
pub fn validate_metadata(
    metadata: &std::collections::HashMap<String, String>,
) -> Result<(), Status> {
    if metadata.len() > MAX_METADATA_ENTRIES {
        return Err(Status::invalid_argument(format!(
            "too many metadata entries: {} > {}",
            metadata.len(),
            MAX_METADATA_ENTRIES
        )));
    }

    for (key, value) in metadata.iter() {
        if key.len() > MAX_METADATA_KEY_SIZE {
            return Err(Status::invalid_argument(format!(
                "metadata key too large: {} > {}",
                key.len(),
                MAX_METADATA_KEY_SIZE
            )));
        }
        if value.len() > MAX_METADATA_VALUE_SIZE {
            return Err(Status::invalid_argument(format!(
                "metadata value too large: {} > {}",
                value.len(),
                MAX_METADATA_VALUE_SIZE
            )));
        }
    }

    Ok(())
}

/// Validates plaintext size for encryption
pub fn validate_plaintext_size(plaintext: &[u8]) -> Result<(), Status> {
    validate_data_size(plaintext, "plaintext")
}

/// Validates ciphertext size for decryption
pub fn validate_ciphertext_size(ciphertext: &[u8]) -> Result<(), Status> {
    validate_data_size(ciphertext, "ciphertext")
}

/// Validates signature size
pub fn validate_signature_size(signature: &[u8]) -> Result<(), Status> {
    if signature.is_empty() {
        return Err(Status::invalid_argument("signature is required"));
    }
    if signature.len() > MAX_MESSAGE_SIZE {
        return Err(Status::invalid_argument(format!(
            "signature too large: {} > {}",
            signature.len(),
            MAX_MESSAGE_SIZE
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_key_id_valid() {
        let key_id = b"test-key-123";
        assert!(validate_key_id(key_id).is_ok());
    }

    #[test]
    fn test_validate_key_id_empty() {
        let key_id = b"";
        assert!(validate_key_id(key_id).is_err());
    }

    #[test]
    fn test_validate_key_id_too_large() {
        let key_id = vec![0u8; MAX_KEY_ID_SIZE + 1];
        assert!(validate_key_id(&key_id).is_err());
    }

    #[test]
    fn test_validate_namespace_valid() {
        assert!(validate_namespace("test-namespace_123").is_ok());
    }

    #[test]
    fn test_validate_namespace_empty() {
        assert!(validate_namespace("").is_err());
    }

    #[test]
    fn test_validate_namespace_invalid_chars() {
        assert!(validate_namespace("test@namespace").is_err());
        assert!(validate_namespace("test namespace").is_err());
        assert!(validate_namespace("test/namespace").is_err());
    }

    #[test]
    fn test_validate_data_size_valid() {
        let data = vec![0u8; 1024];
        assert!(validate_data_size(&data, "test").is_ok());
    }

    #[test]
    fn test_validate_data_size_empty() {
        let data = vec![];
        assert!(validate_data_size(&data, "test").is_err());
    }

    #[test]
    fn test_validate_data_size_too_large() {
        let data = vec![0u8; MAX_MESSAGE_SIZE + 1];
        assert!(validate_data_size(&data, "test").is_err());
    }

    #[test]
    fn test_validate_batch_size_valid() {
        assert!(validate_batch_size(10, "test").is_ok());
        assert!(validate_batch_size(MAX_BATCH_SIZE, "test").is_ok());
    }

    #[test]
    fn test_validate_batch_size_empty() {
        assert!(validate_batch_size(0, "test").is_err());
    }

    #[test]
    fn test_validate_batch_size_too_large() {
        assert!(validate_batch_size(MAX_BATCH_SIZE + 1, "test").is_err());
    }

    #[test]
    fn test_validate_metadata_valid() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "value2".to_string());
        assert!(validate_metadata(&metadata).is_ok());
    }

    #[test]
    fn test_validate_metadata_too_many_entries() {
        let mut metadata = std::collections::HashMap::new();
        for i in 0..=MAX_METADATA_ENTRIES {
            metadata.insert(format!("key{}", i), format!("value{}", i));
        }
        assert!(validate_metadata(&metadata).is_err());
    }

    #[test]
    fn test_validate_metadata_key_too_large() {
        let mut metadata = std::collections::HashMap::new();
        let large_key = "k".repeat(MAX_METADATA_KEY_SIZE + 1);
        metadata.insert(large_key, "value".to_string());
        assert!(validate_metadata(&metadata).is_err());
    }

    #[test]
    fn test_validate_metadata_value_too_large() {
        let mut metadata = std::collections::HashMap::new();
        let large_value = "v".repeat(MAX_METADATA_VALUE_SIZE + 1);
        metadata.insert("key".to_string(), large_value);
        assert!(validate_metadata(&metadata).is_err());
    }
}
