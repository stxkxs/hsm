//! REST API Request and Response Types
//!
//! JSON-serializable types for REST API endpoints.

use serde::{Deserialize, Serialize};

// ============================================================================
// Key Management Types
// ============================================================================

/// Supported key algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyAlgorithm {
    /// Ed25519 (recommended for signatures)
    Ed25519,
    /// ECDSA with P-256 curve
    EcdsaP256,
    /// ECDSA with P-384 curve
    EcdsaP384,
    /// RSA (legacy, not recommended for new keys)
    Rsa2048,
    Rsa3072,
    Rsa4096,
    /// AES for symmetric encryption
    Aes128,
    Aes256,
}

/// Key purpose/usage
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyPurpose {
    /// Signing and verification
    Sign,
    /// Encryption and decryption
    Encrypt,
    /// Both signing and encryption
    General,
}

/// Request to generate a new key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeyRequest {
    /// Unique key identifier (optional, generated if not provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// Key algorithm
    pub algorithm: KeyAlgorithm,

    /// Key purpose
    pub purpose: KeyPurpose,

    /// Namespace for the key (default: "default")
    #[serde(default = "default_namespace")]
    pub namespace: String,

    /// Optional labels/tags for the key
    #[serde(default)]
    pub labels: std::collections::HashMap<String, String>,
}

fn default_namespace() -> String {
    "default".to_string()
}

/// Response after generating a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeyResponse {
    /// Generated key ID
    pub key_id: String,

    /// Key algorithm
    pub algorithm: KeyAlgorithm,

    /// Key purpose
    pub purpose: KeyPurpose,

    /// Public key (base64-encoded, for asymmetric keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// Creation timestamp (RFC 3339)
    pub created_at: String,
}

/// Key metadata response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadataResponse {
    /// Key ID
    pub key_id: String,

    /// Key algorithm
    pub algorithm: KeyAlgorithm,

    /// Key purpose
    pub purpose: KeyPurpose,

    /// Namespace
    pub namespace: String,

    /// Public key (base64-encoded, for asymmetric keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// Creation timestamp
    pub created_at: String,

    /// Last used timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used: Option<String>,

    /// Key labels
    pub labels: std::collections::HashMap<String, String>,

    /// Whether the key is active
    pub active: bool,
}

/// List keys response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListKeysResponse {
    /// List of keys
    pub keys: Vec<KeyMetadataResponse>,

    /// Total count (for pagination)
    pub total: u64,

    /// Next page cursor (if more results available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ============================================================================
// Cryptographic Operation Types
// ============================================================================

/// Request to sign data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// Data to sign (base64-encoded)
    pub data: String,

    /// Optional hash algorithm (defaults to SHA-256)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
}

/// Sign response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    /// Signature (base64-encoded)
    pub signature: String,

    /// Algorithm used
    pub algorithm: String,
}

/// Request to verify a signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// Original data (base64-encoded)
    pub data: String,

    /// Signature to verify (base64-encoded)
    pub signature: String,
}

/// Verify response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Whether the signature is valid
    pub valid: bool,
}

/// Request to encrypt data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptRequest {
    /// Plaintext data (base64-encoded)
    pub plaintext: String,

    /// Optional additional authenticated data (base64-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

/// Encrypt response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResponse {
    /// Ciphertext (base64-encoded)
    pub ciphertext: String,

    /// Nonce/IV (base64-encoded)
    pub nonce: String,

    /// Authentication tag (base64-encoded, for AEAD)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// Request to decrypt data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequest {
    /// Ciphertext (base64-encoded)
    pub ciphertext: String,

    /// Nonce/IV (base64-encoded)
    pub nonce: String,

    /// Authentication tag (base64-encoded, for AEAD)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Optional additional authenticated data (base64-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

/// Decrypt response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptResponse {
    /// Decrypted plaintext (base64-encoded)
    pub plaintext: String,
}

// ============================================================================
// Audit Types
// ============================================================================

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Entry ID
    pub id: String,

    /// Timestamp (RFC 3339)
    pub timestamp: String,

    /// Event type
    pub event_type: String,

    /// Actor (client identity)
    pub actor: String,

    /// Resource (key ID, namespace, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,

    /// Action performed
    pub action: String,

    /// Result (success/failure)
    pub result: String,

    /// Additional details (sanitized)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Audit log response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogResponse {
    /// Audit entries
    pub entries: Vec<AuditEntry>,

    /// Total count
    pub total: u64,

    /// Next page cursor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ============================================================================
// Health Check Types
// ============================================================================

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Service status
    pub status: String,

    /// Service version
    pub version: String,

    /// Uptime in seconds
    pub uptime_seconds: u64,
}

/// Readiness check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyResponse {
    /// Whether the service is ready
    pub ready: bool,

    /// Component status
    pub components: std::collections::HashMap<String, ComponentStatus>,
}

/// Component status for readiness check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    /// Component status (healthy, degraded, unhealthy)
    pub status: String,

    /// Optional message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_request_serialization() {
        let request = GenerateKeyRequest {
            key_id: Some("test-key".to_string()),
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::Sign,
            namespace: "default".to_string(),
            labels: std::collections::HashMap::new(),
        };

        let json = serde_json::to_string(&request).expect("serialization should succeed");
        assert!(json.contains("ED25519"));
    }

    #[test]
    fn test_sign_request_deserialization() {
        let json = r#"{"data": "SGVsbG8gV29ybGQ="}"#;
        let request: SignRequest =
            serde_json::from_str(json).expect("deserialization should succeed");
        assert_eq!(request.data, "SGVsbG8gV29ybGQ=");
    }
}
