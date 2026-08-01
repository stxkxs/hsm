//! HSM Client Types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Supported key algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Aes128,
    Aes256,
}

/// Key purpose/usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyPurpose {
    Sign,
    Encrypt,
    General,
}

/// Key state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyState {
    Active,
    Inactive,
    Compromised,
    Destroyed,
}

impl KeyState {
    /// The wire representation of this state.
    ///
    /// This is the same string the `Serialize` impl produces (the enum is
    /// `SCREAMING_SNAKE_CASE`), and is what must appear in query strings — the
    /// `Debug` rendering (`Active`) is *not* a valid value for the API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Inactive => "INACTIVE",
            Self::Compromised => "COMPROMISED",
            Self::Destroyed => "DESTROYED",
        }
    }
}

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Request to generate a new key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub algorithm: KeyAlgorithm,
    pub purpose: KeyPurpose,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
}

/// Response after generating a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeyResponse {
    pub key_id: String,
    pub algorithm: KeyAlgorithm,
    pub purpose: KeyPurpose,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub created_at: String,
}

/// Key metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub algorithm: KeyAlgorithm,
    pub purpose: KeyPurpose,
    pub namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    pub active: bool,
}

/// List keys response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListKeysResponse {
    pub keys: Vec<KeyMetadata>,
    pub total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// List keys options.
#[derive(Debug, Clone, Default)]
pub struct ListKeysOptions {
    pub namespace: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    pub state: Option<KeyState>,
}

/// Request to sign data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
}

/// Sign response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature: String,
    pub algorithm: String,
}

/// Request to verify a signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub data: String,
    pub signature: String,
}

/// Verify response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub valid: bool,
}

/// Request to encrypt data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub plaintext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

/// Encrypt response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub ciphertext: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// Request to decrypt data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub ciphertext: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

/// Decrypt response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub plaintext: String,
}

/// Batch sign item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSignItem {
    pub key_id: String,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
}

/// Batch sign request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSignRequest {
    pub requests: Vec<BatchSignItem>,
}

/// Batch sign response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSignResponse {
    pub results: Vec<SignResponse>,
    #[serde(default)]
    pub errors: Vec<String>,
}

/// Batch verify item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerifyItem {
    pub key_id: String,
    pub data: String,
    pub signature: String,
}

/// Batch verify request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerifyRequest {
    pub requests: Vec<BatchVerifyItem>,
}

/// Batch verify response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerifyResponse {
    pub results: Vec<VerifyResponse>,
    #[serde(default)]
    pub errors: Vec<String>,
}

/// Batch encrypt item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEncryptItem {
    pub key_id: String,
    pub plaintext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

/// Batch encrypt request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEncryptRequest {
    pub requests: Vec<BatchEncryptItem>,
}

/// Batch encrypt response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEncryptResponse {
    pub results: Vec<EncryptResponse>,
    #[serde(default)]
    pub errors: Vec<String>,
}

/// Batch decrypt item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDecryptItem {
    pub key_id: String,
    pub ciphertext: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

/// Batch decrypt request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDecryptRequest {
    pub requests: Vec<BatchDecryptItem>,
}

/// Batch decrypt response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDecryptResponse {
    pub results: Vec<DecryptResponse>,
    #[serde(default)]
    pub errors: Vec<String>,
}

/// Audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    pub action: String,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Audit log response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogResponse {
    pub entries: Vec<AuditEntry>,
    pub total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Audit log options.
#[derive(Debug, Clone, Default)]
pub struct AuditLogOptions {
    pub namespace: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub user_id: Option<String>,
    pub operation: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
}

/// Component status for readiness check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Readiness check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyResponse {
    pub ready: bool,
    pub components: HashMap<String, ComponentStatus>,
}

/// Retry configuration.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub jitter: f64,
    pub retry_on_status: Vec<u16>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            jitter: 0.1,
            retry_on_status: vec![429, 502, 503, 504],
        }
    }
}

/// Session scope for limiting session capabilities.
#[derive(Debug, Clone, Default)]
pub struct SessionScope {
    pub allowed_operations: Option<Vec<String>>,
    pub allowed_keys: Option<Vec<String>>,
    pub max_operations: Option<u32>,
    pub rate_limit: Option<u32>,
}

/// HSM Client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub base_url: String,
    pub session_id: Option<String>,
    pub session_token: Option<String>,
    pub timeout: Duration,
    pub headers: HashMap<String, String>,
    pub retry: Option<RetryConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            session_id: None,
            session_token: None,
            timeout: Duration::from_secs(30),
            headers: HashMap::new(),
            retry: None,
        }
    }
}
