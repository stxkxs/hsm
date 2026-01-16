use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Types of events that can be audited
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Key management operations
    KeyGeneration,
    KeyImport,
    KeyExport,
    KeyDeletion,
    KeyRotation,

    /// Cryptographic operations
    Sign,
    Verify,
    Encrypt,
    Decrypt,

    /// Access control
    Authentication,
    Authorization,
    AccessDenied,

    /// System events
    SystemStartup,
    SystemShutdown,
    ConfigChange,

    /// Audit events
    AuditLogRotation,
    AuditVerification,
}

/// Result of an operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationResult {
    Success,
    Failure { reason: String },
}

/// Main audit event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// UTC timestamp of when the event occurred
    pub timestamp: DateTime<Utc>,

    /// Sequence number (monotonically increasing)
    pub sequence: u64,

    /// Type of event
    pub event_type: EventType,

    /// Specific operation name
    pub operation: String,

    /// Namespace/domain of the operation
    pub namespace: String,

    /// Client identifier
    pub client_id: String,

    /// Key ID if applicable
    pub key_id: Option<String>,

    /// Result of the operation
    pub result: OperationResult,

    /// Hash of the previous event (for chain integrity)
    pub prev_hash: String,

    /// Hash of this event
    pub current_hash: String,

    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

impl AuditEvent {
    /// Create a new audit event builder
    pub fn builder() -> AuditEventBuilder {
        AuditEventBuilder::default()
    }

    /// Compute hash of this event (excluding current_hash field)
    pub fn compute_hash(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(self.sequence.to_le_bytes());
        hasher.update(
            serde_json::to_string(&self.event_type)
                .unwrap_or_default()
                .as_bytes(),
        );
        hasher.update(self.operation.as_bytes());
        hasher.update(self.namespace.as_bytes());
        hasher.update(self.client_id.as_bytes());

        if let Some(key_id) = &self.key_id {
            hasher.update(key_id.as_bytes());
        }

        hasher.update(
            serde_json::to_string(&self.result)
                .unwrap_or_default()
                .as_bytes(),
        );
        hasher.update(self.prev_hash.as_bytes());

        if let Some(metadata) = &self.metadata {
            hasher.update(
                serde_json::to_string(metadata)
                    .unwrap_or_default()
                    .as_bytes(),
            );
        }

        hex::encode(hasher.finalize())
    }

    /// Verify that the current_hash matches the computed hash
    pub fn verify_hash(&self) -> bool {
        self.current_hash == self.compute_hash()
    }
}

/// Builder for AuditEvent
#[derive(Default, Clone)]
pub struct AuditEventBuilder {
    timestamp: Option<DateTime<Utc>>,
    sequence: Option<u64>,
    event_type: Option<EventType>,
    operation: Option<String>,
    namespace: Option<String>,
    client_id: Option<String>,
    key_id: Option<String>,
    result: Option<OperationResult>,
    prev_hash: Option<String>,
    metadata: Option<serde_json::Value>,
}

impl AuditEventBuilder {
    pub fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn sequence(mut self, sequence: u64) -> Self {
        self.sequence = Some(sequence);
        self
    }

    pub fn event_type(mut self, event_type: EventType) -> Self {
        self.event_type = Some(event_type);
        self
    }

    pub fn operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }

    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    pub fn result(mut self, result: OperationResult) -> Self {
        self.result = Some(result);
        self
    }

    pub fn prev_hash(mut self, prev_hash: impl Into<String>) -> Self {
        self.prev_hash = Some(prev_hash.into());
        self
    }

    pub fn metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn success(mut self) -> Self {
        self.result = Some(OperationResult::Success);
        self
    }

    pub fn failure(mut self, reason: impl Into<String>) -> Self {
        self.result = Some(OperationResult::Failure {
            reason: reason.into(),
        });
        self
    }

    pub fn build(self) -> Result<AuditEvent, &'static str> {
        let timestamp = self.timestamp.unwrap_or_else(Utc::now);
        let sequence = self.sequence.ok_or("sequence is required")?;
        let event_type = self.event_type.ok_or("event_type is required")?;
        let operation = self.operation.ok_or("operation is required")?;
        let namespace = self.namespace.ok_or("namespace is required")?;
        let client_id = self.client_id.ok_or("client_id is required")?;
        let result = self.result.ok_or("result is required")?;
        let prev_hash = self.prev_hash.unwrap_or_else(|| "0".repeat(64));

        let mut event = AuditEvent {
            timestamp,
            sequence,
            event_type,
            operation,
            namespace,
            client_id,
            key_id: self.key_id,
            result,
            prev_hash,
            current_hash: String::new(), // Will be computed
            metadata: self.metadata,
        };

        event.current_hash = event.compute_hash();

        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = AuditEvent::builder()
            .sequence(1)
            .event_type(EventType::KeyGeneration)
            .operation("generate_rsa_key")
            .namespace("default")
            .client_id("client_123")
            .key_id("key_456")
            .success()
            .build()
            .unwrap();

        assert_eq!(event.sequence, 1);
        assert_eq!(event.event_type, EventType::KeyGeneration);
        assert_eq!(event.operation, "generate_rsa_key");
        assert_eq!(event.result, OperationResult::Success);
    }

    #[test]
    fn test_hash_computation() {
        let event = AuditEvent::builder()
            .sequence(1)
            .event_type(EventType::Sign)
            .operation("sign_data")
            .namespace("default")
            .client_id("client_123")
            .success()
            .build()
            .unwrap();

        assert!(event.verify_hash());
        assert_eq!(event.current_hash.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn test_hash_chain() {
        let event1 = AuditEvent::builder()
            .sequence(1)
            .event_type(EventType::KeyGeneration)
            .operation("generate_key")
            .namespace("default")
            .client_id("client_1")
            .success()
            .build()
            .unwrap();

        let event2 = AuditEvent::builder()
            .sequence(2)
            .event_type(EventType::Sign)
            .operation("sign_data")
            .namespace("default")
            .client_id("client_1")
            .prev_hash(&event1.current_hash)
            .success()
            .build()
            .unwrap();

        assert_eq!(event2.prev_hash, event1.current_hash);
        assert_ne!(event1.current_hash, event2.current_hash);
    }

    #[test]
    fn test_serialization() {
        let event = AuditEvent::builder()
            .sequence(1)
            .event_type(EventType::Encrypt)
            .operation("encrypt_data")
            .namespace("default")
            .client_id("client_123")
            .success()
            .build()
            .unwrap();

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event.sequence, deserialized.sequence);
        assert_eq!(event.current_hash, deserialized.current_hash);
    }
}
