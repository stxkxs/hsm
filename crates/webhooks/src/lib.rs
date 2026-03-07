#![deny(unsafe_code)]
#![allow(dead_code)]
#![allow(unused_imports)]
//! # HSM Webhook Delivery System
//!
//! Provides webhook notifications for HSM events, enabling real-time integration
//! with external systems like SIEM platforms, alerting services, and audit systems.
//!
//! ## Features
//!
//! - **Reliable Delivery**: Automatic retries with exponential backoff
//! - **HMAC-SHA256 Signatures**: Cryptographic verification of webhook payloads
//! - **Event Filtering**: Subscribe to specific event types
//! - **Async Dispatch**: Non-blocking event delivery
//! - **Dead Letter Queue**: Failed deliveries stored for later retry
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    Webhook Delivery Pipeline                         │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                       │
//! │  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐         │
//! │  │  HSM Events  │────▶│  Event Filter│────▶│  Dispatcher  │         │
//! │  │ (audit logs) │     │  (by type)   │     │  (async)     │         │
//! │  └──────────────┘     └──────────────┘     └──────────────┘         │
//! │                                                   │                  │
//! │                              ┌────────────────────┴─────────┐       │
//! │                              ▼                              ▼       │
//! │                    ┌──────────────────┐         ┌────────────────┐  │
//! │                    │  HMAC Signer     │         │   HTTP Client  │  │
//! │                    │  (SHA-256)       │────────▶│   + Retry      │  │
//! │                    └──────────────────┘         └────────────────┘  │
//! │                                                         │           │
//! │                              ┌──────────────────────────┘           │
//! │                              ▼                                       │
//! │                    ┌──────────────────┐                             │
//! │                    │  Webhook Endpoint│ ◀── Your server             │
//! │                    │  (HTTPS)         │                             │
//! │                    └──────────────────┘                             │
//! │                                                                       │
//! │  HTTP Headers:                                                       │
//! │  • X-Webhook-ID: Unique event identifier                            │
//! │  • X-Webhook-Timestamp: Unix timestamp (for replay protection)      │
//! │  • X-Webhook-Signature: HMAC-SHA256(secret, timestamp.payload)      │
//! │                                                                       │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ### Register a Webhook
//!
//! ```rust,ignore
//! use hsm_webhooks::{WebhookRegistry, Webhook, EventFilter, WebhookEventType};
//!
//! // Create the webhook registry
//! let mut registry = WebhookRegistry::new();
//!
//! // Register a webhook endpoint
//! let webhook = Webhook {
//!     id: "wh_001".to_string(),
//!     url: "https://your-server.com/webhooks/hsm".to_string(),
//!     secret: "your-webhook-secret-key".to_string(),
//!     enabled: true,
//!     filter: EventFilter::new()
//!         .with_events(vec![
//!             WebhookEventType::KeyCreated,
//!             WebhookEventType::KeyDeleted,
//!             WebhookEventType::AuthenticationFailed,
//!         ])
//!         .with_namespaces(vec!["production".to_string()]),
//! };
//!
//! registry.register(webhook);
//! ```
//!
//! ### Configure Event Filtering
//!
//! Subscribe only to events you care about:
//!
//! ```rust,ignore
//! use hsm_webhooks::{EventFilter, WebhookEventType};
//!
//! // Security-focused filter (authentication/authorization events only)
//! let security_filter = EventFilter::new()
//!     .with_events(vec![
//!         WebhookEventType::AuthenticationFailed,
//!         WebhookEventType::AuthorizationDenied,
//!         WebhookEventType::RateLimitExceeded,
//!         WebhookEventType::PolicyViolated,
//!     ]);
//!
//! // Key lifecycle filter
//! let key_filter = EventFilter::new()
//!     .with_events(vec![
//!         WebhookEventType::KeyCreated,
//!         WebhookEventType::KeyDeleted,
//!         WebhookEventType::KeyRotated,
//!         WebhookEventType::KeyExported,
//!     ])
//!     .with_namespaces(vec!["production".to_string()]);
//!
//! // Backup monitoring filter
//! let backup_filter = EventFilter::new()
//!     .with_events(vec![
//!         WebhookEventType::BackupStarted,
//!         WebhookEventType::BackupCompleted,
//!         WebhookEventType::BackupFailed,
//!     ]);
//! ```
//!
//! ### Verify Webhook Signatures (Receiver Side)
//!
//! Always verify webhook signatures to ensure authenticity:
//!
//! ```rust,ignore
//! use hsm_webhooks::WebhookSigner;
//!
//! fn verify_webhook(
//!     secret: &str,
//!     signature_header: &str,   // X-Webhook-Signature
//!     timestamp_header: &str,   // X-Webhook-Timestamp
//!     body: &[u8],
//! ) -> bool {
//!     let signer = WebhookSigner::new(secret.as_bytes());
//!
//!     // Verify the signature matches
//!     let expected_signature = signer.sign(timestamp_header, body);
//!     let is_valid = constant_time_compare(signature_header, &expected_signature);
//!
//!     // Also check timestamp to prevent replay attacks (5 minute window)
//!     let timestamp: i64 = timestamp_header.parse().unwrap();
//!     let now = std::time::SystemTime::now()
//!         .duration_since(std::time::UNIX_EPOCH)
//!         .unwrap()
//!         .as_secs() as i64;
//!     let is_recent = (now - timestamp).abs() < 300;
//!
//!     is_valid && is_recent
//! }
//! ```
//!
//! ## Webhook Payload Format
//!
//! Webhooks are delivered as JSON POST requests:
//!
//! ```text
//! POST /webhooks/hsm HTTP/1.1
//! Host: your-server.com
//! Content-Type: application/json
//! X-Webhook-ID: evt_abc123
//! X-Webhook-Timestamp: 1705312800
//! X-Webhook-Signature: sha256=8d2a1b3c...
//!
//! {
//!   "id": "evt_abc123",
//!   "event_type": "key.created",
//!   "timestamp": "2024-01-15T10:00:00Z",
//!   "namespace": "production",
//!   "data": {
//!     "key_id": "key_xyz789",
//!     "algorithm": "Ed25519",
//!     "created_by": "admin@example.com"
//!   }
//! }
//! ```
//!
//! ## Retry Behavior
//!
//! Failed deliveries are retried with exponential backoff:
//!
//! | Attempt | Delay       | Total Time |
//! |---------|-------------|------------|
//! | 1       | Immediate   | 0s         |
//! | 2       | 1 second    | 1s         |
//! | 3       | 2 seconds   | 3s         |
//! | 4       | 4 seconds   | 7s         |
//! | 5       | 8 seconds   | 15s        |
//! | 6       | 16 seconds  | 31s        |
//! | 7       | 32 seconds  | 63s        |
//! | 8       | 60 seconds  | ~2m        |
//!
//! After 8 failed attempts, the event is moved to the dead letter queue.
//!
//! ## Security Considerations
//!
//! - **Use HTTPS**: Always use HTTPS endpoints for webhook delivery
//! - **Verify Signatures**: Always verify HMAC signatures before processing
//! - **Check Timestamps**: Reject events older than 5 minutes (replay protection)
//! - **Secret Rotation**: Rotate webhook secrets periodically
//! - **Idempotency**: Handle duplicate deliveries gracefully (use event ID)

pub mod config;
pub mod delivery;
pub mod dispatcher;
pub mod filter;
pub mod registry;
pub mod signature;

pub use config::WebhookConfig;
pub use delivery::{DeliveryResult, DeliveryStatus};
pub use dispatcher::WebhookDispatcher;
pub use filter::EventFilter;
pub use registry::{Webhook, WebhookRegistry};
pub use signature::WebhookSigner;

/// Webhook event types (mirrors audit event types)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum WebhookEventType {
    // Key events
    KeyCreated,
    KeyDeleted,
    KeyRotated,
    KeyUsed,
    KeyExported,

    // Session events
    SessionCreated,
    SessionExpired,
    SessionRevoked,

    // Policy events
    PolicyViolated,
    PolicyUpdated,

    // Backup events
    BackupStarted,
    BackupCompleted,
    BackupFailed,

    // System events
    SystemStartup,
    SystemShutdown,

    // Security events
    AuthenticationFailed,
    AuthorizationDenied,
    RateLimitExceeded,
}

impl WebhookEventType {
    /// Get the string name
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KeyCreated => "key.created",
            Self::KeyDeleted => "key.deleted",
            Self::KeyRotated => "key.rotated",
            Self::KeyUsed => "key.used",
            Self::KeyExported => "key.exported",
            Self::SessionCreated => "session.created",
            Self::SessionExpired => "session.expired",
            Self::SessionRevoked => "session.revoked",
            Self::PolicyViolated => "policy.violated",
            Self::PolicyUpdated => "policy.updated",
            Self::BackupStarted => "backup.started",
            Self::BackupCompleted => "backup.completed",
            Self::BackupFailed => "backup.failed",
            Self::SystemStartup => "system.startup",
            Self::SystemShutdown => "system.shutdown",
            Self::AuthenticationFailed => "security.auth_failed",
            Self::AuthorizationDenied => "security.authz_denied",
            Self::RateLimitExceeded => "security.rate_limited",
        }
    }

    /// Parse from string representation
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "key.created" => Some(Self::KeyCreated),
            "key.deleted" => Some(Self::KeyDeleted),
            "key.rotated" => Some(Self::KeyRotated),
            "key.used" => Some(Self::KeyUsed),
            "key.exported" => Some(Self::KeyExported),
            "session.created" => Some(Self::SessionCreated),
            "session.expired" => Some(Self::SessionExpired),
            "session.revoked" => Some(Self::SessionRevoked),
            "policy.violated" => Some(Self::PolicyViolated),
            "policy.updated" => Some(Self::PolicyUpdated),
            "backup.started" => Some(Self::BackupStarted),
            "backup.completed" => Some(Self::BackupCompleted),
            "backup.failed" => Some(Self::BackupFailed),
            "system.startup" => Some(Self::SystemStartup),
            "system.shutdown" => Some(Self::SystemShutdown),
            "security.auth_failed" => Some(Self::AuthenticationFailed),
            "security.authz_denied" => Some(Self::AuthorizationDenied),
            "security.rate_limited" => Some(Self::RateLimitExceeded),
            _ => None,
        }
    }

    /// Get all event types
    pub fn all() -> &'static [Self] {
        &[
            Self::KeyCreated,
            Self::KeyDeleted,
            Self::KeyRotated,
            Self::KeyUsed,
            Self::KeyExported,
            Self::SessionCreated,
            Self::SessionExpired,
            Self::SessionRevoked,
            Self::PolicyViolated,
            Self::PolicyUpdated,
            Self::BackupStarted,
            Self::BackupCompleted,
            Self::BackupFailed,
            Self::SystemStartup,
            Self::SystemShutdown,
            Self::AuthenticationFailed,
            Self::AuthorizationDenied,
            Self::RateLimitExceeded,
        ]
    }
}

impl std::fmt::Display for WebhookEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Webhook event payload
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebhookEvent {
    /// Unique event ID
    pub id: String,
    /// Event type
    pub event_type: WebhookEventType,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Namespace
    pub namespace: String,
    /// Event data
    pub data: serde_json::Value,
}

impl WebhookEvent {
    /// Create a new webhook event
    pub fn new(event_type: WebhookEventType, namespace: &str, data: serde_json::Value) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            event_type,
            timestamp: chrono::Utc::now(),
            namespace: namespace.to_string(),
            data,
        }
    }
}
