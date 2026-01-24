#![allow(clippy::all)]
#![allow(dead_code)]
#![allow(unused_imports)]
//! HSM Webhook Delivery System
//!
//! Provides webhook notifications for HSM events with:
//! - Reliable delivery with retries
//! - HMAC-SHA256 signature verification
//! - Event filtering
//! - Async dispatch
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   Webhook System Architecture                    │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                   │
//! │  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     │
//! │  │  HSM Events  │────▶│  Dispatcher  │────▶│   Delivery   │     │
//! │  │ (audit logs) │     │  (filtering) │     │  (HTTP POST) │     │
//! │  └──────────────┘     └──────────────┘     └──────────────┘     │
//! │                                                   │              │
//! │                                                   ▼              │
//! │                                          ┌──────────────┐       │
//! │                                          │   Webhooks   │       │
//! │                                          │  Endpoints   │       │
//! │                                          └──────────────┘       │
//! │                                                                   │
//! │  Security Features:                                              │
//! │  • HMAC-SHA256 signature in X-Webhook-Signature header          │
//! │  • Timestamp in X-Webhook-Timestamp header                      │
//! │  • Unique ID in X-Webhook-ID header                             │
//! │                                                                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

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

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
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
