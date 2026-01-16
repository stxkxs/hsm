// Audit logging module for authentication and authorization events
// Provides complete audit trail for compliance and security

use crate::mtls::ClientIdentity;
use crate::rbac::Permission;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Authentication events
    AuthenticationSuccess,
    AuthenticationFailure,
    CertificateValidationFailed,
    CertificateExpired,
    CertificateRevoked,

    /// Authorization events
    AuthorizationGranted,
    AuthorizationDenied,
    PermissionCheckFailed,

    /// Session events
    SessionCreated,
    SessionValidated,
    SessionExpired,
    SessionDeleted,
    SessionHijackingAttempt,
    SessionTokenRotated,

    /// Namespace events
    NamespaceAccessGranted,
    NamespaceAccessDenied,
    NamespaceViolation,
    NamespaceCreated,
    NamespaceDeleted,

    /// Rate limiting events
    RateLimitExceeded,
    RateLimitWarning,

    /// Certificate events
    CertificatePinningFailed,
    CertificateRenewed,

    /// Policy events
    PolicyLoaded,
    PolicyReloadFailed,
    PolicyViolation,

    /// ACL events
    AclViolation,
    AclUpdated,
}

/// Audit event severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event type
    pub event_type: AuditEventType,

    /// Event severity
    pub severity: AuditSeverity,

    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Client identity (if available)
    pub identity: Option<ClientIdentity>,

    /// Namespace (if applicable)
    pub namespace: Option<String>,

    /// Permission (if applicable)
    pub permission: Option<String>,

    /// Additional details
    pub details: String,

    /// Result (success/failure)
    pub success: bool,

    /// Client IP address (if available)
    pub client_ip: Option<String>,

    /// Resource being accessed (if applicable)
    pub resource: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(event_type: AuditEventType, severity: AuditSeverity, details: String) -> Self {
        Self {
            event_type,
            severity,
            timestamp: Utc::now(),
            identity: None,
            namespace: None,
            permission: None,
            details,
            success: false,
            client_ip: None,
            resource: None,
        }
    }

    /// Set identity
    pub fn with_identity(mut self, identity: ClientIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Set namespace
    pub fn with_namespace(mut self, namespace: String) -> Self {
        self.namespace = Some(namespace);
        self
    }

    /// Set permission
    pub fn with_permission(mut self, permission: &Permission) -> Self {
        self.permission = Some(permission.as_str().to_string());
        self
    }

    /// Set success
    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    /// Set client IP
    pub fn with_client_ip(mut self, ip: String) -> Self {
        self.client_ip = Some(ip);
        self
    }

    /// Set resource
    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource = Some(resource);
        self
    }
}

/// Audit logger trait
pub trait AuditLogger: Send + Sync {
    /// Log an audit event
    fn log(&self, event: AuditEvent);

    /// Flush pending events
    fn flush(&self);
}

/// In-memory audit logger (for testing and development)
pub struct InMemoryAuditLogger {
    events: Arc<parking_lot::RwLock<Vec<AuditEvent>>>,
}

impl InMemoryAuditLogger {
    /// Create a new in-memory audit logger
    pub fn new() -> Self {
        Self {
            events: Arc::new(parking_lot::RwLock::new(Vec::new())),
        }
    }

    /// Get all events
    pub fn get_events(&self) -> Vec<AuditEvent> {
        self.events.read().clone()
    }

    /// Get events by type
    pub fn get_events_by_type(&self, event_type: AuditEventType) -> Vec<AuditEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| {
                std::mem::discriminant(&e.event_type) == std::mem::discriminant(&event_type)
            })
            .cloned()
            .collect()
    }

    /// Get events by severity
    pub fn get_events_by_severity(&self, severity: AuditSeverity) -> Vec<AuditEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.severity == severity)
            .cloned()
            .collect()
    }

    /// Get events for an identity
    pub fn get_events_for_identity(&self, common_name: &str) -> Vec<AuditEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| {
                e.identity
                    .as_ref()
                    .map(|i| i.common_name == common_name)
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// Clear all events
    pub fn clear(&self) {
        self.events.write().clear();
    }

    /// Get event count
    pub fn event_count(&self) -> usize {
        self.events.read().len()
    }
}

impl Default for InMemoryAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger for InMemoryAuditLogger {
    fn log(&self, event: AuditEvent) {
        self.events.write().push(event.clone());

        // Emit metric
        metrics::counter!("auth.audit.event").increment(1);

        // Log to stdout for debugging (in production, use proper logging)
        #[cfg(debug_assertions)]
        {
            eprintln!("[AUDIT] {:?}: {}", event.event_type, event.details);
        }
    }

    fn flush(&self) {
        // No-op for in-memory logger
    }
}

/// Global audit logger instance
use std::sync::OnceLock;
static AUDIT_LOGGER: OnceLock<Arc<dyn AuditLogger>> = OnceLock::new();

/// Get or initialize the global audit logger
fn get_audit_logger() -> &'static Arc<dyn AuditLogger> {
    AUDIT_LOGGER.get_or_init(|| Arc::new(InMemoryAuditLogger::new()))
}

/// Log an audit event using the global logger
pub fn log(event: AuditEvent) {
    get_audit_logger().log(event);
}

/// Helper functions for common audit events

pub fn log_authentication_success(identity: ClientIdentity) {
    log(AuditEvent::new(
        AuditEventType::AuthenticationSuccess,
        AuditSeverity::Info,
        format!("Client {} authenticated successfully", identity.common_name),
    )
    .with_identity(identity)
    .with_success(true));
}

pub fn log_authentication_failure(reason: String) {
    log(AuditEvent::new(
        AuditEventType::AuthenticationFailure,
        AuditSeverity::Warning,
        reason,
    ));
}

pub fn log_authorization_denied(
    identity: ClientIdentity,
    permission: &Permission,
    resource: String,
) {
    log(AuditEvent::new(
        AuditEventType::AuthorizationDenied,
        AuditSeverity::Warning,
        format!(
            "Client {} denied access to {} (permission: {})",
            identity.common_name,
            resource,
            permission.as_str()
        ),
    )
    .with_identity(identity)
    .with_permission(permission)
    .with_resource(resource));
}

pub fn log_authorization_granted(
    identity: ClientIdentity,
    permission: &Permission,
    resource: String,
) {
    log(AuditEvent::new(
        AuditEventType::AuthorizationGranted,
        AuditSeverity::Info,
        format!(
            "Client {} granted access to {} (permission: {})",
            identity.common_name,
            resource,
            permission.as_str()
        ),
    )
    .with_identity(identity)
    .with_permission(permission)
    .with_resource(resource)
    .with_success(true));
}

pub fn log_rate_limit_exceeded(identity: ClientIdentity, limit_type: String) {
    log(AuditEvent::new(
        AuditEventType::RateLimitExceeded,
        AuditSeverity::Warning,
        format!(
            "Rate limit exceeded for client {} (type: {})",
            identity.common_name, limit_type
        ),
    )
    .with_identity(identity));
}

pub fn log_namespace_violation(identity: ClientIdentity, namespace: String) {
    log(AuditEvent::new(
        AuditEventType::NamespaceViolation,
        AuditSeverity::Error,
        format!(
            "Client {} attempted to access namespace {} without permission",
            identity.common_name, namespace
        ),
    )
    .with_identity(identity)
    .with_namespace(namespace));
}

pub fn log_session_hijacking_attempt(identity: ClientIdentity, details: String) {
    log(AuditEvent::new(
        AuditEventType::SessionHijackingAttempt,
        AuditSeverity::Critical,
        format!(
            "Possible session hijacking detected for client {}: {}",
            identity.common_name, details
        ),
    )
    .with_identity(identity));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::Role;

    fn create_test_identity() -> ClientIdentity {
        ClientIdentity::new(
            "test-client".to_string(),
            None,
            "test-namespace".to_string(),
            vec![Role::User],
            "123456".to_string(),
        )
    }

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            AuditEventType::AuthenticationSuccess,
            AuditSeverity::Info,
            "Test event".to_string(),
        );

        assert_eq!(event.severity, AuditSeverity::Info);
        assert_eq!(event.details, "Test event");
        assert!(event.identity.is_none());
    }

    #[test]
    fn test_audit_event_with_identity() {
        let identity = create_test_identity();
        let event = AuditEvent::new(
            AuditEventType::AuthenticationSuccess,
            AuditSeverity::Info,
            "Test event".to_string(),
        )
        .with_identity(identity.clone());

        assert!(event.identity.is_some());
        assert_eq!(event.identity.unwrap().common_name, "test-client");
    }

    #[test]
    fn test_in_memory_logger() {
        let logger = InMemoryAuditLogger::new();

        let event = AuditEvent::new(
            AuditEventType::AuthenticationSuccess,
            AuditSeverity::Info,
            "Test event".to_string(),
        );

        logger.log(event);
        assert_eq!(logger.event_count(), 1);

        let events = logger.get_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].details, "Test event");
    }

    #[test]
    fn test_filter_by_severity() {
        let logger = InMemoryAuditLogger::new();

        logger.log(AuditEvent::new(
            AuditEventType::AuthenticationSuccess,
            AuditSeverity::Info,
            "Info event".to_string(),
        ));

        logger.log(AuditEvent::new(
            AuditEventType::AuthenticationFailure,
            AuditSeverity::Warning,
            "Warning event".to_string(),
        ));

        logger.log(AuditEvent::new(
            AuditEventType::SessionHijackingAttempt,
            AuditSeverity::Critical,
            "Critical event".to_string(),
        ));

        let warnings = logger.get_events_by_severity(AuditSeverity::Warning);
        assert_eq!(warnings.len(), 1);

        let criticals = logger.get_events_by_severity(AuditSeverity::Critical);
        assert_eq!(criticals.len(), 1);
    }
}
