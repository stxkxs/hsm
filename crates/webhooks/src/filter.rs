//! Event filtering for webhooks

use crate::WebhookEventType;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Event filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    /// Event types to include (empty = all)
    pub include_events: HashSet<WebhookEventType>,
    /// Event types to exclude
    pub exclude_events: HashSet<WebhookEventType>,
    /// Namespaces to include (empty = all)
    pub include_namespaces: HashSet<String>,
    /// Namespaces to exclude
    pub exclude_namespaces: HashSet<String>,
    /// Minimum severity level (optional)
    pub min_severity: Option<EventSeverity>,
}

/// Event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventSeverity {
    /// Debug level
    Debug = 0,
    /// Info level
    Info = 1,
    /// Warning level
    Warning = 2,
    /// Error level
    Error = 3,
    /// Critical level
    Critical = 4,
}

impl EventFilter {
    /// Create a filter that accepts all events
    pub fn all() -> Self {
        Self {
            include_events: HashSet::new(),
            exclude_events: HashSet::new(),
            include_namespaces: HashSet::new(),
            exclude_namespaces: HashSet::new(),
            min_severity: None,
        }
    }

    /// Create a filter for specific events
    pub fn events(events: &[WebhookEventType]) -> Self {
        Self {
            include_events: events.iter().copied().collect(),
            exclude_events: HashSet::new(),
            include_namespaces: HashSet::new(),
            exclude_namespaces: HashSet::new(),
            min_severity: None,
        }
    }

    /// Add events to include
    pub fn include_event(mut self, event: WebhookEventType) -> Self {
        self.include_events.insert(event);
        self
    }

    /// Add events to exclude
    pub fn exclude_event(mut self, event: WebhookEventType) -> Self {
        self.exclude_events.insert(event);
        self
    }

    /// Add namespace to include
    pub fn include_namespace(mut self, namespace: &str) -> Self {
        self.include_namespaces.insert(namespace.to_string());
        self
    }

    /// Add namespace to exclude
    pub fn exclude_namespace(mut self, namespace: &str) -> Self {
        self.exclude_namespaces.insert(namespace.to_string());
        self
    }

    /// Set minimum severity
    pub fn with_min_severity(mut self, severity: EventSeverity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    /// Check if an event passes the filter
    pub fn matches(&self, event_type: WebhookEventType, namespace: &str) -> bool {
        // Check event type exclusion first
        if self.exclude_events.contains(&event_type) {
            return false;
        }

        // Check event type inclusion
        if !self.include_events.is_empty() && !self.include_events.contains(&event_type) {
            return false;
        }

        // Check namespace exclusion
        if self.exclude_namespaces.contains(namespace) {
            return false;
        }

        // Check namespace inclusion
        if !self.include_namespaces.is_empty() && !self.include_namespaces.contains(namespace) {
            return false;
        }

        true
    }

    /// Check if an event passes with severity check
    pub fn matches_with_severity(
        &self,
        event_type: WebhookEventType,
        namespace: &str,
        severity: EventSeverity,
    ) -> bool {
        // Check minimum severity
        if let Some(min) = self.min_severity {
            if severity < min {
                return false;
            }
        }

        self.matches(event_type, namespace)
    }
}

impl Default for EventFilter {
    fn default() -> Self {
        Self::all()
    }
}

/// Get the severity of an event type
pub fn event_severity(event_type: WebhookEventType) -> EventSeverity {
    match event_type {
        // Critical events
        WebhookEventType::PolicyViolated
        | WebhookEventType::AuthenticationFailed
        | WebhookEventType::AuthorizationDenied
        | WebhookEventType::BackupFailed => EventSeverity::Critical,

        // Warning events
        WebhookEventType::KeyDeleted
        | WebhookEventType::SessionRevoked
        | WebhookEventType::RateLimitExceeded => EventSeverity::Warning,

        // Info events
        WebhookEventType::KeyCreated
        | WebhookEventType::KeyRotated
        | WebhookEventType::KeyExported
        | WebhookEventType::SessionCreated
        | WebhookEventType::SessionExpired
        | WebhookEventType::PolicyUpdated
        | WebhookEventType::BackupStarted
        | WebhookEventType::BackupCompleted
        | WebhookEventType::SystemStartup
        | WebhookEventType::SystemShutdown => EventSeverity::Info,

        // Debug events
        WebhookEventType::KeyUsed => EventSeverity::Debug,
    }
}

/// Predefined filters
pub mod presets {
    use super::*;

    /// Filter for security-related events only
    pub fn security_only() -> EventFilter {
        EventFilter::events(&[
            WebhookEventType::AuthenticationFailed,
            WebhookEventType::AuthorizationDenied,
            WebhookEventType::PolicyViolated,
            WebhookEventType::RateLimitExceeded,
            WebhookEventType::KeyDeleted,
            WebhookEventType::KeyExported,
        ])
    }

    /// Filter for key lifecycle events
    pub fn key_lifecycle() -> EventFilter {
        EventFilter::events(&[
            WebhookEventType::KeyCreated,
            WebhookEventType::KeyDeleted,
            WebhookEventType::KeyRotated,
            WebhookEventType::KeyExported,
        ])
    }

    /// Filter for backup events
    pub fn backup_events() -> EventFilter {
        EventFilter::events(&[
            WebhookEventType::BackupStarted,
            WebhookEventType::BackupCompleted,
            WebhookEventType::BackupFailed,
        ])
    }

    /// Filter for system events
    pub fn system_events() -> EventFilter {
        EventFilter::events(&[
            WebhookEventType::SystemStartup,
            WebhookEventType::SystemShutdown,
        ])
    }

    /// Filter for high severity events (warning and above)
    pub fn high_severity() -> EventFilter {
        EventFilter::all().with_min_severity(EventSeverity::Warning)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_all() {
        let filter = EventFilter::all();
        assert!(filter.matches(WebhookEventType::KeyCreated, "default"));
        assert!(filter.matches(WebhookEventType::PolicyViolated, "prod"));
    }

    #[test]
    fn test_filter_include_events() {
        let filter =
            EventFilter::events(&[WebhookEventType::KeyCreated, WebhookEventType::KeyDeleted]);

        assert!(filter.matches(WebhookEventType::KeyCreated, "default"));
        assert!(filter.matches(WebhookEventType::KeyDeleted, "default"));
        assert!(!filter.matches(WebhookEventType::KeyRotated, "default"));
    }

    #[test]
    fn test_filter_exclude_events() {
        let filter = EventFilter::all().exclude_event(WebhookEventType::KeyUsed);

        assert!(filter.matches(WebhookEventType::KeyCreated, "default"));
        assert!(!filter.matches(WebhookEventType::KeyUsed, "default"));
    }

    #[test]
    fn test_filter_namespaces() {
        let filter = EventFilter::all()
            .include_namespace("prod")
            .include_namespace("staging");

        assert!(filter.matches(WebhookEventType::KeyCreated, "prod"));
        assert!(filter.matches(WebhookEventType::KeyCreated, "staging"));
        assert!(!filter.matches(WebhookEventType::KeyCreated, "dev"));
    }

    #[test]
    fn test_filter_exclude_namespaces() {
        let filter = EventFilter::all().exclude_namespace("test");

        assert!(filter.matches(WebhookEventType::KeyCreated, "prod"));
        assert!(!filter.matches(WebhookEventType::KeyCreated, "test"));
    }

    #[test]
    fn test_filter_severity() {
        let filter = EventFilter::all().with_min_severity(EventSeverity::Warning);

        // KeyUsed is Debug severity
        assert!(!filter.matches_with_severity(
            WebhookEventType::KeyUsed,
            "default",
            EventSeverity::Debug
        ));

        // PolicyViolated is Critical severity
        assert!(filter.matches_with_severity(
            WebhookEventType::PolicyViolated,
            "default",
            EventSeverity::Critical
        ));
    }

    #[test]
    fn test_preset_security_only() {
        let filter = presets::security_only();
        assert!(filter.matches(WebhookEventType::AuthenticationFailed, "default"));
        assert!(!filter.matches(WebhookEventType::KeyCreated, "default"));
    }
}
