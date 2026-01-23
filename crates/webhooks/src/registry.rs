//! Webhook registration and management

use crate::{config::WebhookConfig, filter::EventFilter};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Webhook ID
pub type WebhookId = String;

/// Webhook registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    /// Unique identifier
    pub id: WebhookId,
    /// Display name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Configuration
    pub config: WebhookConfig,
    /// Event filter
    pub filter: EventFilter,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last delivery attempt
    pub last_delivery: Option<DateTime<Utc>>,
    /// Total delivery attempts
    pub delivery_count: u64,
    /// Successful deliveries
    pub success_count: u64,
    /// Failed deliveries
    pub failure_count: u64,
    /// Owner/creator
    pub owner: String,
}

impl Webhook {
    /// Create a new webhook
    pub fn new(name: &str, config: WebhookConfig, owner: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: None,
            config,
            filter: EventFilter::all(),
            created_at: Utc::now(),
            last_delivery: None,
            delivery_count: 0,
            success_count: 0,
            failure_count: 0,
            owner: owner.to_string(),
        }
    }

    /// Set description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Set filter
    pub fn with_filter(mut self, filter: EventFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Record a delivery attempt
    pub fn record_delivery(&mut self, success: bool) {
        self.delivery_count += 1;
        self.last_delivery = Some(Utc::now());
        if success {
            self.success_count += 1;
        } else {
            self.failure_count += 1;
        }
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.delivery_count == 0 {
            1.0
        } else {
            self.success_count as f64 / self.delivery_count as f64
        }
    }

    /// Check if webhook is healthy (>90% success rate)
    pub fn is_healthy(&self) -> bool {
        self.delivery_count < 10 || self.success_rate() > 0.9
    }
}

/// Webhook registry for managing registrations
pub struct WebhookRegistry {
    /// Registered webhooks
    webhooks: Arc<DashMap<WebhookId, Webhook>>,
}

impl WebhookRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            webhooks: Arc::new(DashMap::new()),
        }
    }

    /// Register a new webhook
    pub fn register(&self, webhook: Webhook) -> WebhookId {
        let id = webhook.id.clone();
        self.webhooks.insert(id.clone(), webhook);
        id
    }

    /// Get a webhook by ID
    pub fn get(&self, id: &str) -> Option<Webhook> {
        self.webhooks.get(id).map(|w| w.clone())
    }

    /// Update a webhook
    pub fn update(&self, id: &str, updater: impl FnOnce(&mut Webhook)) -> Option<Webhook> {
        let mut webhook = self.webhooks.get_mut(id)?;
        updater(&mut webhook);
        Some(webhook.clone())
    }

    /// Delete a webhook
    pub fn delete(&self, id: &str) -> Option<Webhook> {
        self.webhooks.remove(id).map(|(_, w)| w)
    }

    /// List all webhooks
    pub fn list(&self) -> Vec<Webhook> {
        self.webhooks.iter().map(|r| r.clone()).collect()
    }

    /// List webhooks by owner
    pub fn list_by_owner(&self, owner: &str) -> Vec<Webhook> {
        self.webhooks
            .iter()
            .filter(|r| r.owner == owner)
            .map(|r| r.clone())
            .collect()
    }

    /// Get enabled webhooks matching an event
    pub fn get_matching(
        &self,
        event_type: crate::WebhookEventType,
        namespace: &str,
    ) -> Vec<Webhook> {
        self.webhooks
            .iter()
            .filter(|w| w.config.enabled && w.filter.matches(event_type, namespace))
            .map(|w| w.clone())
            .collect()
    }

    /// Record delivery result
    pub fn record_delivery(&self, id: &str, success: bool) {
        if let Some(mut webhook) = self.webhooks.get_mut(id) {
            webhook.record_delivery(success);
        }
    }

    /// Enable a webhook
    pub fn enable(&self, id: &str) -> bool {
        self.update(id, |w| w.config.set_enabled(true)).is_some()
    }

    /// Disable a webhook
    pub fn disable(&self, id: &str) -> bool {
        self.update(id, |w| w.config.set_enabled(false)).is_some()
    }

    /// Count total webhooks
    pub fn count(&self) -> usize {
        self.webhooks.len()
    }

    /// Count enabled webhooks
    pub fn count_enabled(&self) -> usize {
        self.webhooks.iter().filter(|w| w.config.enabled).count()
    }

    /// Get unhealthy webhooks
    pub fn get_unhealthy(&self) -> Vec<Webhook> {
        self.webhooks
            .iter()
            .filter(|w| !w.is_healthy())
            .map(|w| w.clone())
            .collect()
    }
}

impl Default for WebhookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_creation() {
        let config = WebhookConfig::new("https://example.com/webhook", "secret_key_12345678");
        let webhook = Webhook::new("Test Webhook", config, "admin");

        assert!(!webhook.id.is_empty());
        assert_eq!(webhook.name, "Test Webhook");
        assert_eq!(webhook.owner, "admin");
        assert_eq!(webhook.delivery_count, 0);
    }

    #[test]
    fn test_webhook_delivery_tracking() {
        let config = WebhookConfig::new("https://example.com/webhook", "secret_key_12345678");
        let mut webhook = Webhook::new("Test", config, "admin");

        webhook.record_delivery(true);
        webhook.record_delivery(true);
        webhook.record_delivery(false);

        assert_eq!(webhook.delivery_count, 3);
        assert_eq!(webhook.success_count, 2);
        assert_eq!(webhook.failure_count, 1);
        assert!((webhook.success_rate() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_registry_crud() {
        let registry = WebhookRegistry::new();

        // Create
        let config = WebhookConfig::new("https://example.com/webhook", "secret_key_12345678");
        let webhook = Webhook::new("Test", config, "admin");
        let id = registry.register(webhook);

        // Read
        let retrieved = registry.get(&id).unwrap();
        assert_eq!(retrieved.name, "Test");

        // Update
        registry.update(&id, |w| w.name = "Updated".to_string());
        let updated = registry.get(&id).unwrap();
        assert_eq!(updated.name, "Updated");

        // Delete
        let deleted = registry.delete(&id);
        assert!(deleted.is_some());
        assert!(registry.get(&id).is_none());
    }

    #[test]
    fn test_registry_filtering() {
        let registry = WebhookRegistry::new();

        // Add webhook for key events
        let config = WebhookConfig::new("https://example.com/keys", "secret_key_12345678");
        let webhook = Webhook::new("Key Events", config, "admin")
            .with_filter(crate::filter::presets::key_lifecycle());
        registry.register(webhook);

        // Add webhook for all events
        let config = WebhookConfig::new("https://example.com/all", "secret_key_12345678");
        let webhook = Webhook::new("All Events", config, "admin");
        registry.register(webhook);

        // Check matching
        let key_matches = registry.get_matching(crate::WebhookEventType::KeyCreated, "default");
        assert_eq!(key_matches.len(), 2);

        let session_matches =
            registry.get_matching(crate::WebhookEventType::SessionCreated, "default");
        assert_eq!(session_matches.len(), 1); // Only "All Events"
    }
}
