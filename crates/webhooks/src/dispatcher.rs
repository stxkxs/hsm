//! Webhook event dispatcher

use crate::{
    delivery::{DeliveryResult, DeliveryStatus, WebhookDeliverer},
    registry::{Webhook, WebhookRegistry},
    signature::WebhookSigner,
    WebhookEvent, WebhookEventType,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Webhook dispatcher for async event delivery
pub struct WebhookDispatcher {
    /// Registry of webhooks
    registry: Arc<WebhookRegistry>,
    /// HTTP deliverer
    deliverer: Arc<WebhookDeliverer>,
    /// Event sender channel
    event_tx: mpsc::Sender<WebhookEvent>,
}

impl WebhookDispatcher {
    /// Create a new dispatcher
    pub fn new(registry: Arc<WebhookRegistry>) -> Self {
        let deliverer = Arc::new(WebhookDeliverer::new());
        let (event_tx, event_rx) = mpsc::channel(10000);

        let dispatcher = Self {
            registry: registry.clone(),
            deliverer: deliverer.clone(),
            event_tx,
        };

        // Start background delivery task
        tokio::spawn(Self::delivery_task(registry, deliverer, event_rx));

        dispatcher
    }

    /// Dispatch an event to matching webhooks
    pub async fn dispatch(
        &self,
        event: WebhookEvent,
    ) -> Result<(), mpsc::error::SendError<WebhookEvent>> {
        self.event_tx.send(event).await
    }

    /// Dispatch synchronously (non-blocking)
    pub fn dispatch_sync(
        &self,
        event: WebhookEvent,
    ) -> Result<(), mpsc::error::TrySendError<WebhookEvent>> {
        self.event_tx.try_send(event)
    }

    /// Create and dispatch an event
    pub async fn emit(
        &self,
        event_type: WebhookEventType,
        namespace: &str,
        data: serde_json::Value,
    ) -> Result<String, mpsc::error::SendError<WebhookEvent>> {
        let event = WebhookEvent::new(event_type, namespace, data);
        let id = event.id.clone();
        self.dispatch(event).await?;
        Ok(id)
    }

    /// Background task for processing events
    async fn delivery_task(
        registry: Arc<WebhookRegistry>,
        deliverer: Arc<WebhookDeliverer>,
        mut event_rx: mpsc::Receiver<WebhookEvent>,
    ) {
        while let Some(event) = event_rx.recv().await {
            // Find matching webhooks
            let webhooks = registry.get_matching(event.event_type, &event.namespace);

            if webhooks.is_empty() {
                continue;
            }

            info!(
                event_id = %event.id,
                event_type = %event.event_type,
                webhook_count = webhooks.len(),
                "Dispatching event to webhooks"
            );

            // Deliver to each webhook concurrently
            let futures: Vec<_> = webhooks
                .into_iter()
                .map(|webhook| {
                    let deliverer = deliverer.clone();
                    let registry = registry.clone();
                    let event = event.clone();
                    tokio::spawn(async move {
                        Self::deliver_to_webhook(&deliverer, &registry, &webhook, &event).await
                    })
                })
                .collect();

            // Wait for all deliveries
            for future in futures {
                if let Err(e) = future.await {
                    error!(error = %e, "Delivery task failed");
                }
            }
        }
    }

    /// Deliver event to a single webhook
    async fn deliver_to_webhook(
        deliverer: &WebhookDeliverer,
        registry: &WebhookRegistry,
        webhook: &Webhook,
        event: &WebhookEvent,
    ) {
        let signer = WebhookSigner::new(&webhook.config.secret);

        let result = deliverer
            .deliver_with_retries(
                &webhook.config.url,
                event,
                &signer,
                &webhook.config.headers,
                webhook.config.max_retries,
                webhook.config.retry_delay,
            )
            .await;

        // Record delivery result
        let success = result.status == DeliveryStatus::Success;
        registry.record_delivery(&webhook.id, success);

        if success {
            info!(
                webhook_id = %webhook.id,
                event_id = %event.id,
                attempt = result.attempt,
                duration_ms = result.duration_ms,
                "Webhook delivered successfully"
            );
        } else {
            warn!(
                webhook_id = %webhook.id,
                event_id = %event.id,
                attempt = result.attempt,
                error = ?result.error,
                "Webhook delivery failed"
            );
        }
    }

    /// Get the registry
    pub fn registry(&self) -> Arc<WebhookRegistry> {
        self.registry.clone()
    }

    /// Get pending events count (approximate)
    pub fn pending_count(&self) -> usize {
        self.event_tx.capacity() - self.event_tx.max_capacity()
    }
}

/// Builder for webhook dispatcher
pub struct WebhookDispatcherBuilder {
    registry: Option<Arc<WebhookRegistry>>,
    channel_size: usize,
}

impl WebhookDispatcherBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            registry: None,
            channel_size: 10000,
        }
    }

    /// Set the registry
    pub fn registry(mut self, registry: Arc<WebhookRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Set channel size
    pub fn channel_size(mut self, size: usize) -> Self {
        self.channel_size = size;
        self
    }

    /// Build the dispatcher
    pub fn build(self) -> WebhookDispatcher {
        let registry = self
            .registry
            .unwrap_or_else(|| Arc::new(WebhookRegistry::new()));
        WebhookDispatcher::new(registry)
    }
}

impl Default for WebhookDispatcherBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WebhookConfig;
    use serde_json::json;

    #[tokio::test]
    async fn test_dispatcher_creation() {
        let registry = Arc::new(WebhookRegistry::new());
        let dispatcher = WebhookDispatcher::new(registry);
        assert_eq!(dispatcher.registry().count(), 0);
    }

    #[tokio::test]
    async fn test_emit_event() {
        let registry = Arc::new(WebhookRegistry::new());

        // Add a webhook
        let config = WebhookConfig::new("https://example.com/webhook", "secret_key_12345678");
        let webhook = Webhook::new("Test", config, "admin");
        registry.register(webhook);

        let dispatcher = WebhookDispatcher::new(registry);

        // Emit an event
        let event_id = dispatcher
            .emit(
                WebhookEventType::KeyCreated,
                "default",
                json!({"key_id": "key-123"}),
            )
            .await
            .unwrap();

        assert!(!event_id.is_empty());
    }

    #[tokio::test]
    async fn test_builder() {
        let dispatcher = WebhookDispatcherBuilder::new().channel_size(5000).build();

        assert_eq!(dispatcher.registry().count(), 0);
    }
}
