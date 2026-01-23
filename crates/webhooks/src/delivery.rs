//! Webhook HTTP delivery

use crate::{signature::WebhookSigner, WebhookEvent};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Delivery error
#[derive(Debug, Error)]
pub enum DeliveryError {
    /// HTTP error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    /// Timeout
    #[error("Request timeout")]
    Timeout,
    /// Invalid response
    #[error("Invalid response: {status} - {message}")]
    InvalidResponse { status: u16, message: String },
    /// Max retries exceeded
    #[error("Max retries exceeded after {attempts} attempts")]
    MaxRetriesExceeded { attempts: u32 },
}

/// Delivery status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// Successfully delivered
    Success,
    /// Failed delivery
    Failed,
    /// Pending retry
    PendingRetry,
}

/// Delivery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryResult {
    /// Webhook ID
    pub webhook_id: String,
    /// Event ID
    pub event_id: String,
    /// Status
    pub status: DeliveryStatus,
    /// HTTP status code (if response received)
    pub http_status: Option<u16>,
    /// Attempt number
    pub attempt: u32,
    /// Timestamp
    pub timestamp: chrono::DateTime<Utc>,
    /// Duration
    pub duration_ms: u64,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// HTTP webhook deliverer
pub struct WebhookDeliverer {
    client: Client,
}

impl WebhookDeliverer {
    /// Create a new deliverer
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("HSM-Webhook/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    /// Create with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .user_agent("HSM-Webhook/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    /// Deliver an event to a webhook
    pub async fn deliver(
        &self,
        url: &str,
        event: &WebhookEvent,
        signer: &WebhookSigner,
        headers: &std::collections::HashMap<String, String>,
    ) -> Result<DeliveryResult, DeliveryError> {
        let start = std::time::Instant::now();
        let payload = serde_json::to_vec(event).expect("Event serialization");
        let timestamp = Utc::now().timestamp();

        // Sign the payload
        let signature = signer.sign_with_timestamp(&payload, timestamp);

        // Build request
        let mut request = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header(crate::signature::headers::SIGNATURE, &signature)
            .header(crate::signature::headers::TIMESTAMP, timestamp.to_string())
            .header(crate::signature::headers::ID, &event.id)
            .header(
                crate::signature::headers::EVENT_TYPE,
                event.event_type.as_str(),
            );

        // Add custom headers
        for (name, value) in headers {
            request = request.header(name, value);
        }

        // Send request
        let response = request.body(payload).send().await?;

        let duration_ms = start.elapsed().as_millis() as u64;
        let http_status = response.status().as_u16();

        if response.status().is_success() {
            Ok(DeliveryResult {
                webhook_id: String::new(), // Set by caller
                event_id: event.id.clone(),
                status: DeliveryStatus::Success,
                http_status: Some(http_status),
                attempt: 1,
                timestamp: Utc::now(),
                duration_ms,
                error: None,
            })
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(DeliveryError::InvalidResponse {
                status: http_status,
                message: body,
            })
        }
    }

    /// Deliver with retries
    pub async fn deliver_with_retries(
        &self,
        url: &str,
        event: &WebhookEvent,
        signer: &WebhookSigner,
        headers: &std::collections::HashMap<String, String>,
        max_retries: u32,
        initial_delay: Duration,
    ) -> DeliveryResult {
        let mut attempt = 0;
        let mut delay = initial_delay;

        loop {
            attempt += 1;

            match self.deliver(url, event, signer, headers).await {
                Ok(mut result) => {
                    result.attempt = attempt;
                    return result;
                }
                Err(e) => {
                    if attempt >= max_retries {
                        return DeliveryResult {
                            webhook_id: String::new(),
                            event_id: event.id.clone(),
                            status: DeliveryStatus::Failed,
                            http_status: None,
                            attempt,
                            timestamp: Utc::now(),
                            duration_ms: 0,
                            error: Some(e.to_string()),
                        };
                    }

                    // Exponential backoff
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
            }
        }
    }
}

impl Default for WebhookDeliverer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_delivery_result_creation() {
        let result = DeliveryResult {
            webhook_id: "wh-123".to_string(),
            event_id: "evt-456".to_string(),
            status: DeliveryStatus::Success,
            http_status: Some(200),
            attempt: 1,
            timestamp: Utc::now(),
            duration_ms: 150,
            error: None,
        };

        assert_eq!(result.status, DeliveryStatus::Success);
        assert_eq!(result.http_status, Some(200));
    }

    #[tokio::test]
    async fn test_deliverer_creation() {
        let deliverer = WebhookDeliverer::new();
        // Just verify it creates successfully
        assert!(true);

        let deliverer_with_timeout = WebhookDeliverer::with_timeout(Duration::from_secs(60));
        assert!(true);
    }
}
