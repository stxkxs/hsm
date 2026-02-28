//! Webhook HTTP delivery

use crate::{signature::WebhookSigner, WebhookEvent};
use chrono::Utc;
use dashmap::DashMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
    /// Circuit breaker open
    #[error("Circuit breaker open for URL: {0}")]
    CircuitBreakerOpen(String),
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

/// Circuit breaker state for a specific URL
#[derive(Debug, Clone)]
pub struct CircuitState {
    /// Number of consecutive failures
    pub consecutive_failures: u32,
    /// Timestamp of the last failure (Unix timestamp)
    pub last_failure_time: i64,
    /// Whether the circuit is open (rejecting requests)
    pub is_open: bool,
}

impl CircuitState {
    fn new() -> Self {
        Self {
            consecutive_failures: 0,
            last_failure_time: 0,
            is_open: false,
        }
    }
}

/// Threshold for consecutive failures before opening the circuit
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
/// Cooldown period in seconds before allowing a retry through an open circuit
const CIRCUIT_BREAKER_COOLDOWN_SECS: i64 = 60;

/// HTTP webhook deliverer
pub struct WebhookDeliverer {
    client: Client,
    circuit_breaker: Arc<DashMap<String, CircuitState>>,
}

impl WebhookDeliverer {
    /// Create a new deliverer
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("HSM-Webhook/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            circuit_breaker: Arc::new(DashMap::new()),
        }
    }

    /// Create with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .user_agent("HSM-Webhook/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            circuit_breaker: Arc::new(DashMap::new()),
        }
    }

    /// Check if the circuit breaker is open for a given URL
    fn is_circuit_open(&self, url: &str) -> bool {
        if let Some(state) = self.circuit_breaker.get(url) {
            if state.is_open {
                let now = Utc::now().timestamp();
                // Allow retry if cooldown period has elapsed
                if now - state.last_failure_time < CIRCUIT_BREAKER_COOLDOWN_SECS {
                    return true;
                }
            }
        }
        false
    }

    /// Record a successful delivery, resetting the circuit breaker
    fn record_success(&self, url: &str) {
        self.circuit_breaker.insert(url.to_string(), CircuitState::new());
    }

    /// Record a failed delivery, potentially opening the circuit breaker
    fn record_failure(&self, url: &str) {
        let mut state = self
            .circuit_breaker
            .entry(url.to_string())
            .or_insert_with(CircuitState::new);
        state.consecutive_failures += 1;
        state.last_failure_time = Utc::now().timestamp();
        if state.consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD {
            state.is_open = true;
        }
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
        // Check circuit breaker before attempting delivery
        if self.is_circuit_open(url) {
            return DeliveryResult {
                webhook_id: String::new(),
                event_id: event.id.clone(),
                status: DeliveryStatus::Failed,
                http_status: None,
                attempt: 0,
                timestamp: Utc::now(),
                duration_ms: 0,
                error: Some(format!("Circuit breaker open for URL: {}", url)),
            };
        }

        let mut attempt = 0;
        let mut delay = initial_delay;

        loop {
            attempt += 1;

            match self.deliver(url, event, signer, headers).await {
                Ok(mut result) => {
                    result.attempt = attempt;
                    self.record_success(url);
                    return result;
                }
                Err(e) => {
                    self.record_failure(url);

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

                    // Check circuit breaker after recording failure
                    if self.is_circuit_open(url) {
                        return DeliveryResult {
                            webhook_id: String::new(),
                            event_id: event.id.clone(),
                            status: DeliveryStatus::Failed,
                            http_status: None,
                            attempt,
                            timestamp: Utc::now(),
                            duration_ms: 0,
                            error: Some(format!("Circuit breaker open for URL: {}", url)),
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

    #[test]
    fn test_circuit_breaker_initially_closed() {
        let deliverer = WebhookDeliverer::new();
        assert!(!deliverer.is_circuit_open("https://example.com/webhook"));
    }

    #[test]
    fn test_circuit_breaker_opens_after_threshold() {
        let deliverer = WebhookDeliverer::new();
        let url = "https://example.com/webhook";

        // Record failures up to threshold
        for _ in 0..CIRCUIT_BREAKER_THRESHOLD {
            deliverer.record_failure(url);
        }

        assert!(deliverer.is_circuit_open(url));
    }

    #[test]
    fn test_circuit_breaker_resets_on_success() {
        let deliverer = WebhookDeliverer::new();
        let url = "https://example.com/webhook";

        // Open the circuit
        for _ in 0..CIRCUIT_BREAKER_THRESHOLD {
            deliverer.record_failure(url);
        }
        assert!(deliverer.is_circuit_open(url));

        // Reset on success
        deliverer.record_success(url);
        assert!(!deliverer.is_circuit_open(url));
    }
}
