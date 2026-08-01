//! Alert channels for bridge security notifications

use crate::config::AlertConfig;
use crate::detection::{DetectionResult, Severity};
use crate::error::{BridgeError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Alert message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Alert ID
    pub id: String,
    /// Alert title
    pub title: String,
    /// Alert message
    pub message: String,
    /// Severity level
    pub severity: Severity,
    /// Source (component that generated alert)
    pub source: String,
    /// Timestamp
    pub timestamp: i64,
    /// Additional data
    #[serde(default)]
    pub metadata: serde_json::Value,
    /// Whether alert has been acknowledged
    pub acknowledged: bool,
}

impl Alert {
    /// Create a new alert
    pub fn new(title: &str, message: &str, severity: Severity, source: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title: title.to_string(),
            message: message.to_string(),
            severity,
            source: source.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            metadata: serde_json::Value::Null,
            acknowledged: false,
        }
    }

    /// Add metadata
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    /// Create from detection result
    pub fn from_detection(detection: &DetectionResult, source: &str) -> Self {
        Self::new(
            &format!("{:?} Detected", detection.anomaly_type),
            &detection.description,
            detection.severity,
            source,
        )
        .with_metadata(detection.details.clone())
    }
}

/// Alert channel trait
#[async_trait::async_trait]
pub trait AlertChannel: Send + Sync {
    /// Channel name
    fn name(&self) -> &str;

    /// Send an alert
    async fn send(&self, alert: &Alert) -> Result<()>;

    /// Check if channel is available
    fn is_available(&self) -> bool;
}

/// Slack alert channel
pub struct SlackChannel {
    name: String,
    webhook_url: String,
    client: reqwest::Client,
}

impl SlackChannel {
    /// Create a new Slack channel
    pub fn new(webhook_url: &str) -> Self {
        Self {
            name: "slack".to_string(),
            webhook_url: webhook_url.to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Format alert for Slack
    fn format_message(&self, alert: &Alert) -> serde_json::Value {
        let color = match alert.severity {
            Severity::Critical => "#FF0000",
            Severity::High => "#FF6600",
            Severity::Medium => "#FFCC00",
            Severity::Low => "#00CC00",
        };

        serde_json::json!({
            "attachments": [{
                "color": color,
                "title": alert.title,
                "text": alert.message,
                "fields": [
                    {
                        "title": "Severity",
                        "value": format!("{:?}", alert.severity),
                        "short": true
                    },
                    {
                        "title": "Source",
                        "value": alert.source,
                        "short": true
                    }
                ],
                "ts": alert.timestamp
            }]
        })
    }
}

#[async_trait::async_trait]
impl AlertChannel for SlackChannel {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, alert: &Alert) -> Result<()> {
        let payload = self.format_message(alert);

        let response = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| BridgeError::Internal(format!("Slack request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(BridgeError::Internal(format!(
                "Slack returned error: {}",
                response.status()
            )));
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        !self.webhook_url.is_empty()
    }
}

/// PagerDuty alert channel
pub struct PagerDutyChannel {
    name: String,
    integration_key: String,
    client: reqwest::Client,
}

impl PagerDutyChannel {
    /// Create a new PagerDuty channel
    pub fn new(integration_key: &str) -> Self {
        Self {
            name: "pagerduty".to_string(),
            integration_key: integration_key.to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Get PagerDuty severity
    fn pagerduty_severity(&self, severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "critical",
            Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "info",
        }
    }
}

#[async_trait::async_trait]
impl AlertChannel for PagerDutyChannel {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, alert: &Alert) -> Result<()> {
        let payload = serde_json::json!({
            "routing_key": self.integration_key,
            "event_action": "trigger",
            "dedup_key": alert.id,
            "payload": {
                "summary": alert.message,
                "source": alert.source,
                "severity": self.pagerduty_severity(alert.severity),
                "timestamp": chrono::DateTime::from_timestamp(alert.timestamp, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default(),
                "custom_details": alert.metadata
            }
        });

        let response = self
            .client
            .post("https://events.pagerduty.com/v2/enqueue")
            .json(&payload)
            .send()
            .await
            .map_err(|e| BridgeError::Internal(format!("PagerDuty request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(BridgeError::Internal(format!(
                "PagerDuty returned error: {}",
                response.status()
            )));
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        !self.integration_key.is_empty()
    }
}

/// Telegram alert channel
pub struct TelegramChannel {
    name: String,
    bot_token: String,
    chat_id: String,
    client: reqwest::Client,
}

impl TelegramChannel {
    /// Create a new Telegram channel
    pub fn new(bot_token: &str, chat_id: &str) -> Self {
        Self {
            name: "telegram".to_string(),
            bot_token: bot_token.to_string(),
            chat_id: chat_id.to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Format message for Telegram
    fn format_message(&self, alert: &Alert) -> String {
        let emoji = match alert.severity {
            Severity::Critical => "🚨",
            Severity::High => "⚠️",
            Severity::Medium => "⚡",
            Severity::Low => "ℹ️",
        };

        format!(
            "{} *{}*\n\n{}\n\n*Severity:* {:?}\n*Source:* {}",
            emoji, alert.title, alert.message, alert.severity, alert.source
        )
    }
}

#[async_trait::async_trait]
impl AlertChannel for TelegramChannel {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, alert: &Alert) -> Result<()> {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);

        let payload = serde_json::json!({
            "chat_id": self.chat_id,
            "text": self.format_message(alert),
            "parse_mode": "Markdown"
        });

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| BridgeError::Internal(format!("Telegram request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(BridgeError::Internal(format!(
                "Telegram returned error: {}",
                response.status()
            )));
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        !self.bot_token.is_empty() && !self.chat_id.is_empty()
    }
}

/// Console/log alert channel
pub struct ConsoleChannel {
    name: String,
}

impl ConsoleChannel {
    /// Create a new console channel
    pub fn new() -> Self {
        Self {
            name: "console".to_string(),
        }
    }
}

impl Default for ConsoleChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AlertChannel for ConsoleChannel {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, alert: &Alert) -> Result<()> {
        match alert.severity {
            Severity::Critical | Severity::High => {
                tracing::error!("[{}] {}: {}", alert.source, alert.title, alert.message);
            }
            Severity::Medium => {
                tracing::warn!("[{}] {}: {}", alert.source, alert.title, alert.message);
            }
            Severity::Low => {
                tracing::info!("[{}] {}: {}", alert.source, alert.title, alert.message);
            }
        }
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// Alert manager
pub struct AlertManager {
    /// Configuration
    config: AlertConfig,
    /// Alert channels
    channels: Vec<Arc<dyn AlertChannel>>,
    /// Rate limiter (severity -> last alert time)
    rate_limiter: DashMap<String, Instant>,
    /// Rate limit interval
    rate_limit_interval: Duration,
    /// Alert history
    history: DashMap<String, Alert>,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(config: AlertConfig) -> Self {
        let mut channels: Vec<Arc<dyn AlertChannel>> = vec![Arc::new(ConsoleChannel::new())];

        if let Some(ref webhook) = config.slack_webhook {
            channels.push(Arc::new(SlackChannel::new(webhook)));
        }

        if let Some(ref key) = config.pagerduty_key {
            channels.push(Arc::new(PagerDutyChannel::new(key)));
        }

        if let (Some(ref token), Some(ref chat_id)) =
            (&config.telegram_bot_token, &config.telegram_chat_id)
        {
            channels.push(Arc::new(TelegramChannel::new(token, chat_id)));
        }

        let rate_limit_secs = 60 / config.rate_limit_per_minute.max(1) as u64;

        Self {
            config,
            channels,
            rate_limiter: DashMap::new(),
            rate_limit_interval: Duration::from_secs(rate_limit_secs),
            history: DashMap::new(),
        }
    }

    /// Send an alert to all channels
    pub async fn send_alert(&self, alert: Alert) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Rate limiting by severity
        let rate_key = format!("{:?}", alert.severity);
        if let Some(last) = self.rate_limiter.get(&rate_key) {
            if last.elapsed() < self.rate_limit_interval {
                tracing::debug!("Alert rate limited: {}", alert.title);
                return Ok(());
            }
        }
        self.rate_limiter.insert(rate_key, Instant::now());

        // Store in history
        self.history.insert(alert.id.clone(), alert.clone());

        // Send to all available channels
        for channel in &self.channels {
            if channel.is_available() {
                if let Err(e) = channel.send(&alert).await {
                    tracing::error!("Failed to send alert to {}: {}", channel.name(), e);
                }
            }
        }

        Ok(())
    }

    /// Create and send alert from detection result
    pub async fn alert_from_detection(
        &self,
        detection: &DetectionResult,
        source: &str,
    ) -> Result<()> {
        if !detection.is_anomaly {
            return Ok(());
        }

        let alert = Alert::from_detection(detection, source);
        self.send_alert(alert).await
    }

    /// Acknowledge an alert
    pub fn acknowledge(&self, alert_id: &str) -> bool {
        if let Some(mut alert) = self.history.get_mut(alert_id) {
            alert.acknowledged = true;
            true
        } else {
            false
        }
    }

    /// Get alert by ID
    pub fn get_alert(&self, alert_id: &str) -> Option<Alert> {
        self.history.get(alert_id).map(|a| a.clone())
    }

    /// Get recent alerts
    pub fn recent_alerts(&self, limit: usize) -> Vec<Alert> {
        let mut alerts: Vec<_> = self.history.iter().map(|e| e.clone()).collect();
        alerts.sort_by_key(|a| Reverse(a.timestamp));
        alerts.truncate(limit);
        alerts
    }

    /// Get unacknowledged alerts
    pub fn unacknowledged_alerts(&self) -> Vec<Alert> {
        self.history
            .iter()
            .filter(|e| !e.acknowledged)
            .map(|e| e.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AlertConfig {
        AlertConfig {
            enabled: true,
            slack_webhook: None,
            pagerduty_key: None,
            email_recipients: vec![],
            telegram_bot_token: None,
            telegram_chat_id: None,
            rate_limit_per_minute: 60,
        }
    }

    #[test]
    fn test_alert_creation() {
        let alert = Alert::new("Test Alert", "This is a test", Severity::Medium, "test");

        assert!(!alert.id.is_empty());
        assert_eq!(alert.severity, Severity::Medium);
        assert!(!alert.acknowledged);
    }

    #[tokio::test]
    async fn test_console_channel() {
        let channel = ConsoleChannel::new();
        let alert = Alert::new("Test", "Message", Severity::Low, "test");

        assert!(channel.is_available());
        assert!(channel.send(&alert).await.is_ok());
    }

    #[tokio::test]
    async fn test_alert_manager() {
        let manager = AlertManager::new(test_config());

        let alert = Alert::new("Test Alert", "Test message", Severity::Medium, "test");

        assert!(manager.send_alert(alert).await.is_ok());
        assert_eq!(manager.recent_alerts(10).len(), 1);
    }

    #[test]
    fn test_acknowledge() {
        let manager = AlertManager::new(test_config());

        let alert = Alert::new("Test", "Message", Severity::Low, "test");
        let id = alert.id.clone();

        manager.history.insert(id.clone(), alert);

        assert!(manager.acknowledge(&id));

        let updated = manager.get_alert(&id).unwrap();
        assert!(updated.acknowledged);
    }
}
