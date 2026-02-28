//! Webhook configuration

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Endpoint URL
    pub url: String,
    /// Secret key for HMAC signing
    #[serde(skip_serializing)]
    pub secret: String,
    /// Request timeout
    #[serde(with = "humantime_serde", default = "default_timeout")]
    pub timeout: Duration,
    /// Maximum retries
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Initial retry delay
    #[serde(with = "humantime_serde", default = "default_retry_delay")]
    pub retry_delay: Duration,
    /// Whether webhook is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Custom headers
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_delay() -> Duration {
    Duration::from_secs(1)
}

fn default_enabled() -> bool {
    true
}

impl WebhookConfig {
    /// Create a new webhook config
    pub fn new(url: &str, secret: &str) -> Self {
        Self {
            url: url.to_string(),
            secret: secret.to_string(),
            timeout: default_timeout(),
            max_retries: default_max_retries(),
            retry_delay: default_retry_delay(),
            enabled: true,
            headers: std::collections::HashMap::new(),
        }
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set max retries
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Set retry delay
    pub fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = delay;
        self
    }

    /// Add a custom header
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Enable/disable
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Validate the config
    pub fn validate(&self) -> Result<(), String> {
        if self.url.is_empty() {
            return Err("URL cannot be empty".to_string());
        }

        // Validate URL for SSRF prevention
        validate_url(&self.url)?;

        if self.secret.len() < 16 {
            return Err("Secret must be at least 16 characters".to_string());
        }

        Ok(())
    }
}

/// Validate a webhook URL to prevent SSRF attacks.
///
/// Checks that:
/// - The scheme is "https" (rejects "http")
/// - The hostname does not resolve to a private/internal IP range
pub fn validate_url(url_str: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url_str)
        .map_err(|e| format!("Invalid URL: {}", e))?;

    // Require HTTPS
    if parsed.scheme() != "https" {
        return Err("URL scheme must be https".to_string());
    }

    // Check hostname against private IP ranges
    if let Some(host) = parsed.host_str() {
        // Try to parse as IP address directly
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if is_private_ip(&ip) {
                return Err(format!("URL hostname resolves to private IP range: {}", host));
            }
        }

        // Also reject known private hostnames
        if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
            return Err(format!("URL hostname is not allowed: {}", host));
        }
    } else {
        return Err("URL must have a hostname".to_string());
    }

    Ok(())
}

/// Check if an IP address is in a private/reserved range.
fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 127.0.0.0/8 (loopback)
            || octets[0] == 127
            // 169.254.0.0/16 (link-local)
            || (octets[0] == 169 && octets[1] == 254)
            // 0.0.0.0
            || (octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0)
        }
        std::net::IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_unspecified()
        }
    }
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            secret: String::new(),
            timeout: default_timeout(),
            max_retries: default_max_retries(),
            retry_delay: default_retry_delay(),
            enabled: true,
            headers: std::collections::HashMap::new(),
        }
    }
}

/// Serde module for humantime duration
mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}s", duration.as_secs()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        // Simple parsing: assume format like "30s", "5m", "1h"
        if let Some(secs) = s.strip_suffix('s') {
            secs.parse()
                .map(Duration::from_secs)
                .map_err(serde::de::Error::custom)
        } else if let Some(mins) = s.strip_suffix('m') {
            mins.parse::<u64>()
                .map(|m| Duration::from_secs(m * 60))
                .map_err(serde::de::Error::custom)
        } else if let Some(hours) = s.strip_suffix('h') {
            hours
                .parse::<u64>()
                .map(|h| Duration::from_secs(h * 3600))
                .map_err(serde::de::Error::custom)
        } else {
            Err(serde::de::Error::custom("Invalid duration format"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_config() {
        let config = WebhookConfig::new("https://example.com/webhook", "super_secret_key_123")
            .with_timeout(Duration::from_secs(60))
            .with_max_retries(5);

        assert!(config.validate().is_ok());
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_invalid_url() {
        let config = WebhookConfig::new("not-a-url", "super_secret_key_123");
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_short_secret() {
        let config = WebhookConfig::new("https://example.com", "short");
        assert!(config.validate().is_err());
    }
}
