//! Bridge monitor configuration

use bigdecimal::BigDecimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Monitor configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MonitorConfig {
    /// Bridge configuration
    pub bridge: BridgeConfig,
    /// Chain configurations
    pub chains: HashMap<String, ChainConfig>,
    /// Correlation settings
    #[serde(default)]
    pub correlation: CorrelationConfig,
    /// Detection settings
    #[serde(default)]
    pub detection: DetectionConfig,
    /// Policy settings
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Alert settings
    #[serde(default)]
    pub alerts: AlertConfig,
}

/// Bridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Bridge name/identifier
    pub name: String,
    /// Source chain ID
    pub source_chain: String,
    /// Destination chain ID
    pub destination_chain: String,
    /// Bridge contract addresses
    pub contract_addresses: HashMap<String, String>,
    /// Supported tokens
    pub supported_tokens: Vec<TokenConfig>,
    /// Whether bridge is currently enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            source_chain: "ethereum".to_string(),
            destination_chain: "arbitrum".to_string(),
            contract_addresses: HashMap::new(),
            supported_tokens: vec![],
            enabled: true,
        }
    }
}

/// Token configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    /// Token symbol
    pub symbol: String,
    /// Token decimals
    pub decimals: u8,
    /// Contract addresses per chain
    pub addresses: HashMap<String, String>,
    /// Minimum transfer amount
    pub min_amount: Option<BigDecimal>,
    /// Maximum transfer amount
    pub max_amount: Option<BigDecimal>,
}

/// Chain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Chain ID
    pub chain_id: String,
    /// Chain name
    pub name: String,
    /// RPC endpoints
    pub rpc_endpoints: Vec<String>,
    /// Block confirmation requirement
    #[serde(default = "default_confirmations")]
    pub confirmations: u32,
    /// Polling interval in seconds
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Chain type
    pub chain_type: ChainType,
}

fn default_confirmations() -> u32 {
    12
}

fn default_poll_interval() -> u64 {
    15
}

/// Chain type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    /// EVM-compatible chain
    Evm,
    /// Bitcoin
    Bitcoin,
    /// Solana
    Solana,
    /// Cosmos SDK chain
    Cosmos,
}

/// Correlation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    /// Maximum time to wait for correlation
    #[serde(default = "default_correlation_timeout")]
    pub timeout_secs: u64,
    /// Event buffer size
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    /// Cleanup interval
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
}

fn default_correlation_timeout() -> u64 {
    3600 // 1 hour
}

fn default_buffer_size() -> usize {
    10000
}

fn default_cleanup_interval() -> u64 {
    300 // 5 minutes
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_correlation_timeout(),
            buffer_size: default_buffer_size(),
            cleanup_interval_secs: default_cleanup_interval(),
        }
    }
}

/// Detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Large withdrawal threshold (percentage of TVL)
    #[serde(default = "default_large_threshold")]
    pub large_withdrawal_pct: f64,
    /// Hourly volume limit
    pub hourly_volume_limit: Option<BigDecimal>,
    /// Daily volume limit
    pub daily_volume_limit: Option<BigDecimal>,
    /// Imbalance threshold (percentage)
    #[serde(default = "default_imbalance_threshold")]
    pub imbalance_threshold_pct: f64,
    /// Velocity anomaly threshold (stddev)
    #[serde(default = "default_velocity_threshold")]
    pub velocity_threshold: f64,
    /// Time windows for analysis
    #[serde(default)]
    pub time_windows: TimeWindows,
}

fn default_large_threshold() -> f64 {
    1.0 // 1% of TVL
}

fn default_imbalance_threshold() -> f64 {
    10.0 // 10%
}

fn default_velocity_threshold() -> f64 {
    3.0 // 3 standard deviations
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            large_withdrawal_pct: default_large_threshold(),
            hourly_volume_limit: None,
            daily_volume_limit: None,
            imbalance_threshold_pct: default_imbalance_threshold(),
            velocity_threshold: default_velocity_threshold(),
            time_windows: TimeWindows::default(),
        }
    }
}

/// Time windows for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindows {
    /// Short window (seconds)
    #[serde(default = "default_short_window")]
    pub short_secs: u64,
    /// Medium window (seconds)
    #[serde(default = "default_medium_window")]
    pub medium_secs: u64,
    /// Long window (seconds)
    #[serde(default = "default_long_window")]
    pub long_secs: u64,
}

fn default_short_window() -> u64 {
    300 // 5 minutes
}

fn default_medium_window() -> u64 {
    3600 // 1 hour
}

fn default_long_window() -> u64 {
    86400 // 24 hours
}

impl Default for TimeWindows {
    fn default() -> Self {
        Self {
            short_secs: default_short_window(),
            medium_secs: default_medium_window(),
            long_secs: default_long_window(),
        }
    }
}

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Auto-pause on anomaly
    #[serde(default = "default_true")]
    pub auto_pause_on_anomaly: bool,
    /// Approval threshold for large withdrawals
    pub approval_threshold: Option<BigDecimal>,
    /// Required number of approvers
    #[serde(default = "default_approvers")]
    pub required_approvers: u32,
    /// Time lock for large withdrawals (seconds)
    #[serde(default)]
    pub time_lock_secs: u64,
    /// Whitelist addresses (bypass some checks)
    #[serde(default)]
    pub whitelist: Vec<String>,
    /// Blacklist addresses (block all transactions)
    #[serde(default)]
    pub blacklist: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_approvers() -> u32 {
    2
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            auto_pause_on_anomaly: true,
            approval_threshold: None,
            required_approvers: default_approvers(),
            time_lock_secs: 0,
            whitelist: vec![],
            blacklist: vec![],
        }
    }
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable alerts
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Slack webhook URL
    pub slack_webhook: Option<String>,
    /// PagerDuty integration key
    pub pagerduty_key: Option<String>,
    /// Email recipients
    #[serde(default)]
    pub email_recipients: Vec<String>,
    /// Telegram bot token
    pub telegram_bot_token: Option<String>,
    /// Telegram chat ID
    pub telegram_chat_id: Option<String>,
    /// Alert rate limit (per severity, per minute)
    #[serde(default = "default_alert_rate_limit")]
    pub rate_limit_per_minute: u32,
}

fn default_alert_rate_limit() -> u32 {
    10
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            slack_webhook: None,
            pagerduty_key: None,
            email_recipients: vec![],
            telegram_bot_token: None,
            telegram_chat_id: None,
            rate_limit_per_minute: default_alert_rate_limit(),
        }
    }
}
