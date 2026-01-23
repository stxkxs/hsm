//! Core policy types

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Unique policy identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(Uuid);

impl PolicyId {
    /// Create a new random policy ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }

    /// Get as string
    pub fn as_string(&self) -> String {
        self.0.to_string()
    }
}

impl Default for PolicyId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Policy scope - what the policy applies to
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyScope {
    /// Applies globally
    Global,
    /// Applies to a specific namespace
    Namespace(String),
    /// Applies to a specific key
    Key(String),
    /// Applies to a specific user/client
    User(String),
    /// Applies to an asset type
    Asset(AssetType),
}

/// Asset type for spending limits
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetType {
    /// Native cryptocurrency (ETH, BTC, SOL, etc.)
    Native(String),
    /// ERC-20 token
    Erc20 { chain_id: u64, contract: String },
    /// ERC-721 NFT
    Erc721 { chain_id: u64, contract: String },
    /// Any asset
    Any,
}

impl AssetType {
    /// Create a native asset
    pub fn native(symbol: &str) -> Self {
        Self::Native(symbol.to_uppercase())
    }

    /// Create an ERC-20 token
    pub fn erc20(chain_id: u64, contract: &str) -> Self {
        Self::Erc20 {
            chain_id,
            contract: contract.to_lowercase(),
        }
    }

    /// Check if this asset type matches another
    pub fn matches(&self, other: &AssetType) -> bool {
        match (self, other) {
            (AssetType::Any, _) | (_, AssetType::Any) => true,
            (AssetType::Native(a), AssetType::Native(b)) => a == b,
            (
                AssetType::Erc20 {
                    chain_id: c1,
                    contract: a1,
                },
                AssetType::Erc20 {
                    chain_id: c2,
                    contract: a2,
                },
            ) => c1 == c2 && a1 == a2,
            (
                AssetType::Erc721 {
                    chain_id: c1,
                    contract: a1,
                },
                AssetType::Erc721 {
                    chain_id: c2,
                    contract: a2,
                },
            ) => c1 == c2 && a1 == a2,
            _ => false,
        }
    }
}

impl fmt::Display for AssetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetType::Native(symbol) => write!(f, "{}", symbol),
            AssetType::Erc20 { chain_id, contract } => {
                write!(
                    f,
                    "ERC20:{}:{}",
                    chain_id,
                    &contract[..8.min(contract.len())]
                )
            }
            AssetType::Erc721 { chain_id, contract } => {
                write!(
                    f,
                    "ERC721:{}:{}",
                    chain_id,
                    &contract[..8.min(contract.len())]
                )
            }
            AssetType::Any => write!(f, "*"),
        }
    }
}

/// Time window for limits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeWindow {
    /// Per-transaction (no aggregation)
    PerTransaction,
    /// Per hour
    Hour,
    /// Per day (24 hours)
    Day,
    /// Per week (7 days)
    Week,
    /// Per month (30 days)
    Month,
}

impl TimeWindow {
    /// Get the duration for this window
    pub fn duration(&self) -> Option<Duration> {
        match self {
            TimeWindow::PerTransaction => None,
            TimeWindow::Hour => Some(Duration::hours(1)),
            TimeWindow::Day => Some(Duration::days(1)),
            TimeWindow::Week => Some(Duration::weeks(1)),
            TimeWindow::Month => Some(Duration::days(30)),
        }
    }

    /// Check if a timestamp is within this window from now
    pub fn is_within(&self, timestamp: DateTime<Utc>) -> bool {
        match self.duration() {
            None => true, // Per-transaction always applies
            Some(duration) => Utc::now() - timestamp < duration,
        }
    }

    /// Get the window start time
    pub fn window_start(&self) -> DateTime<Utc> {
        match self.duration() {
            None => Utc::now(),
            Some(duration) => Utc::now() - duration,
        }
    }
}

impl fmt::Display for TimeWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeWindow::PerTransaction => write!(f, "per-tx"),
            TimeWindow::Hour => write!(f, "hourly"),
            TimeWindow::Day => write!(f, "daily"),
            TimeWindow::Week => write!(f, "weekly"),
            TimeWindow::Month => write!(f, "monthly"),
        }
    }
}

/// Main policy structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Unique identifier
    pub id: PolicyId,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Scope of the policy
    pub scope: PolicyScope,
    /// Whether the policy is enabled
    pub enabled: bool,
    /// Priority (higher = evaluated first)
    pub priority: i32,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Policy version (for optimistic locking)
    pub version: u32,
    /// Policy rules (stored as JSON)
    pub rules: serde_json::Value,
}

impl Policy {
    /// Create a new policy
    pub fn new(name: &str, scope: PolicyScope, rules: serde_json::Value) -> Self {
        let now = Utc::now();
        Self {
            id: PolicyId::new(),
            name: name.to_string(),
            description: None,
            scope,
            enabled: true,
            priority: 0,
            created_at: now,
            updated_at: now,
            version: 1,
            rules,
        }
    }

    /// Set description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Enable or disable the policy
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.updated_at = Utc::now();
        self.version += 1;
    }

    /// Update the rules
    pub fn update_rules(&mut self, rules: serde_json::Value) {
        self.rules = rules;
        self.updated_at = Utc::now();
        self.version += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_policy_id() {
        let id1 = PolicyId::new();
        let id2 = PolicyId::new();
        assert_ne!(id1, id2);

        let id_str = id1.as_string();
        let parsed = PolicyId::from_str(&id_str).unwrap();
        assert_eq!(id1, parsed);
    }

    #[test]
    fn test_asset_type_matching() {
        let eth = AssetType::native("ETH");
        let btc = AssetType::native("BTC");
        let any = AssetType::Any;

        assert!(eth.matches(&eth));
        assert!(!eth.matches(&btc));
        assert!(any.matches(&eth));
        assert!(eth.matches(&any));
    }

    #[test]
    fn test_time_window() {
        assert!(TimeWindow::PerTransaction.duration().is_none());
        assert_eq!(TimeWindow::Hour.duration(), Some(Duration::hours(1)));
        assert_eq!(TimeWindow::Day.duration(), Some(Duration::days(1)));
    }

    #[test]
    fn test_policy_creation() {
        let policy = Policy::new(
            "Test Policy",
            PolicyScope::Global,
            json!({"max_value": 1000}),
        );

        assert!(policy.enabled);
        assert_eq!(policy.version, 1);
    }
}
