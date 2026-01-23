//! Spending limits and velocity controls

use super::types::{AssetType, TimeWindow};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Spending limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingLimit {
    /// Asset type this limit applies to
    pub asset_type: AssetType,
    /// Time window for aggregation
    pub window: TimeWindow,
    /// Maximum value in smallest unit (wei, satoshi, etc.)
    pub max_value: String, // Using String to handle large numbers
    /// Maximum number of transactions (optional)
    pub max_transactions: Option<u32>,
    /// Whether this is a hard limit (reject) or soft limit (require approval)
    pub hard_limit: bool,
}

impl SpendingLimit {
    /// Create a new spending limit
    pub fn new(asset_type: AssetType, window: TimeWindow, max_value: &str) -> Self {
        Self {
            asset_type,
            window,
            max_value: max_value.to_string(),
            max_transactions: None,
            hard_limit: true,
        }
    }

    /// Set maximum number of transactions
    pub fn with_max_transactions(mut self, max: u32) -> Self {
        self.max_transactions = Some(max);
        self
    }

    /// Make this a soft limit (requires approval instead of rejection)
    pub fn soft_limit(mut self) -> Self {
        self.hard_limit = false;
        self
    }

    /// Parse max_value as u128 for comparison
    pub fn max_value_u128(&self) -> Option<u128> {
        self.max_value.parse().ok()
    }

    /// Check if a value exceeds this limit
    pub fn exceeds(&self, value: &str) -> bool {
        if let (Some(max), Ok(val)) = (self.max_value_u128(), value.parse::<u128>()) {
            val > max
        } else {
            // If we can't parse, be conservative and don't exceed
            false
        }
    }
}

impl fmt::Display for SpendingLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} max {} {}",
            if self.hard_limit { "Hard" } else { "Soft" },
            self.window,
            self.max_value,
            self.asset_type
        )
    }
}

/// Velocity limit (rate limiting for transactions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VelocityLimit {
    /// Time window
    pub window: TimeWindow,
    /// Maximum number of transactions
    pub max_count: u32,
    /// Maximum total value (optional)
    pub max_total_value: Option<String>,
    /// Asset type (optional - None means all assets)
    pub asset_type: Option<AssetType>,
    /// Cooldown period between transactions (in seconds)
    pub cooldown_seconds: Option<u32>,
}

impl VelocityLimit {
    /// Create a new velocity limit
    pub fn new(window: TimeWindow, max_count: u32) -> Self {
        Self {
            window,
            max_count,
            max_total_value: None,
            asset_type: None,
            cooldown_seconds: None,
        }
    }

    /// Set maximum total value
    pub fn with_max_total_value(mut self, value: &str) -> Self {
        self.max_total_value = Some(value.to_string());
        self
    }

    /// Set asset type filter
    pub fn for_asset(mut self, asset_type: AssetType) -> Self {
        self.asset_type = Some(asset_type);
        self
    }

    /// Set cooldown period
    pub fn with_cooldown(mut self, seconds: u32) -> Self {
        self.cooldown_seconds = Some(seconds);
        self
    }

    /// Check if count exceeds limit
    pub fn exceeds_count(&self, count: u32) -> bool {
        count >= self.max_count
    }

    /// Check if total value exceeds limit
    pub fn exceeds_value(&self, total: &str) -> bool {
        if let Some(ref max) = self.max_total_value {
            if let (Ok(max_val), Ok(total_val)) = (max.parse::<u128>(), total.parse::<u128>()) {
                return total_val > max_val;
            }
        }
        false
    }
}

impl fmt::Display for VelocityLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} tx per {}", self.max_count, self.window)?;
        if let Some(ref value) = self.max_total_value {
            write!(f, " (max {})", value)?;
        }
        if let Some(cooldown) = self.cooldown_seconds {
            write!(f, " [{}s cooldown]", cooldown)?;
        }
        Ok(())
    }
}

/// Spending policy combining limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingPolicy {
    /// Spending limits
    pub limits: Vec<SpendingLimit>,
    /// Velocity limits
    pub velocity_limits: Vec<VelocityLimit>,
    /// Whitelist of addresses that bypass limits
    pub bypass_addresses: Vec<String>,
}

impl SpendingPolicy {
    /// Create a new spending policy
    pub fn new() -> Self {
        Self {
            limits: Vec::new(),
            velocity_limits: Vec::new(),
            bypass_addresses: Vec::new(),
        }
    }

    /// Add a spending limit
    pub fn add_limit(mut self, limit: SpendingLimit) -> Self {
        self.limits.push(limit);
        self
    }

    /// Add a velocity limit
    pub fn add_velocity_limit(mut self, limit: VelocityLimit) -> Self {
        self.velocity_limits.push(limit);
        self
    }

    /// Add a bypass address
    pub fn add_bypass(mut self, address: &str) -> Self {
        self.bypass_addresses.push(address.to_lowercase());
        self
    }

    /// Check if an address bypasses limits
    pub fn is_bypass_address(&self, address: &str) -> bool {
        self.bypass_addresses.contains(&address.to_lowercase())
    }

    /// Get applicable limits for an asset
    pub fn limits_for_asset(&self, asset: &AssetType) -> Vec<&SpendingLimit> {
        self.limits
            .iter()
            .filter(|l| l.asset_type.matches(asset))
            .collect()
    }
}

impl Default for SpendingPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spending_limit() {
        let limit = SpendingLimit::new(
            AssetType::native("ETH"),
            TimeWindow::Day,
            "1000000000000000000", // 1 ETH in wei
        );

        assert!(limit.exceeds("2000000000000000000")); // 2 ETH
        assert!(!limit.exceeds("500000000000000000")); // 0.5 ETH
    }

    #[test]
    fn test_velocity_limit() {
        let limit = VelocityLimit::new(TimeWindow::Hour, 10)
            .with_max_total_value("10000000000000000000") // 10 ETH
            .with_cooldown(60);

        assert!(limit.exceeds_count(10));
        assert!(!limit.exceeds_count(5));
        assert!(limit.exceeds_value("20000000000000000000"));
        assert!(!limit.exceeds_value("5000000000000000000"));
    }

    #[test]
    fn test_spending_policy() {
        let policy = SpendingPolicy::new()
            .add_limit(SpendingLimit::new(
                AssetType::native("ETH"),
                TimeWindow::Day,
                "10000000000000000000",
            ))
            .add_velocity_limit(VelocityLimit::new(TimeWindow::Hour, 20))
            .add_bypass("0x1234567890123456789012345678901234567890");

        assert!(policy.is_bypass_address("0x1234567890123456789012345678901234567890"));
        assert!(!policy.is_bypass_address("0x0000000000000000000000000000000000000000"));

        let limits = policy.limits_for_asset(&AssetType::native("ETH"));
        assert_eq!(limits.len(), 1);
    }
}
