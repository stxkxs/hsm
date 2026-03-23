//! Spending tracker for enforcing limits

use super::types::{AssetType, TimeWindow};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Transaction record for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    /// Transaction ID/hash
    pub tx_id: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Asset type
    pub asset_type: AssetType,
    /// Value (in smallest unit)
    pub value: String,
    /// Recipient address
    pub recipient: String,
    /// Key ID used
    pub key_id: String,
    /// Namespace
    pub namespace: String,
    /// User/client who initiated
    pub user: String,
}

impl TransactionRecord {
    /// Create a new transaction record
    pub fn new(
        tx_id: &str,
        asset_type: AssetType,
        value: &str,
        recipient: &str,
        key_id: &str,
        namespace: &str,
        user: &str,
    ) -> Self {
        Self {
            tx_id: tx_id.to_string(),
            timestamp: Utc::now(),
            asset_type,
            value: value.to_string(),
            recipient: recipient.to_string(),
            key_id: key_id.to_string(),
            namespace: namespace.to_string(),
            user: user.to_string(),
        }
    }

    /// Parse value as u128
    pub fn value_u128(&self) -> Option<u128> {
        self.value.parse().ok()
    }
}

/// Key for grouping transactions
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrackerKey {
    /// Asset type
    pub asset_type: String,
    /// Scope (key_id, namespace, user, or global)
    pub scope: String,
}

impl TrackerKey {
    /// Create a key for a specific key ID
    pub fn for_key(asset: &AssetType, key_id: &str) -> Self {
        Self {
            asset_type: asset.to_string(),
            scope: format!("key:{}", key_id),
        }
    }

    /// Create a key for a namespace
    pub fn for_namespace(asset: &AssetType, namespace: &str) -> Self {
        Self {
            asset_type: asset.to_string(),
            scope: format!("ns:{}", namespace),
        }
    }

    /// Create a key for a user
    pub fn for_user(asset: &AssetType, user: &str) -> Self {
        Self {
            asset_type: asset.to_string(),
            scope: format!("user:{}", user),
        }
    }

    /// Create a global key
    pub fn global(asset: &AssetType) -> Self {
        Self {
            asset_type: asset.to_string(),
            scope: "global".to_string(),
        }
    }
}

/// Aggregated spending data
#[derive(Debug, Clone, Default)]
pub struct SpendingAggregate {
    /// Total value
    pub total_value: u128,
    /// Transaction count
    pub tx_count: u32,
    /// Last transaction timestamp
    pub last_tx: Option<DateTime<Utc>>,
}

impl SpendingAggregate {
    /// Add a transaction
    pub fn add(&mut self, value: u128, timestamp: DateTime<Utc>) {
        self.total_value = self.total_value.saturating_add(value);
        self.tx_count += 1;
        self.last_tx = Some(timestamp);
    }
}

/// Spending tracker
pub struct SpendingTracker {
    /// Transaction history
    transactions: Arc<DashMap<TrackerKey, Vec<TransactionRecord>>>,
    /// Maximum history to keep (per key)
    max_history: usize,
}

impl SpendingTracker {
    /// Create a new spending tracker
    pub fn new() -> Self {
        Self {
            transactions: Arc::new(DashMap::new()),
            max_history: 10000,
        }
    }

    /// Create with custom max history
    pub fn with_max_history(max: usize) -> Self {
        Self {
            transactions: Arc::new(DashMap::new()),
            max_history: max,
        }
    }

    /// Record a transaction
    pub fn record(&self, record: TransactionRecord) {
        // Record by key
        self.record_for_key(
            TrackerKey::for_key(&record.asset_type, &record.key_id),
            record.clone(),
        );

        // Record by namespace
        self.record_for_key(
            TrackerKey::for_namespace(&record.asset_type, &record.namespace),
            record.clone(),
        );

        // Record by user
        self.record_for_key(
            TrackerKey::for_user(&record.asset_type, &record.user),
            record.clone(),
        );

        // Record globally
        self.record_for_key(TrackerKey::global(&record.asset_type), record);
    }

    fn record_for_key(&self, key: TrackerKey, record: TransactionRecord) {
        self.transactions.entry(key).or_default().push(record);

        // Trim if over limit
        self.transactions.alter_all(|_, mut v| {
            if v.len() > self.max_history {
                v.drain(0..v.len() - self.max_history);
            }
            v
        });
    }

    /// Get spending aggregate for a key and time window
    pub fn get_aggregate(&self, key: &TrackerKey, window: TimeWindow) -> SpendingAggregate {
        let window_start = window.window_start();
        let mut aggregate = SpendingAggregate::default();

        if let Some(records) = self.transactions.get(key) {
            for record in records.iter() {
                if record.timestamp >= window_start {
                    if let Some(value) = record.value_u128() {
                        aggregate.add(value, record.timestamp);
                    }
                }
            }
        }

        aggregate
    }

    /// Get spending for a key in a time window
    pub fn get_spending_for_key(
        &self,
        asset: &AssetType,
        key_id: &str,
        window: TimeWindow,
    ) -> SpendingAggregate {
        self.get_aggregate(&TrackerKey::for_key(asset, key_id), window)
    }

    /// Get spending for a namespace in a time window
    pub fn get_spending_for_namespace(
        &self,
        asset: &AssetType,
        namespace: &str,
        window: TimeWindow,
    ) -> SpendingAggregate {
        self.get_aggregate(&TrackerKey::for_namespace(asset, namespace), window)
    }

    /// Get spending for a user in a time window
    pub fn get_spending_for_user(
        &self,
        asset: &AssetType,
        user: &str,
        window: TimeWindow,
    ) -> SpendingAggregate {
        self.get_aggregate(&TrackerKey::for_user(asset, user), window)
    }

    /// Get global spending in a time window
    pub fn get_global_spending(&self, asset: &AssetType, window: TimeWindow) -> SpendingAggregate {
        self.get_aggregate(&TrackerKey::global(asset), window)
    }

    /// Check if a new transaction would exceed a limit
    pub fn would_exceed_limit(
        &self,
        key: &TrackerKey,
        window: TimeWindow,
        new_value: u128,
        max_value: u128,
    ) -> bool {
        let aggregate = self.get_aggregate(key, window);
        aggregate.total_value.saturating_add(new_value) > max_value
    }

    /// Check if adding a transaction would exceed count limit
    pub fn would_exceed_count(&self, key: &TrackerKey, window: TimeWindow, max_count: u32) -> bool {
        let aggregate = self.get_aggregate(key, window);
        aggregate.tx_count >= max_count
    }

    /// Get time since last transaction
    pub fn time_since_last_tx(
        &self,
        key: &TrackerKey,
        window: TimeWindow,
    ) -> Option<chrono::Duration> {
        let aggregate = self.get_aggregate(key, window);
        aggregate.last_tx.map(|last| Utc::now() - last)
    }

    /// Cleanup old records
    pub fn cleanup(&self, retention: chrono::Duration) {
        let cutoff = Utc::now() - retention;
        self.transactions.alter_all(|_, mut records| {
            records.retain(|r| r.timestamp > cutoff);
            records
        });
    }

    /// Get recent transactions
    pub fn get_recent(&self, key: &TrackerKey, limit: usize) -> Vec<TransactionRecord> {
        self.transactions
            .get(key)
            .map(|records| records.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }
}

impl Default for SpendingTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_aggregate() {
        let tracker = SpendingTracker::new();
        let asset = AssetType::native("ETH");

        // Record some transactions
        for i in 0..5 {
            tracker.record(TransactionRecord::new(
                &format!("tx-{}", i),
                asset.clone(),
                "1000000000000000000", // 1 ETH
                "0x1234",
                "key-1",
                "default",
                "alice",
            ));
        }

        // Check aggregate
        let aggregate = tracker.get_spending_for_key(&asset, "key-1", TimeWindow::Hour);
        assert_eq!(aggregate.tx_count, 5);
        assert_eq!(aggregate.total_value, 5_000_000_000_000_000_000u128);
    }

    #[test]
    fn test_would_exceed_limit() {
        let tracker = SpendingTracker::new();
        let asset = AssetType::native("ETH");

        // Record 9 ETH
        tracker.record(TransactionRecord::new(
            "tx-1",
            asset.clone(),
            "9000000000000000000",
            "0x1234",
            "key-1",
            "default",
            "alice",
        ));

        let key = TrackerKey::for_key(&asset, "key-1");
        let max = 10_000_000_000_000_000_000u128; // 10 ETH

        // 1 ETH more should not exceed
        assert!(!tracker.would_exceed_limit(&key, TimeWindow::Day, 1_000_000_000_000_000_000, max));

        // 2 ETH more should exceed
        assert!(tracker.would_exceed_limit(&key, TimeWindow::Day, 2_000_000_000_000_000_000, max));
    }

    #[test]
    fn test_count_limit() {
        let tracker = SpendingTracker::new();
        let asset = AssetType::native("ETH");

        for i in 0..10 {
            tracker.record(TransactionRecord::new(
                &format!("tx-{}", i),
                asset.clone(),
                "1000",
                "0x1234",
                "key-1",
                "default",
                "alice",
            ));
        }

        let key = TrackerKey::for_key(&asset, "key-1");
        assert!(tracker.would_exceed_count(&key, TimeWindow::Hour, 10));
        assert!(!tracker.would_exceed_count(&key, TimeWindow::Hour, 20));
    }

    #[test]
    fn test_multi_scope_tracking() {
        let tracker = SpendingTracker::new();
        let asset = AssetType::native("ETH");

        // Record transaction for key-1, namespace default, user alice
        tracker.record(TransactionRecord::new(
            "tx-1",
            asset.clone(),
            "1000",
            "0x1234",
            "key-1",
            "default",
            "alice",
        ));

        // Should appear in all scopes
        assert_eq!(
            tracker
                .get_spending_for_key(&asset, "key-1", TimeWindow::Hour)
                .tx_count,
            1
        );
        assert_eq!(
            tracker
                .get_spending_for_namespace(&asset, "default", TimeWindow::Hour)
                .tx_count,
            1
        );
        assert_eq!(
            tracker
                .get_spending_for_user(&asset, "alice", TimeWindow::Hour)
                .tx_count,
            1
        );
        assert_eq!(
            tracker
                .get_global_spending(&asset, TimeWindow::Hour)
                .tx_count,
            1
        );
    }
}
