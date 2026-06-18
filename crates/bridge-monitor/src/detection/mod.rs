//! Anomaly detection for bridge security

use crate::config::DetectionConfig;
use crate::correlation::CorrelatedEvent;
use crate::error::Result;
use bigdecimal::BigDecimal;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Anomaly types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Single large withdrawal
    LargeWithdrawal,
    /// Volume exceeds threshold
    VolumeExceeded,
    /// TVL imbalance between chains
    Imbalance,
    /// Unusual transaction velocity
    VelocityAnomaly,
    /// Blacklisted address
    BlacklistedAddress,
    /// Amount mismatch between deposit and withdrawal
    AmountMismatch,
    /// Unknown token
    UnknownToken,
    /// Rapid sequential withdrawals
    RapidWithdrawals,
    /// Unusual time pattern
    TimeAnomaly,
}

/// Detection severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low severity - monitoring only
    Low,
    /// Medium severity - requires attention
    Medium,
    /// High severity - immediate action needed
    High,
    /// Critical severity - bridge should pause
    Critical,
}

/// Detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Whether an anomaly was detected
    pub is_anomaly: bool,
    /// Anomaly type if detected
    pub anomaly_type: Option<AnomalyType>,
    /// Severity level
    pub severity: Severity,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Human-readable description
    pub description: String,
    /// Recommended action
    pub recommended_action: Option<String>,
    /// Additional details
    #[serde(default)]
    pub details: serde_json::Value,
}

impl DetectionResult {
    /// Create a normal (non-anomalous) result
    pub fn normal() -> Self {
        Self {
            is_anomaly: false,
            anomaly_type: None,
            severity: Severity::Low,
            confidence: 0.0,
            description: "No anomaly detected".to_string(),
            recommended_action: None,
            details: serde_json::Value::Null,
        }
    }

    /// Create an anomaly result
    pub fn anomaly(
        anomaly_type: AnomalyType,
        severity: Severity,
        confidence: f64,
        description: String,
    ) -> Self {
        Self {
            is_anomaly: true,
            anomaly_type: Some(anomaly_type),
            severity,
            confidence,
            description,
            recommended_action: None,
            details: serde_json::Value::Null,
        }
    }

    /// Set recommended action
    pub fn with_action(mut self, action: &str) -> Self {
        self.recommended_action = Some(action.to_string());
        self
    }

    /// Set details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

/// Time-series data point
#[derive(Debug, Clone)]
struct DataPoint {
    value: BigDecimal,
    timestamp: Instant,
}

/// Token statistics
#[derive(Debug, Default)]
struct TokenStats {
    /// Recent transaction values
    values: VecDeque<DataPoint>,
    /// Running sum for short window
    short_sum: BigDecimal,
    /// Running sum for medium window
    medium_sum: BigDecimal,
    /// Running sum for long window
    long_sum: BigDecimal,
    /// Total value locked on source
    source_tvl: BigDecimal,
    /// Total value locked on destination
    dest_tvl: BigDecimal,
    /// Count in short window
    short_count: u32,
}

/// Anomaly detector
pub struct AnomalyDetector {
    /// Configuration
    config: DetectionConfig,
    /// Token statistics
    token_stats: DashMap<String, RwLock<TokenStats>>,
    /// Blacklisted addresses
    blacklist: DashMap<String, ()>,
    /// Short window duration
    short_window: Duration,
    /// Medium window duration
    medium_window: Duration,
    /// Long window duration
    long_window: Duration,
}

impl AnomalyDetector {
    /// Create a new anomaly detector
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            short_window: Duration::from_secs(config.time_windows.short_secs),
            medium_window: Duration::from_secs(config.time_windows.medium_secs),
            long_window: Duration::from_secs(config.time_windows.long_secs),
            config,
            token_stats: DashMap::new(),
            blacklist: DashMap::new(),
        }
    }

    /// Add address to blacklist
    pub fn add_to_blacklist(&self, address: &str) {
        self.blacklist.insert(address.to_lowercase(), ());
    }

    /// Remove address from blacklist
    pub fn remove_from_blacklist(&self, address: &str) {
        self.blacklist.remove(&address.to_lowercase());
    }

    /// Check if address is blacklisted
    pub fn is_blacklisted(&self, address: &str) -> bool {
        self.blacklist.contains_key(&address.to_lowercase())
    }

    /// Update TVL for a token
    pub fn update_tvl(&self, token: &str, source_tvl: BigDecimal, dest_tvl: BigDecimal) {
        let stats = self
            .token_stats
            .entry(token.to_string())
            .or_insert_with(|| RwLock::new(TokenStats::default()));

        let mut stats = stats.write();
        stats.source_tvl = source_tvl;
        stats.dest_tvl = dest_tvl;
    }

    /// Analyze a correlated event for anomalies
    pub async fn analyze(&self, event: &CorrelatedEvent) -> Result<DetectionResult> {
        // Check blacklist first
        if self.is_blacklisted(&event.source_event.from_address)
            || self.is_blacklisted(&event.source_event.to_address)
        {
            return Ok(DetectionResult::anomaly(
                AnomalyType::BlacklistedAddress,
                Severity::Critical,
                1.0,
                "Transaction involves blacklisted address".to_string(),
            )
            .with_action("Block transaction and alert"));
        }

        // Check for amount mismatch
        if !event.amounts_match() {
            return Ok(DetectionResult::anomaly(
                AnomalyType::AmountMismatch,
                Severity::High,
                1.0,
                "Amount mismatch between deposit and withdrawal".to_string(),
            )
            .with_action("Investigate and possibly pause bridge"));
        }

        // Record the transaction
        self.record_transaction(event);

        // Check for large withdrawal
        if let Some(result) = self.check_large_withdrawal(event).await {
            return Ok(result);
        }

        // Check volume limits
        if let Some(result) = self.check_volume_limits(event).await {
            return Ok(result);
        }

        // Check for velocity anomaly
        if let Some(result) = self.check_velocity_anomaly(event).await {
            return Ok(result);
        }

        // Check for imbalance
        if let Some(result) = self.check_imbalance(event).await {
            return Ok(result);
        }

        Ok(DetectionResult::normal())
    }

    /// Record a transaction in statistics
    fn record_transaction(&self, event: &CorrelatedEvent) {
        let token = event.token();
        let stats = self
            .token_stats
            .entry(token.to_string())
            .or_insert_with(|| RwLock::new(TokenStats::default()));

        let mut stats = stats.write();
        let now = Instant::now();

        // Add new data point
        stats.values.push_back(DataPoint {
            value: event.amount().clone(),
            timestamp: now,
        });

        // The new point contributes to the long-window running sum. The
        // short/medium window aggregates are recomputed from the live points
        // in `cleanup_old_data`, so they are not incremented here.
        stats.long_sum = &stats.long_sum + event.amount();

        // Evict expired points and recompute each window independently.
        self.cleanup_old_data(&mut stats, now);
    }

    /// Evict data points older than the long window and recompute the
    /// short/medium window aggregates.
    ///
    /// Each window is maintained independently: a point contributes to a given
    /// window's sum only while its age is within that specific window boundary.
    /// Because `short_window <= medium_window <= long_window`, a point can age
    /// out of the short window while remaining inside the medium and long
    /// windows, so the per-window sums must be derived from the live points
    /// rather than gated on long-window eviction. The deque retains every point
    /// younger than the long window (newest at the back), and points are only
    /// physically removed once they exceed the long window.
    fn cleanup_old_data(&self, stats: &mut TokenStats, now: Instant) {
        // Drop points that have aged out of the longest window.
        while let Some(front) = stats.values.front() {
            let age = now.duration_since(front.timestamp);
            if age > self.long_window {
                let removed = stats.values.pop_front().unwrap();
                stats.long_sum = &stats.long_sum - &removed.value;
            } else {
                break;
            }
        }

        // Recompute the short and medium window aggregates from the points that
        // remain. This guarantees they shrink as soon as a point's age crosses
        // the corresponding window boundary, independent of long-window
        // eviction.
        let mut short_sum = BigDecimal::from(0);
        let mut medium_sum = BigDecimal::from(0);
        let mut short_count: u32 = 0;
        for point in &stats.values {
            let age = now.duration_since(point.timestamp);
            if age <= self.medium_window {
                medium_sum = &medium_sum + &point.value;
            }
            if age <= self.short_window {
                short_sum = &short_sum + &point.value;
                short_count += 1;
            }
        }
        stats.short_sum = short_sum;
        stats.medium_sum = medium_sum;
        stats.short_count = short_count;
    }

    /// Check for large withdrawal
    async fn check_large_withdrawal(&self, event: &CorrelatedEvent) -> Option<DetectionResult> {
        let token = event.token();
        let amount = event.amount();

        // Get TVL
        let stats = self.token_stats.get(token)?;
        let stats = stats.read();

        if stats.source_tvl == 0 {
            return None;
        }

        // Calculate percentage of TVL
        let pct = (amount * &BigDecimal::from(100)) / &stats.source_tvl;
        let pct_f64: f64 = pct.to_string().parse().unwrap_or(0.0);

        if pct_f64 > self.config.large_withdrawal_pct {
            let severity = if pct_f64 > self.config.large_withdrawal_pct * 5.0 {
                Severity::Critical
            } else if pct_f64 > self.config.large_withdrawal_pct * 2.0 {
                Severity::High
            } else {
                Severity::Medium
            };

            return Some(
                DetectionResult::anomaly(
                    AnomalyType::LargeWithdrawal,
                    severity,
                    0.9,
                    format!(
                        "Large withdrawal: {:.2}% of TVL ({} {})",
                        pct_f64, amount, token
                    ),
                )
                .with_action("Require manual approval")
                .with_details(serde_json::json!({
                    "percentage": pct_f64,
                    "threshold": self.config.large_withdrawal_pct,
                    "amount": amount.to_string(),
                    "tvl": stats.source_tvl.to_string()
                })),
            );
        }

        None
    }

    /// Check volume limits
    async fn check_volume_limits(&self, event: &CorrelatedEvent) -> Option<DetectionResult> {
        let token = event.token();
        let stats = self.token_stats.get(token)?;
        let stats = stats.read();

        // Check hourly limit
        if let Some(ref limit) = self.config.hourly_volume_limit {
            if &stats.medium_sum > limit {
                return Some(
                    DetectionResult::anomaly(
                        AnomalyType::VolumeExceeded,
                        Severity::High,
                        0.95,
                        format!(
                            "Hourly volume exceeded: {} > {} for {}",
                            stats.medium_sum, limit, token
                        ),
                    )
                    .with_action("Rate limit or pause bridge"),
                );
            }
        }

        // Check daily limit
        if let Some(ref limit) = self.config.daily_volume_limit {
            if &stats.long_sum > limit {
                return Some(
                    DetectionResult::anomaly(
                        AnomalyType::VolumeExceeded,
                        Severity::Critical,
                        0.98,
                        format!(
                            "Daily volume exceeded: {} > {} for {}",
                            stats.long_sum, limit, token
                        ),
                    )
                    .with_action("Pause bridge immediately"),
                );
            }
        }

        None
    }

    /// Check for velocity anomaly
    async fn check_velocity_anomaly(&self, event: &CorrelatedEvent) -> Option<DetectionResult> {
        let token = event.token();
        let stats = self.token_stats.get(token)?;
        let stats = stats.read();

        // Need enough data points
        if stats.values.len() < 10 {
            return None;
        }

        // Check for rapid withdrawals in short window
        if stats.short_count > 10 {
            return Some(
                DetectionResult::anomaly(
                    AnomalyType::RapidWithdrawals,
                    Severity::Medium,
                    0.8,
                    format!(
                        "Rapid withdrawals detected: {} in last {} seconds for {}",
                        stats.short_count, self.config.time_windows.short_secs, token
                    ),
                )
                .with_action("Investigate pattern"),
            );
        }

        None
    }

    /// Check for TVL imbalance
    async fn check_imbalance(&self, event: &CorrelatedEvent) -> Option<DetectionResult> {
        let token = event.token();
        let stats = self.token_stats.get(token)?;
        let stats = stats.read();

        if stats.source_tvl == 0 || stats.dest_tvl == 0 {
            return None;
        }

        // Calculate imbalance percentage
        let total = &stats.source_tvl + &stats.dest_tvl;
        let diff = (&stats.source_tvl - &stats.dest_tvl).abs();
        let imbalance_pct = (&diff * &BigDecimal::from(100)) / &total;
        let imbalance_f64: f64 = imbalance_pct.to_string().parse().unwrap_or(0.0);

        if imbalance_f64 > self.config.imbalance_threshold_pct {
            return Some(
                DetectionResult::anomaly(
                    AnomalyType::Imbalance,
                    Severity::High,
                    0.85,
                    format!(
                        "TVL imbalance detected: {:.2}% for {} (source: {}, dest: {})",
                        imbalance_f64, token, stats.source_tvl, stats.dest_tvl
                    ),
                )
                .with_action("Investigate and consider pausing"),
            );
        }

        None
    }

    /// Get statistics for a token
    pub fn get_stats(&self, token: &str) -> Option<TokenStatsSummary> {
        let stats = self.token_stats.get(token)?;
        let stats = stats.read();

        Some(TokenStatsSummary {
            token: token.to_string(),
            short_volume: stats.short_sum.clone(),
            medium_volume: stats.medium_sum.clone(),
            long_volume: stats.long_sum.clone(),
            source_tvl: stats.source_tvl.clone(),
            dest_tvl: stats.dest_tvl.clone(),
            transaction_count: stats.values.len(),
        })
    }
}

/// Summary of token statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStatsSummary {
    /// Token symbol
    pub token: String,
    /// Volume in short window
    pub short_volume: BigDecimal,
    /// Volume in medium window
    pub medium_volume: BigDecimal,
    /// Volume in long window
    pub long_volume: BigDecimal,
    /// Source chain TVL
    pub source_tvl: BigDecimal,
    /// Destination chain TVL
    pub dest_tvl: BigDecimal,
    /// Transaction count in buffer
    pub transaction_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TimeWindows;
    use crate::watcher::{BridgeEvent, EventType};
    use std::str::FromStr;

    fn test_config() -> DetectionConfig {
        DetectionConfig {
            large_withdrawal_pct: 1.0,
            hourly_volume_limit: Some(BigDecimal::from_str("1000000").unwrap()),
            daily_volume_limit: Some(BigDecimal::from_str("10000000").unwrap()),
            imbalance_threshold_pct: 10.0,
            velocity_threshold: 3.0,
            time_windows: Default::default(),
        }
    }

    fn test_event(amount: &str) -> CorrelatedEvent {
        let source = BridgeEvent::new(
            "ethereum",
            12345,
            "0xdep",
            EventType::Deposit,
            "USDC",
            BigDecimal::from_str(amount).unwrap(),
            "0xsender",
            "0xrecipient",
        );

        let dest = BridgeEvent::new(
            "arbitrum",
            67890,
            "0xwith",
            EventType::Withdrawal,
            "USDC",
            BigDecimal::from_str(amount).unwrap(),
            "0xbridge",
            "0xrecipient",
        );

        CorrelatedEvent {
            id: "test-1".to_string(),
            source_event: source,
            destination_event: Some(dest),
            status: crate::correlation::CorrelationStatus::Matched,
            created_at: chrono::Utc::now().timestamp(),
            completed_at: Some(chrono::Utc::now().timestamp()),
            latency_secs: Some(60),
        }
    }

    #[tokio::test]
    async fn test_normal_transaction() {
        let detector = AnomalyDetector::new(test_config());

        // Set TVL
        detector.update_tvl(
            "USDC",
            BigDecimal::from_str("100000000").unwrap(),
            BigDecimal::from_str("100000000").unwrap(),
        );

        let event = test_event("1000");
        let result = detector.analyze(&event).await.unwrap();

        assert!(!result.is_anomaly);
    }

    #[tokio::test]
    async fn test_large_withdrawal() {
        let detector = AnomalyDetector::new(test_config());

        // Set TVL
        detector.update_tvl(
            "USDC",
            BigDecimal::from_str("1000000").unwrap(),
            BigDecimal::from_str("1000000").unwrap(),
        );

        // Withdraw 2% of TVL
        let event = test_event("20000");
        let result = detector.analyze(&event).await.unwrap();

        assert!(result.is_anomaly);
        assert_eq!(result.anomaly_type, Some(AnomalyType::LargeWithdrawal));
    }

    #[tokio::test]
    async fn test_blacklisted_address() {
        let detector = AnomalyDetector::new(test_config());
        detector.add_to_blacklist("0xsender");

        let event = test_event("1000");
        let result = detector.analyze(&event).await.unwrap();

        assert!(result.is_anomaly);
        assert_eq!(result.anomaly_type, Some(AnomalyType::BlacklistedAddress));
        assert_eq!(result.severity, Severity::Critical);
    }

    /// Build a detector with explicit, strictly-ordered window sizes so we can
    /// reason about which points belong to which window.
    fn rolling_window_config() -> DetectionConfig {
        DetectionConfig {
            large_withdrawal_pct: 1.0,
            hourly_volume_limit: None,
            daily_volume_limit: None,
            imbalance_threshold_pct: 10.0,
            velocity_threshold: 3.0,
            time_windows: TimeWindows {
                short_secs: 10,
                medium_secs: 100,
                long_secs: 1000,
            },
        }
    }

    fn dp(value: &str, age: Duration, now: Instant) -> DataPoint {
        DataPoint {
            value: BigDecimal::from_str(value).unwrap(),
            // Place the point `age` in the past relative to `now`.
            timestamp: now.checked_sub(age).expect("age within Instant range"),
        }
    }

    /// Regression test for HIGH #22.
    ///
    /// `cleanup_old_data` previously nested the short/medium decrements inside
    /// the long-window eviction branch, guarded by `age <= short/medium_window`.
    /// Since `short <= medium <= long`, those guards could never be true when
    /// `age > long_window`, so the short/medium sums (and short_count) only ever
    /// grew. This test seeds points with controlled ages spanning all three
    /// windows and asserts that each window's aggregate reflects ONLY the points
    /// inside that window -- i.e. the rolling windows actually shrink.
    #[test]
    fn test_rolling_windows_shrink() {
        let detector = AnomalyDetector::new(rolling_window_config());
        // Anchor `now` well forward of the monotonic-clock origin so the
        // backwards-dated points below never underflow `checked_sub`.
        let now = Instant::now()
            .checked_add(Duration::from_secs(10_000))
            .expect("anchor within Instant range");

        let mut stats = TokenStats::default();

        // Points listed oldest-first. With short=10s, medium=100s, long=1000s:
        //   age 2000s -> outside long (evicted)      value 1600
        //   age 500s  -> in long only                value 800
        //   age  50s  -> in medium, long (NOT short) value 400
        //   age   8s  -> in short, medium, long      value 200
        //   age   5s  -> in short, medium, long      value 100
        let points = [
            dp("1600", Duration::from_secs(2000), now),
            dp("800", Duration::from_secs(500), now),
            dp("400", Duration::from_secs(50), now),
            dp("200", Duration::from_secs(8), now),
            dp("100", Duration::from_secs(5), now),
        ];

        // `push_back` in oldest-first order so the deque is ordered
        // front (oldest) -> back (newest), matching how `record_transaction`
        // pushes points and how `cleanup_old_data` evicts from the front.
        for p in &points {
            stats.values.push_back(p.clone());
        }

        // Seed long_sum the way record_transaction does (running total of every
        // point currently considered "added", including the about-to-be-evicted
        // one) so eviction has something to subtract.
        stats.long_sum = BigDecimal::from_str("3100").unwrap(); // 100+200+400+800+1600

        detector.cleanup_old_data(&mut stats, now);

        // Long window (<=1000s): excludes the 2000s point (1600). 100+200+400+800.
        assert_eq!(
            stats.long_sum,
            BigDecimal::from_str("1500").unwrap(),
            "long_sum must drop the point older than the long window"
        );
        // The evicted point must be physically removed from the buffer.
        assert_eq!(stats.values.len(), 4, "stale point must be evicted");

        // Medium window (<=100s): excludes 500s (800) and 2000s. 100+200+400.
        assert_eq!(
            stats.medium_sum,
            BigDecimal::from_str("700").unwrap(),
            "medium_sum must exclude points older than the medium window"
        );

        // Short window (<=10s): only the 5s and 8s points. 100+200.
        assert_eq!(
            stats.short_sum,
            BigDecimal::from_str("300").unwrap(),
            "short_sum must exclude points older than the short window"
        );
        assert_eq!(
            stats.short_count, 2,
            "short_count must reflect only points inside the short window"
        );

        // Now advance time so the 8s point ages past the 10s short window.
        // (now + 5s => point ages become 10s and 13s; only the 5s-origin point,
        // now 10s old, stays within short=10s with the <= boundary.)
        let later = now.checked_add(Duration::from_secs(5)).unwrap();
        detector.cleanup_old_data(&mut stats, later);

        // The 8s point (now 13s old) must have dropped OUT of the short window:
        // short_sum shrinks from 300 to just the 100-value point.
        assert_eq!(
            stats.short_sum,
            BigDecimal::from_str("100").unwrap(),
            "advancing time must shrink short_sum as points age out"
        );
        assert_eq!(
            stats.short_count, 1,
            "advancing time must shrink short_count as points age out"
        );
        // Medium window unaffected by a 5s advance (all 3 still <=100s old).
        assert_eq!(
            stats.medium_sum,
            BigDecimal::from_str("700").unwrap(),
            "medium_sum unchanged when no point crosses the medium boundary"
        );
    }
}
