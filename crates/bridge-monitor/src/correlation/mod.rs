//! Event correlation for cross-chain transactions

use crate::config::CorrelationConfig;
use crate::error::Result;
use crate::watcher::{BridgeEvent, EventType};
use bigdecimal::BigDecimal;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Correlated cross-chain event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    /// Correlation ID
    pub id: String,
    /// Source chain event (deposit)
    pub source_event: BridgeEvent,
    /// Destination chain event (withdrawal), if matched
    pub destination_event: Option<BridgeEvent>,
    /// Correlation status
    pub status: CorrelationStatus,
    /// Time when correlation was created
    pub created_at: i64,
    /// Time when correlation was completed
    pub completed_at: Option<i64>,
    /// Correlation latency (seconds)
    pub latency_secs: Option<u64>,
}

impl CorrelatedEvent {
    /// Check if the event amounts match
    pub fn amounts_match(&self) -> bool {
        if let Some(ref dest) = self.destination_event {
            self.source_event.amount == dest.amount
        } else {
            false
        }
    }

    /// Check if addresses match (source.to == destination.to)
    pub fn recipient_matches(&self) -> bool {
        if let Some(ref dest) = self.destination_event {
            self.source_event.to_address == dest.to_address
        } else {
            false
        }
    }

    /// Get the transfer amount
    pub fn amount(&self) -> &BigDecimal {
        &self.source_event.amount
    }

    /// Get the token
    pub fn token(&self) -> &str {
        &self.source_event.token
    }
}

/// Correlation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationStatus {
    /// Waiting for destination event
    Pending,
    /// Successfully correlated
    Matched,
    /// Correlation timed out
    TimedOut,
    /// Amount mismatch detected
    AmountMismatch,
    /// Correlation failed
    Failed,
}

/// Pending correlation entry
#[derive(Debug)]
struct PendingCorrelation {
    event: BridgeEvent,
    created_at: Instant,
}

/// Event correlator
pub struct EventCorrelator {
    /// Configuration
    config: CorrelationConfig,
    /// Pending correlations by message hash
    pending_by_hash: DashMap<String, PendingCorrelation>,
    /// Pending correlations by (token, amount, recipient) for fuzzy matching
    pending_by_key: DashMap<String, Vec<PendingCorrelation>>,
    /// Completed correlations
    completed: DashMap<String, CorrelatedEvent>,
    /// Correlation timeout
    timeout: Duration,
}

impl EventCorrelator {
    /// Create a new event correlator
    pub fn new(config: CorrelationConfig) -> Self {
        Self {
            timeout: Duration::from_secs(config.timeout_secs),
            config,
            pending_by_hash: DashMap::new(),
            pending_by_key: DashMap::new(),
            completed: DashMap::new(),
        }
    }

    /// Process a bridge event
    pub async fn process_event(&self, event: &BridgeEvent) -> Result<Option<CorrelatedEvent>> {
        match event.event_type {
            EventType::Deposit => {
                // Source event - add to pending
                self.add_pending(event.clone());
                Ok(None)
            }
            EventType::Withdrawal | EventType::Claim => {
                // Destination event - try to correlate
                self.correlate(event).await
            }
            _ => Ok(None),
        }
    }

    /// Add event to pending correlations
    fn add_pending(&self, event: BridgeEvent) {
        let pending = PendingCorrelation {
            event: event.clone(),
            created_at: Instant::now(),
        };

        // Index by message hash if available
        if let Some(ref hash) = event.message_hash {
            self.pending_by_hash.insert(
                hash.clone(),
                PendingCorrelation {
                    event: event.clone(),
                    created_at: Instant::now(),
                },
            );
        }

        // Index by fuzzy key (token + amount + recipient)
        let key = Self::make_fuzzy_key(&event);
        self.pending_by_key.entry(key).or_default().push(pending);
    }

    /// Try to correlate a destination event with a pending source event
    async fn correlate(&self, dest_event: &BridgeEvent) -> Result<Option<CorrelatedEvent>> {
        // First try exact match by message hash
        if let Some(ref hash) = dest_event.message_hash {
            if let Some((_, pending)) = self.pending_by_hash.remove(hash) {
                let correlated = self.create_correlated(pending.event, dest_event.clone());
                self.completed
                    .insert(correlated.id.clone(), correlated.clone());
                return Ok(Some(correlated));
            }
        }

        // Try fuzzy match by key
        let key = Self::make_fuzzy_key(dest_event);
        if let Some(mut pendings) = self.pending_by_key.get_mut(&key) {
            // Find the oldest matching pending event
            if let Some(pos) = pendings
                .iter()
                .position(|p| self.events_match(&p.event, dest_event))
            {
                let pending = pendings.remove(pos);
                let correlated = self.create_correlated(pending.event, dest_event.clone());
                self.completed
                    .insert(correlated.id.clone(), correlated.clone());
                return Ok(Some(correlated));
            }
        }

        // No match found - log unmatched withdrawal
        tracing::warn!(
            "Unmatched withdrawal: {} {} to {}",
            dest_event.amount,
            dest_event.token,
            dest_event.to_address
        );

        Ok(None)
    }

    /// Create fuzzy key for matching
    fn make_fuzzy_key(event: &BridgeEvent) -> String {
        format!(
            "{}:{}:{}",
            event.token,
            event.amount,
            event.to_address.to_lowercase()
        )
    }

    /// Check if two events match (for fuzzy correlation)
    fn events_match(&self, source: &BridgeEvent, dest: &BridgeEvent) -> bool {
        source.token == dest.token
            && source.amount == dest.amount
            && source.to_address.to_lowercase() == dest.to_address.to_lowercase()
    }

    /// Create correlated event
    fn create_correlated(&self, source: BridgeEvent, dest: BridgeEvent) -> CorrelatedEvent {
        let now = chrono::Utc::now().timestamp();
        let latency = (now - source.timestamp).max(0) as u64;

        let status = if source.amount == dest.amount {
            CorrelationStatus::Matched
        } else {
            CorrelationStatus::AmountMismatch
        };

        CorrelatedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            source_event: source,
            destination_event: Some(dest),
            status,
            created_at: now,
            completed_at: Some(now),
            latency_secs: Some(latency),
        }
    }

    /// Cleanup expired pending correlations
    pub fn cleanup_expired(&self) -> usize {
        let mut expired_count = 0;

        // Clean pending by hash
        self.pending_by_hash.retain(|_, pending| {
            if pending.created_at.elapsed() > self.timeout {
                expired_count += 1;
                false
            } else {
                true
            }
        });

        // Clean pending by key
        self.pending_by_key.iter_mut().for_each(|mut entry| {
            let before = entry.value().len();
            entry
                .value_mut()
                .retain(|p| p.created_at.elapsed() <= self.timeout);
            expired_count += before - entry.value().len();
        });

        // Remove empty entries
        self.pending_by_key.retain(|_, v| !v.is_empty());

        expired_count
    }

    /// Get pending count
    pub fn pending_count(&self) -> usize {
        self.pending_by_hash.len()
            + self
                .pending_by_key
                .iter()
                .map(|e| e.value().len())
                .sum::<usize>()
    }

    /// Get completed count
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    /// Get correlated event by ID
    pub fn get_correlated(&self, id: &str) -> Option<CorrelatedEvent> {
        self.completed.get(id).map(|e| e.clone())
    }

    /// Get all completed correlations
    pub fn all_completed(&self) -> Vec<CorrelatedEvent> {
        self.completed.iter().map(|e| e.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_config() -> CorrelationConfig {
        CorrelationConfig {
            timeout_secs: 3600,
            buffer_size: 1000,
            cleanup_interval_secs: 60,
        }
    }

    fn deposit_event() -> BridgeEvent {
        BridgeEvent::new(
            "ethereum",
            12345,
            "0xdep123",
            EventType::Deposit,
            "USDC",
            BigDecimal::from_str("1000000").unwrap(),
            "0xsender",
            "0xrecipient",
        )
        .with_message_hash("0xmessage123")
    }

    fn withdrawal_event() -> BridgeEvent {
        BridgeEvent::new(
            "arbitrum",
            67890,
            "0xwith123",
            EventType::Withdrawal,
            "USDC",
            BigDecimal::from_str("1000000").unwrap(),
            "0xbridge",
            "0xrecipient",
        )
        .with_message_hash("0xmessage123")
    }

    #[tokio::test]
    async fn test_correlation_by_hash() {
        let correlator = EventCorrelator::new(test_config());

        // Add deposit
        let deposit = deposit_event();
        let result = correlator.process_event(&deposit).await.unwrap();
        assert!(result.is_none()); // No correlation yet
        assert_eq!(correlator.pending_count(), 2); // In both indexes

        // Add withdrawal
        let withdrawal = withdrawal_event();
        let result = correlator.process_event(&withdrawal).await.unwrap();
        assert!(result.is_some());

        let correlated = result.unwrap();
        assert_eq!(correlated.status, CorrelationStatus::Matched);
        assert!(correlated.amounts_match());
    }

    #[tokio::test]
    async fn test_fuzzy_correlation() {
        let correlator = EventCorrelator::new(test_config());

        // Add deposit without message hash
        let mut deposit = deposit_event();
        deposit.message_hash = None;
        correlator.process_event(&deposit).await.unwrap();

        // Add withdrawal without message hash
        let mut withdrawal = withdrawal_event();
        withdrawal.message_hash = None;
        let result = correlator.process_event(&withdrawal).await.unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().status, CorrelationStatus::Matched);
    }
}
