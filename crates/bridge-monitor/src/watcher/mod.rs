//! Chain watchers for monitoring bridge events

pub mod evm;

use crate::config::ChainConfig;
use crate::error::Result;
use async_trait::async_trait;
use bigdecimal::BigDecimal;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub use evm::EvmWatcher;

/// Bridge event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventType {
    /// Deposit on source chain
    Deposit,
    /// Withdrawal on destination chain
    Withdrawal,
    /// Relayer submission
    RelayerSubmit,
    /// Claim/finalization
    Claim,
    /// Bridge pause
    Pause,
    /// Bridge unpause
    Unpause,
}

impl EventType {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdrawal => "withdrawal",
            Self::RelayerSubmit => "relayer_submit",
            Self::Claim => "claim",
            Self::Pause => "pause",
            Self::Unpause => "unpause",
        }
    }
}

/// Bridge event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeEvent {
    /// Event ID
    pub id: String,
    /// Chain ID
    pub chain_id: String,
    /// Block number
    pub block_number: u64,
    /// Transaction hash
    pub tx_hash: String,
    /// Event type
    pub event_type: EventType,
    /// Token symbol
    pub token: String,
    /// Amount
    pub amount: BigDecimal,
    /// Sender address
    pub from_address: String,
    /// Recipient address
    pub to_address: String,
    /// Nonce/sequence number
    pub nonce: Option<u64>,
    /// Bridge message hash (for correlation)
    pub message_hash: Option<String>,
    /// Timestamp
    pub timestamp: i64,
    /// Log index within block
    pub log_index: u32,
    /// Additional data
    #[serde(default)]
    pub extra_data: serde_json::Value,
}

impl BridgeEvent {
    /// Create a new bridge event
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: &str,
        block_number: u64,
        tx_hash: &str,
        event_type: EventType,
        token: &str,
        amount: BigDecimal,
        from_address: &str,
        to_address: &str,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            chain_id: chain_id.to_string(),
            block_number,
            tx_hash: tx_hash.to_string(),
            event_type,
            token: token.to_string(),
            amount,
            from_address: from_address.to_string(),
            to_address: to_address.to_string(),
            nonce: None,
            message_hash: None,
            timestamp: chrono::Utc::now().timestamp(),
            log_index: 0,
            extra_data: serde_json::Value::Null,
        }
    }

    /// Set nonce
    pub fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set message hash
    pub fn with_message_hash(mut self, hash: &str) -> Self {
        self.message_hash = Some(hash.to_string());
        self
    }

    /// Set timestamp
    pub fn with_timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Set log index
    pub fn with_log_index(mut self, index: u32) -> Self {
        self.log_index = index;
        self
    }
}

/// Chain watcher trait
#[async_trait]
pub trait ChainWatcher: Send + Sync {
    /// Get chain ID
    fn chain_id(&self) -> &str;

    /// Start watching the chain
    async fn start(&self, event_tx: async_channel::Sender<BridgeEvent>) -> Result<()>;

    /// Stop watching
    async fn stop(&self) -> Result<()>;

    /// Get current block number
    async fn current_block(&self) -> Result<u64>;

    /// Get last processed block
    fn last_processed_block(&self) -> u64;

    /// Check if running
    fn is_running(&self) -> bool;
}

/// Watcher metrics
#[derive(Debug, Default)]
pub struct WatcherMetrics {
    /// Events processed
    pub events_processed: u64,
    /// Blocks processed
    pub blocks_processed: u64,
    /// Errors encountered
    pub errors: u64,
    /// Last block number
    pub last_block: u64,
    /// Processing lag (blocks behind)
    pub lag: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_event() {
        let event = BridgeEvent::new(
            "ethereum",
            12345,
            "0xabc123",
            EventType::Deposit,
            "USDC",
            BigDecimal::from_str("1000000").unwrap(),
            "0xsender",
            "0xrecipient",
        )
        .with_nonce(1)
        .with_message_hash("0xmessage");

        assert_eq!(event.chain_id, "ethereum");
        assert_eq!(event.event_type, EventType::Deposit);
        assert_eq!(event.nonce, Some(1));
    }
}
