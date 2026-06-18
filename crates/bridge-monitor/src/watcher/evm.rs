//! EVM chain watcher

use super::{BridgeEvent, ChainWatcher, EventType, WatcherMetrics};
use crate::config::ChainConfig;
use crate::error::{BridgeError, Result};
use async_trait::async_trait;
use bigdecimal::BigDecimal;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// EVM chain watcher
pub struct EvmWatcher {
    /// Chain configuration
    config: ChainConfig,
    /// Bridge contract addresses
    bridge_contracts: Vec<String>,
    /// Event signatures to watch
    event_signatures: HashMap<String, EventType>,
    /// HTTP client
    client: reqwest::Client,
    /// Current RPC endpoint index
    rpc_index: AtomicU64,
    /// Running flag
    running: AtomicBool,
    /// Last processed block
    last_block: AtomicU64,
    /// Metrics
    metrics: RwLock<WatcherMetrics>,
}

impl EvmWatcher {
    /// Create a new EVM watcher
    pub fn new(config: ChainConfig, bridge_contracts: Vec<String>) -> Self {
        let mut event_signatures = HashMap::new();

        // Common bridge event signatures
        event_signatures.insert(
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".to_string(), // Transfer
            EventType::Deposit,
        );

        Self {
            config,
            bridge_contracts,
            event_signatures,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            rpc_index: AtomicU64::new(0),
            running: AtomicBool::new(false),
            last_block: AtomicU64::new(0),
            metrics: RwLock::new(WatcherMetrics::default()),
        }
    }

    /// Add event signature to watch
    pub fn watch_event(&mut self, signature: &str, event_type: EventType) {
        self.event_signatures
            .insert(signature.to_string(), event_type);
    }

    /// Get current RPC endpoint
    fn current_rpc(&self) -> &str {
        let index = self.rpc_index.load(Ordering::SeqCst) as usize;
        &self.config.rpc_endpoints[index % self.config.rpc_endpoints.len()]
    }

    /// Rotate to next RPC endpoint
    fn rotate_rpc(&self) {
        let _ = self.rpc_index.fetch_add(1, Ordering::SeqCst);
    }

    /// Make JSON-RPC call
    async fn rpc_call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let response = self
            .client
            .post(self.current_rpc())
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                self.rotate_rpc();
                BridgeError::ChainConnection(e.to_string())
            })?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BridgeError::ChainConnection(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(BridgeError::ChainConnection(error.to_string()));
        }

        serde_json::from_value(json["result"].clone()).map_err(BridgeError::Serialization)
    }

    /// Get current block number
    async fn get_block_number(&self) -> Result<u64> {
        let result: String = self
            .rpc_call("eth_blockNumber", serde_json::json!([]))
            .await?;
        u64::from_str_radix(result.trim_start_matches("0x"), 16)
            .map_err(|e| BridgeError::ChainConnection(format!("Invalid block number: {}", e)))
    }

    /// Get logs for block range
    async fn get_logs(&self, from_block: u64, to_block: u64) -> Result<Vec<EvmLog>> {
        let topics: Vec<String> = self.event_signatures.keys().cloned().collect();

        let params = serde_json::json!([{
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock": format!("0x{:x}", to_block),
            "address": self.bridge_contracts,
            "topics": [topics]
        }]);

        self.rpc_call("eth_getLogs", params).await
    }

    /// Parse log into bridge event
    fn parse_log(&self, log: &EvmLog) -> Option<BridgeEvent> {
        let topic0 = log.topics.first()?;
        let event_type = self.event_signatures.get(topic0)?;

        let block_number =
            u64::from_str_radix(log.block_number.trim_start_matches("0x"), 16).ok()?;
        let log_index = u32::from_str_radix(log.log_index.trim_start_matches("0x"), 16).ok()?;

        // Parse Transfer event (simplified)
        // In production, use proper ABI decoding
        let (from, to, amount) = self.parse_transfer_data(&log.data, &log.topics)?;

        Some(BridgeEvent {
            id: uuid::Uuid::new_v4().to_string(),
            chain_id: self.config.chain_id.clone(),
            block_number,
            tx_hash: log.transaction_hash.clone(),
            event_type: *event_type,
            token: "UNKNOWN".to_string(), // Would be determined from contract address
            amount,
            from_address: from,
            to_address: to,
            nonce: None,
            message_hash: None,
            timestamp: chrono::Utc::now().timestamp(),
            log_index,
            extra_data: serde_json::json!({
                "contract": log.address,
                "topics": log.topics
            }),
        })
    }

    /// Parse Transfer event data
    fn parse_transfer_data(
        &self,
        data: &str,
        topics: &[String],
    ) -> Option<(String, String, BigDecimal)> {
        if topics.len() < 3 {
            return None;
        }

        // Topics[1] = from (padded to 32 bytes)
        let from = format!("0x{}", &topics[1][26..]);

        // Topics[2] = to (padded to 32 bytes)
        let to = format!("0x{}", &topics[2][26..]);

        // Data = amount (hex encoded)
        let amount_hex = data.trim_start_matches("0x");
        let amount = u128::from_str_radix(amount_hex, 16)
            .ok()
            .map(BigDecimal::from)?;

        Some((from, to, amount))
    }

    /// Process blocks
    async fn process_blocks(
        &self,
        from_block: u64,
        to_block: u64,
        event_tx: &async_channel::Sender<BridgeEvent>,
    ) -> Result<()> {
        let logs = self.get_logs(from_block, to_block).await?;

        // Parse events first, then update metrics
        let mut events = Vec::new();
        for log in logs {
            if let Some(event) = self.parse_log(&log) {
                events.push(event);
            }
        }

        // Send events
        for event in &events {
            event_tx
                .send(event.clone())
                .await
                .map_err(|e| BridgeError::Internal(e.to_string()))?;
        }

        // Update metrics after all async work is done
        {
            let mut metrics = self.metrics.write();
            metrics.blocks_processed += to_block - from_block + 1;
            metrics.events_processed += events.len() as u64;
            metrics.last_block = to_block;
        }

        self.last_block.store(to_block, Ordering::SeqCst);

        Ok(())
    }
}

#[async_trait]
impl ChainWatcher for EvmWatcher {
    fn chain_id(&self) -> &str {
        &self.config.chain_id
    }

    async fn start(&self, event_tx: async_channel::Sender<BridgeEvent>) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        // Get starting block
        let mut current_block = self.get_block_number().await?;
        let mut processed_block = current_block.saturating_sub(self.config.confirmations as u64);
        self.last_block.store(processed_block, Ordering::SeqCst);

        let poll_interval = Duration::from_secs(self.config.poll_interval_secs);
        let batch_size = 100u64; // Process up to 100 blocks at a time

        while self.running.load(Ordering::SeqCst) {
            // Get latest block
            match self.get_block_number().await {
                Ok(latest) => {
                    current_block = latest;
                    let confirmed_block =
                        current_block.saturating_sub(self.config.confirmations as u64);

                    // Process any new blocks
                    while processed_block < confirmed_block && self.running.load(Ordering::SeqCst) {
                        let from_block = processed_block + 1;
                        let to_block = (from_block + batch_size - 1).min(confirmed_block);

                        if let Err(e) = self.process_blocks(from_block, to_block, &event_tx).await {
                            tracing::error!(
                                "Error processing blocks {}-{}: {}",
                                from_block,
                                to_block,
                                e
                            );
                            self.metrics.write().errors += 1;
                            break;
                        }

                        processed_block = to_block;
                    }

                    // Update lag metric
                    self.metrics.write().lag = current_block.saturating_sub(processed_block);
                }
                Err(e) => {
                    tracing::error!("Error getting block number: {}", e);
                    self.metrics.write().errors += 1;
                }
            }

            tokio::time::sleep(poll_interval).await;
        }

        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    async fn current_block(&self) -> Result<u64> {
        self.get_block_number().await
    }

    fn last_processed_block(&self) -> u64 {
        self.last_block.load(Ordering::SeqCst)
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// EVM log structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmLog {
    /// Contract address
    pub address: String,
    /// Log topics
    pub topics: Vec<String>,
    /// Log data
    pub data: String,
    /// Block number (hex)
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    /// Transaction hash
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    /// Transaction index (hex)
    #[serde(rename = "transactionIndex")]
    pub transaction_index: String,
    /// Block hash
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    /// Log index (hex)
    #[serde(rename = "logIndex")]
    pub log_index: String,
    /// Removed flag
    pub removed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ChainType;

    fn test_config() -> ChainConfig {
        ChainConfig {
            chain_id: "ethereum".to_string(),
            name: "Ethereum".to_string(),
            rpc_endpoints: vec!["https://eth.example.com".to_string()],
            confirmations: 12,
            poll_interval_secs: 15,
            chain_type: ChainType::Evm,
        }
    }

    #[test]
    fn test_evm_watcher_creation() {
        let watcher = EvmWatcher::new(test_config(), vec!["0xbridge".to_string()]);

        assert_eq!(watcher.chain_id(), "ethereum");
        assert!(!watcher.is_running());
    }
}
