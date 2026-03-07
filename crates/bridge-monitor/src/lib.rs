#![deny(unsafe_code)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
//! Bridge Security Monitor
//!
//! Provides cross-chain bridge monitoring and security enforcement for HSM.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       Bridge Monitor                             │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
//! │  │  Chain A    │  │  Chain B    │  │  Chain C    │              │
//! │  │  Watcher    │  │  Watcher    │  │  Watcher    │              │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
//! │         │                │                │                      │
//! │         ▼                ▼                ▼                      │
//! │  ┌─────────────────────────────────────────────────────────┐    │
//! │  │                 Event Correlator                         │    │
//! │  │    (matches deposits ↔ withdrawals across chains)        │    │
//! │  └─────────────────────────┬───────────────────────────────┘    │
//! │                            │                                     │
//! │         ┌──────────────────┼──────────────────┐                 │
//! │         ▼                  ▼                  ▼                 │
//! │  ┌───────────┐      ┌───────────┐      ┌───────────┐           │
//! │  │ Anomaly   │      │ Rate      │      │ Balance   │           │
//! │  │ Detector  │      │ Limiter   │      │ Checker   │           │
//! │  └───────────┘      └───────────┘      └───────────┘           │
//! │         │                  │                  │                 │
//! │         ▼                  ▼                  ▼                 │
//! │  ┌─────────────────────────────────────────────────────────┐    │
//! │  │                  Policy Enforcer                         │    │
//! │  │    (pause bridge, require approvals, send alerts)        │    │
//! │  └─────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **Multi-chain watching**: Monitor deposits/withdrawals on multiple chains
//! - **Event correlation**: Match cross-chain transactions
//! - **Anomaly detection**: Detect unusual patterns and suspicious activity
//! - **Rate limiting**: Enforce volume limits per time window
//! - **Balance checking**: Monitor TVL and detect imbalances
//! - **Policy enforcement**: Automatic responses to security events
//! - **Alerting**: Notify operators via multiple channels

pub mod alerts;
pub mod config;
pub mod correlation;
pub mod detection;
pub mod error;
pub mod policy;
pub mod watcher;

pub use config::{BridgeConfig, ChainConfig, MonitorConfig};
pub use correlation::{CorrelatedEvent, EventCorrelator};
pub use detection::{AnomalyDetector, AnomalyType, DetectionResult};
pub use error::{BridgeError, Result};
pub use policy::{BridgePolicy, PolicyAction, PolicyEnforcer};
pub use watcher::{BridgeEvent, ChainWatcher, EventType};

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Bridge monitor service
pub struct BridgeMonitor {
    /// Configuration
    config: MonitorConfig,
    /// Chain watchers
    watchers: DashMap<String, Arc<dyn ChainWatcher>>,
    /// Event correlator
    correlator: Arc<EventCorrelator>,
    /// Anomaly detector
    detector: Arc<AnomalyDetector>,
    /// Policy enforcer
    enforcer: Arc<PolicyEnforcer>,
    /// Running flag
    running: RwLock<bool>,
    /// Event channel sender
    event_tx: async_channel::Sender<BridgeEvent>,
    /// Event channel receiver
    event_rx: async_channel::Receiver<BridgeEvent>,
}

impl BridgeMonitor {
    /// Create a new bridge monitor
    pub fn new(config: MonitorConfig) -> Self {
        let (event_tx, event_rx) = async_channel::unbounded();

        Self {
            correlator: Arc::new(EventCorrelator::new(config.correlation.clone())),
            detector: Arc::new(AnomalyDetector::new(config.detection.clone())),
            enforcer: Arc::new(PolicyEnforcer::new(config.policy.clone())),
            config,
            watchers: DashMap::new(),
            running: RwLock::new(false),
            event_tx,
            event_rx,
        }
    }

    /// Register a chain watcher
    pub fn register_watcher(&self, chain_id: &str, watcher: Arc<dyn ChainWatcher>) {
        self.watchers.insert(chain_id.to_string(), watcher);
    }

    /// Start the bridge monitor
    pub async fn start(&self) -> Result<()> {
        *self.running.write().await = true;

        // Start all watchers
        for entry in self.watchers.iter() {
            let watcher = entry.value().clone();
            let tx = self.event_tx.clone();

            tokio::spawn(async move {
                if let Err(e) = watcher.start(tx).await {
                    tracing::error!("Watcher error: {}", e);
                }
            });
        }

        // Start event processing
        self.process_events().await;

        Ok(())
    }

    /// Stop the bridge monitor
    pub async fn stop(&self) -> Result<()> {
        *self.running.write().await = false;

        // Stop all watchers
        for entry in self.watchers.iter() {
            entry.value().stop().await?;
        }

        Ok(())
    }

    /// Process incoming events
    async fn process_events(&self) {
        while *self.running.read().await {
            match self.event_rx.recv().await {
                Ok(event) => {
                    if let Err(e) = self.handle_event(event).await {
                        tracing::error!("Error handling event: {}", e);
                    }
                }
                Err(_) => break,
            }
        }
    }

    /// Handle a bridge event
    async fn handle_event(&self, event: BridgeEvent) -> Result<()> {
        // Log event
        tracing::info!(
            "Bridge event: {:?} on {} - {} {}",
            event.event_type,
            event.chain_id,
            event.amount,
            event.token
        );

        // Correlate event
        if let Some(correlated) = self.correlator.process_event(&event).await? {
            // Check for anomalies
            let detection = self.detector.analyze(&correlated).await?;

            if detection.is_anomaly {
                tracing::warn!("Anomaly detected: {:?}", detection.anomaly_type);

                // Enforce policy
                let action = self.enforcer.evaluate(&correlated, &detection).await?;
                self.enforcer.execute(action).await?;
            }
        }

        // Update metrics
        self.update_metrics(&event);

        Ok(())
    }

    /// Update monitoring metrics
    fn update_metrics(&self, event: &BridgeEvent) {
        let chain = event.chain_id.clone();
        let token = event.token.clone();
        let event_type = event.event_type.as_str().to_string();

        metrics::counter!(
            "bridge_events_total",
            "chain" => chain,
            "token" => token,
            "type" => event_type
        )
        .increment(1);
    }

    /// Get event correlator
    pub fn correlator(&self) -> Arc<EventCorrelator> {
        self.correlator.clone()
    }

    /// Get anomaly detector
    pub fn detector(&self) -> Arc<AnomalyDetector> {
        self.detector.clone()
    }

    /// Get policy enforcer
    pub fn enforcer(&self) -> Arc<PolicyEnforcer> {
        self.enforcer.clone()
    }
}
