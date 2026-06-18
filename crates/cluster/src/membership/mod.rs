//! Cluster membership management

use crate::config::{ClusterConfig, NodeId, PeerConfig};
use crate::error::{ClusterError, Result};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;

/// Peer health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerHealth {
    /// Peer is healthy
    Healthy,

    /// Peer is unhealthy (missed heartbeats)
    Unhealthy,

    /// Peer is unknown (never connected)
    Unknown,
}

/// Peer state
#[derive(Debug, Clone)]
pub struct PeerState {
    /// Peer configuration
    pub config: PeerConfig,

    /// Health status
    pub health: PeerHealth,

    /// Last heartbeat time
    pub last_heartbeat: Option<Instant>,

    /// Consecutive failed heartbeats
    pub failed_heartbeats: u32,

    /// Match index (for replication)
    pub match_index: u64,

    /// Next index (for replication)
    pub next_index: u64,
}

impl PeerState {
    /// Create a new peer state
    pub fn new(config: PeerConfig) -> Self {
        Self {
            config,
            health: PeerHealth::Unknown,
            last_heartbeat: None,
            failed_heartbeats: 0,
            match_index: 0,
            next_index: 1,
        }
    }

    /// Record a successful heartbeat
    pub fn record_heartbeat(&mut self) {
        self.last_heartbeat = Some(Instant::now());
        self.failed_heartbeats = 0;
        self.health = PeerHealth::Healthy;
    }

    /// Record a failed heartbeat
    pub fn record_failure(&mut self, threshold: u32) {
        self.failed_heartbeats += 1;
        if self.failed_heartbeats >= threshold {
            self.health = PeerHealth::Unhealthy;
        }
    }
}

/// Membership manager
pub struct MembershipManager {
    /// Configuration
    config: ClusterConfig,

    /// Peer states
    peers: DashMap<NodeId, PeerState>,

    /// Connected peer count
    connected_count: AtomicU32,

    /// Running flag
    running: RwLock<bool>,
}

impl MembershipManager {
    /// Create a new membership manager
    pub fn new(config: ClusterConfig) -> Self {
        let peers = DashMap::new();

        // Initialize peer states
        for peer in &config.peers {
            peers.insert(peer.node_id.clone(), PeerState::new(peer.clone()));
        }

        Self {
            config,
            peers,
            connected_count: AtomicU32::new(0),
            running: RwLock::new(false),
        }
    }

    /// Start membership management
    pub async fn start(&self) -> Result<()> {
        *self.running.write().await = true;

        // Start health check loop
        self.start_health_check().await;

        Ok(())
    }

    /// Stop membership management
    pub async fn stop(&self) -> Result<()> {
        *self.running.write().await = false;
        Ok(())
    }

    /// Local node identifier this membership manager belongs to.
    pub fn node_id(&self) -> &NodeId {
        &self.config.node_id
    }

    /// Number of consecutive missed heartbeats after which a peer is marked
    /// unhealthy. Derived from the configured election timeout relative to the
    /// heartbeat interval, so a peer is considered down once it could not have
    /// reset our election timer.
    pub fn failure_threshold(&self) -> u32 {
        let heartbeat = self.config.raft.heartbeat_interval_ms.max(1);
        let election = self.config.raft.election_timeout_max_ms;
        // At least one missed heartbeat; otherwise the number of heartbeats
        // that fit within a full election timeout.
        ((election / heartbeat) as u32).max(1)
    }

    /// Start health check loop
    async fn start_health_check(&self) {
        // Drive the cadence from the configured heartbeat interval rather than
        // a hard-coded value, so the membership view reacts on the same clock
        // the rest of the Raft layer uses.
        let interval =
            std::time::Duration::from_millis(self.config.raft.heartbeat_interval_ms.max(1));

        tokio::spawn({
            async move {
                loop {
                    tokio::time::sleep(interval).await;
                    // Health check would go here
                }
            }
        });
    }

    /// Get peer state
    pub fn get_peer(&self, node_id: &NodeId) -> Option<PeerState> {
        self.peers.get(node_id).map(|p| p.clone())
    }

    /// Update peer state
    pub fn update_peer<F>(&self, node_id: &NodeId, f: F)
    where
        F: FnOnce(&mut PeerState),
    {
        if let Some(mut peer) = self.peers.get_mut(node_id) {
            f(&mut peer);
        }
    }

    /// Record heartbeat from peer
    pub fn record_heartbeat(&self, node_id: &NodeId) {
        self.update_peer(node_id, |peer| {
            peer.record_heartbeat();
        });

        // Update connected count
        self.update_connected_count();
    }

    /// Record failed heartbeat
    pub fn record_failure(&self, node_id: &NodeId) {
        let threshold = self.failure_threshold();
        self.update_peer(node_id, |peer| {
            peer.record_failure(threshold);
        });

        // Update connected count
        self.update_connected_count();
    }

    /// Update connected peer count
    fn update_connected_count(&self) {
        let count = self
            .peers
            .iter()
            .filter(|p| p.health == PeerHealth::Healthy)
            .count() as u32;

        self.connected_count.store(count, Ordering::SeqCst);
    }

    /// Get connected peer count
    pub fn connected_peer_count(&self) -> usize {
        self.connected_count.load(Ordering::SeqCst) as usize
    }

    /// Get all peer IDs
    pub fn peer_ids(&self) -> Vec<NodeId> {
        self.peers.iter().map(|p| p.key().clone()).collect()
    }

    /// Get voting peers
    pub fn voting_peers(&self) -> Vec<NodeId> {
        self.peers
            .iter()
            .filter(|p| p.config.voting)
            .map(|p| p.key().clone())
            .collect()
    }

    /// Get healthy peers
    pub fn healthy_peers(&self) -> Vec<NodeId> {
        self.peers
            .iter()
            .filter(|p| p.health == PeerHealth::Healthy)
            .map(|p| p.key().clone())
            .collect()
    }

    /// Check if we have quorum
    pub fn has_quorum(&self) -> bool {
        let voting_count = self.peers.iter().filter(|p| p.config.voting).count();
        let healthy_voting = self
            .peers
            .iter()
            .filter(|p| p.config.voting && p.health == PeerHealth::Healthy)
            .count();

        // Need n/2 + 1 for quorum (including self)
        let quorum_size = voting_count.div_ceil(2) + 1;
        healthy_voting + 1 >= quorum_size // +1 for self
    }

    /// Add a peer
    pub fn add_peer(&self, config: PeerConfig) -> Result<()> {
        if self.peers.contains_key(&config.node_id) {
            return Err(ClusterError::NodeAlreadyExists(config.node_id));
        }

        self.peers
            .insert(config.node_id.clone(), PeerState::new(config));
        Ok(())
    }

    /// Remove a peer
    pub fn remove_peer(&self, node_id: &NodeId) -> Result<()> {
        if self.peers.remove(node_id).is_none() {
            return Err(ClusterError::NodeNotFound(node_id.clone()));
        }

        self.update_connected_count();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_health() {
        let config = PeerConfig {
            node_id: "node-2".to_string(),
            addr: "127.0.0.1:7001".parse().unwrap(),
            voting: true,
        };

        let mut peer = PeerState::new(config);
        assert_eq!(peer.health, PeerHealth::Unknown);

        peer.record_heartbeat();
        assert_eq!(peer.health, PeerHealth::Healthy);

        for _ in 0..3 {
            peer.record_failure(3);
        }
        assert_eq!(peer.health, PeerHealth::Unhealthy);
    }
}
