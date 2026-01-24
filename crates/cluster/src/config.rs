//! Cluster configuration

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// Node identifier
pub type NodeId = String;

/// Cluster configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// This node's identifier
    pub node_id: NodeId,

    /// Address to bind for cluster communication
    pub bind_addr: SocketAddr,

    /// Peer node configurations
    pub peers: Vec<PeerConfig>,

    /// Raft consensus configuration
    pub raft: RaftConfig,

    /// Replication configuration
    pub replication: ReplicationConfig,

    /// Transport security configuration
    pub transport: TransportConfig,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: "node-1".to_string(),
            bind_addr: "0.0.0.0:7000".parse().unwrap(),
            peers: vec![],
            raft: RaftConfig::default(),
            replication: ReplicationConfig::default(),
            transport: TransportConfig::default(),
        }
    }
}

/// Peer node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Peer node ID
    pub node_id: NodeId,

    /// Peer address
    pub addr: SocketAddr,

    /// Whether this peer is a voting member
    pub voting: bool,
}

/// Raft consensus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftConfig {
    /// Election timeout (minimum)
    pub election_timeout_min_ms: u64,

    /// Election timeout (maximum)
    pub election_timeout_max_ms: u64,

    /// Heartbeat interval
    pub heartbeat_interval_ms: u64,

    /// Number of entries before taking a snapshot
    pub snapshot_threshold: u64,

    /// Maximum entries per append request
    pub max_entries_per_append: u64,

    /// Pre-vote extension (prevents disruption from partitioned nodes)
    pub pre_vote: bool,

    /// Leader lease duration (for fast reads)
    pub leader_lease_ms: u64,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            election_timeout_min_ms: 150,
            election_timeout_max_ms: 300,
            heartbeat_interval_ms: 50,
            snapshot_threshold: 10000,
            max_entries_per_append: 100,
            pre_vote: true,
            leader_lease_ms: 100,
        }
    }
}

impl RaftConfig {
    /// Get election timeout as Duration (randomized between min and max)
    pub fn election_timeout(&self) -> Duration {
        use rand::Rng;
        let ms = rand::thread_rng()
            .gen_range(self.election_timeout_min_ms..=self.election_timeout_max_ms);
        Duration::from_millis(ms)
    }

    /// Get heartbeat interval as Duration
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_millis(self.heartbeat_interval_ms)
    }

    /// Get leader lease as Duration
    pub fn leader_lease(&self) -> Duration {
        Duration::from_millis(self.leader_lease_ms)
    }
}

/// Replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Maximum replication lag before raising alert
    pub max_lag_ms: u64,

    /// Sync write (wait for quorum before returning)
    pub sync_writes: bool,

    /// Batch size for replication
    pub batch_size: usize,

    /// Replication retry interval
    pub retry_interval_ms: u64,

    /// Maximum retries for replication
    pub max_retries: u32,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            max_lag_ms: 100,
            sync_writes: true,
            batch_size: 100,
            retry_interval_ms: 50,
            max_retries: 3,
        }
    }
}

/// Transport security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Enable TLS for cluster transport
    pub tls_enabled: bool,

    /// Path to TLS certificate
    pub tls_cert_path: Option<String>,

    /// Path to TLS private key
    pub tls_key_path: Option<String>,

    /// Path to CA certificate for peer verification
    pub tls_ca_path: Option<String>,

    /// Enable encryption for sensitive data in transit
    pub encrypt_sensitive: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            tls_enabled: true,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
            encrypt_sensitive: true,
        }
    }
}

/// Cluster membership configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipConfig {
    /// Minimum number of nodes for quorum
    pub min_nodes: usize,

    /// Health check interval
    pub health_check_interval_ms: u64,

    /// Node considered unhealthy after this many missed heartbeats
    pub unhealthy_threshold: u32,

    /// Node discovery method
    pub discovery: DiscoveryMethod,
}

impl Default for MembershipConfig {
    fn default() -> Self {
        Self {
            min_nodes: 3,
            health_check_interval_ms: 1000,
            unhealthy_threshold: 3,
            discovery: DiscoveryMethod::Static,
        }
    }
}

/// Node discovery method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// Static peer list
    Static,

    /// DNS-based discovery
    Dns { domain: String },

    /// Kubernetes service discovery
    Kubernetes { namespace: String, service: String },

    /// Consul service discovery
    Consul {
        address: String,
        service_name: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClusterConfig::default();
        assert_eq!(config.node_id, "node-1");
        assert!(config.raft.pre_vote);
    }

    #[test]
    fn test_election_timeout() {
        let raft = RaftConfig::default();
        let timeout = raft.election_timeout();
        assert!(timeout.as_millis() >= 150);
        assert!(timeout.as_millis() <= 300);
    }
}
