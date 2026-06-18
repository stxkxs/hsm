#![deny(unsafe_code)]
//! HSM Cluster Module
//!
//! Provides high availability clustering for HSM using Raft consensus.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Load Balancer                            │
//! │                  (health-aware routing)                     │
//! └─────────────────┬───────────────────┬──────────────────────┘
//!                   │                   │
//!          ┌────────▼────────┐ ┌────────▼────────┐
//!          │   HSM Node 1    │ │   HSM Node 2    │  ...
//!          │   (Leader)      │ │   (Follower)    │
//!          │                 │ │                 │
//!          │  ┌───────────┐  │ │  ┌───────────┐  │
//!          │  │ Key Store │◄─┼─┼──│ Key Store │  │
//!          │  └───────────┘  │ │  └───────────┘  │
//!          │        │        │ │        ▲        │
//!          │        ▼        │ │        │        │
//!          │  ┌───────────┐  │ │  ┌───────────┐  │
//!          │  │  Raft Log │──┼─┼─►│  Raft Log │  │
//!          │  └───────────┘  │ │  └───────────┘  │
//!          └─────────────────┘ └─────────────────┘
//! ```
//!
//! # Features
//!
//! - Raft-based consensus for leader election and log replication
//! - Key replication across nodes
//! - Session replication for failover without re-authentication
//! - Anti-double-signing protection in cluster mode
//! - Automatic failover with <5 second recovery

pub mod config;
pub mod consensus;
pub mod error;
pub mod membership;
pub mod node;
pub mod replication;
pub mod routing;
pub mod transport;

pub use config::{ClusterConfig, NodeId, RaftConfig, ReplicationConfig};
pub use error::{ClusterError, Result};
pub use node::{ClusterNode, ClusterState};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
