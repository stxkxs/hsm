//! Request routing for cluster operations

use crate::config::NodeId;
use crate::error::{ClusterError, Result};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Routing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Route to leader (for writes)
    Leader,

    /// Route to any node (for reads with stale tolerance)
    Any,

    /// Route to local node (for reads with leader lease)
    Local,

    /// Route to specific node
    Specific,
}

/// Router for cluster requests
pub struct Router {
    /// Current leader
    leader: RwLock<Option<NodeId>>,

    /// Local node ID
    local_node: NodeId,

    /// Leader lease expiry
    leader_lease_expiry: RwLock<Option<std::time::Instant>>,
}

impl Router {
    /// Create a new router
    pub fn new(local_node: NodeId) -> Self {
        Self {
            leader: RwLock::new(None),
            local_node,
            leader_lease_expiry: RwLock::new(None),
        }
    }

    /// Set the current leader
    pub async fn set_leader(&self, leader: Option<NodeId>) {
        *self.leader.write().await = leader;
    }

    /// Get the current leader
    pub async fn get_leader(&self) -> Option<NodeId> {
        self.leader.read().await.clone()
    }

    /// Check if this node is the leader
    pub async fn is_leader(&self) -> bool {
        let leader = self.leader.read().await;
        leader.as_ref() == Some(&self.local_node)
    }

    /// Update leader lease
    pub async fn update_lease(&self, duration: std::time::Duration) {
        let expiry = std::time::Instant::now() + duration;
        *self.leader_lease_expiry.write().await = Some(expiry);
    }

    /// Check if leader lease is valid
    pub async fn lease_valid(&self) -> bool {
        if let Some(expiry) = *self.leader_lease_expiry.read().await {
            std::time::Instant::now() < expiry
        } else {
            false
        }
    }

    /// Route a request based on strategy
    pub async fn route(&self, strategy: RoutingStrategy) -> Result<NodeId> {
        match strategy {
            RoutingStrategy::Leader => {
                let leader = self.get_leader().await;
                leader.ok_or(ClusterError::NoLeader)
            }

            RoutingStrategy::Any => {
                // For now, just return local node
                // In production, would round-robin or load-balance
                Ok(self.local_node.clone())
            }

            RoutingStrategy::Local => {
                // Check if we can serve locally
                if self.is_leader().await || self.lease_valid().await {
                    Ok(self.local_node.clone())
                } else {
                    // Forward to leader
                    let leader = self.get_leader().await;
                    leader.ok_or(ClusterError::NoLeader)
                }
            }

            RoutingStrategy::Specific => {
                // Caller should provide the node ID
                Err(ClusterError::Configuration(
                    "Specific routing requires node ID".to_string(),
                ))
            }
        }
    }

    /// Forward a request to the leader
    pub async fn forward_to_leader<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(NodeId) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send>>,
    {
        let leader = self.get_leader().await.ok_or(ClusterError::NoLeader)?;

        if leader == self.local_node {
            return Err(ClusterError::Internal("Cannot forward to self".to_string()));
        }

        f(leader).await
    }
}

/// Request type for routing decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    /// Read request (can be served by followers with stale tolerance)
    Read,

    /// Write request (must go to leader)
    Write,

    /// Strong read (must have leader lease or go to leader)
    StrongRead,
}

impl RequestType {
    /// Get the default routing strategy for this request type
    pub fn default_strategy(&self) -> RoutingStrategy {
        match self {
            Self::Read => RoutingStrategy::Any,
            Self::Write => RoutingStrategy::Leader,
            Self::StrongRead => RoutingStrategy::Local,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_router_leader() {
        let router = Router::new("node-1".to_string());

        // No leader initially
        assert!(router.get_leader().await.is_none());

        // Set leader
        router.set_leader(Some("node-2".to_string())).await;
        assert_eq!(router.get_leader().await, Some("node-2".to_string()));

        // Check is_leader
        assert!(!router.is_leader().await);

        // Set self as leader
        router.set_leader(Some("node-1".to_string())).await;
        assert!(router.is_leader().await);
    }

    #[tokio::test]
    async fn test_routing_strategies() {
        let router = Router::new("node-1".to_string());
        router.set_leader(Some("node-2".to_string())).await;

        // Leader routing
        let result = router.route(RoutingStrategy::Leader).await;
        assert_eq!(result.unwrap(), "node-2");

        // Any routing returns local
        let result = router.route(RoutingStrategy::Any).await;
        assert_eq!(result.unwrap(), "node-1");
    }
}
