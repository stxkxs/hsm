//! Key and session replication

use crate::config::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Replication target
#[derive(Debug, Clone)]
pub struct ReplicationTarget {
    /// Target node ID
    pub node_id: NodeId,

    /// Target address
    pub address: String,

    /// Match index (last replicated)
    pub match_index: u64,

    /// Next index to send
    pub next_index: u64,
}

/// Replication manager
pub struct ReplicationManager {
    /// Replication targets
    targets: HashMap<NodeId, ReplicationTarget>,

    /// Pending entries
    pending: Vec<ReplicationEntry>,
}

impl ReplicationManager {
    /// Create a new replication manager
    pub fn new() -> Self {
        Self {
            targets: HashMap::new(),
            pending: Vec::new(),
        }
    }

    /// Add a replication target
    pub fn add_target(&mut self, node_id: NodeId, address: String) {
        self.targets.insert(
            node_id.clone(),
            ReplicationTarget {
                node_id,
                address,
                match_index: 0,
                next_index: 1,
            },
        );
    }

    /// Remove a replication target
    pub fn remove_target(&mut self, node_id: &NodeId) {
        self.targets.remove(node_id);
    }

    /// Queue an entry for replication
    pub fn queue(&mut self, entry: ReplicationEntry) {
        self.pending.push(entry);
    }

    /// Get entries to replicate to a target
    pub fn entries_for(&self, node_id: &NodeId) -> Vec<&ReplicationEntry> {
        if let Some(target) = self.targets.get(node_id) {
            self.pending
                .iter()
                .filter(|e| e.index >= target.next_index)
                .collect()
        } else {
            vec![]
        }
    }

    /// Mark entries as replicated
    pub fn mark_replicated(&mut self, node_id: &NodeId, match_index: u64) {
        if let Some(target) = self.targets.get_mut(node_id) {
            target.match_index = match_index;
            target.next_index = match_index + 1;
        }
    }

    /// Check if entry is replicated to quorum
    pub fn is_replicated(&self, index: u64, quorum_size: usize) -> bool {
        let count = self
            .targets
            .values()
            .filter(|t| t.match_index >= index)
            .count();

        // +1 for leader
        count + 1 >= quorum_size
    }
}

impl Default for ReplicationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Entry to replicate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationEntry {
    /// Entry index
    pub index: u64,

    /// Entry type
    pub entry_type: EntryType,

    /// Entry data (encrypted for keys)
    pub data: Vec<u8>,
}

/// Entry type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntryType {
    /// Key storage
    Key,

    /// Session storage
    Session,

    /// Audit log entry
    Audit,

    /// Signing record (anti-double-sign)
    SigningRecord,

    /// Configuration change
    Config,
}

/// Key replication data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyReplicationData {
    /// Key ID
    pub key_id: String,

    /// Encrypted key material
    pub encrypted_key: Vec<u8>,

    /// Key metadata
    pub metadata: KeyMetadata,
}

/// Key metadata for replication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Algorithm
    pub algorithm: String,

    /// Creation time
    pub created_at: i64,

    /// Namespace
    pub namespace: String,

    /// Labels
    pub labels: HashMap<String, String>,
}

/// Session replication data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReplicationData {
    /// Session ID
    pub session_id: String,

    /// Client identity
    pub identity: SessionIdentity,

    /// Expiration time
    pub expires_at: i64,

    /// Token hash
    pub token_hash: Vec<u8>,
}

/// Session identity for replication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIdentity {
    /// Common name
    pub common_name: String,

    /// Organization
    pub organization: Option<String>,

    /// Namespace
    pub namespace: String,

    /// Roles
    pub roles: Vec<String>,
}

/// Signing record for anti-double-signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRecord {
    /// Key ID
    pub key_id: String,

    /// Message hash
    pub message_hash: Vec<u8>,

    /// Signing time
    pub signed_at: i64,

    /// Additional context (e.g., slot for validators)
    pub context: SigningContext,
}

/// Signing context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningContext {
    /// Generic signing
    Generic,

    /// Ethereum validator attestation
    EthereumAttestation {
        source_epoch: u64,
        target_epoch: u64,
    },

    /// Ethereum block proposal
    EthereumBlock { slot: u64 },

    /// Babylon EOTS
    BabylonEots { height: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replication_manager() {
        let mut manager = ReplicationManager::new();
        manager.add_target("node-2".to_string(), "127.0.0.1:7001".to_string());

        let entry = ReplicationEntry {
            index: 1,
            entry_type: EntryType::Key,
            data: vec![1, 2, 3],
        };

        manager.queue(entry);

        let entries = manager.entries_for(&"node-2".to_string());
        assert_eq!(entries.len(), 1);

        manager.mark_replicated(&"node-2".to_string(), 1);
        assert!(manager.is_replicated(1, 2));
    }
}
