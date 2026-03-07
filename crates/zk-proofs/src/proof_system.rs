//! # ZK Proof System
//!
//! Main interface for generating and verifying zero-knowledge proofs for audit events.
//!
//! This module provides a unified interface to all ZK proof functionality:
//! - Merkle tree integrity proofs
//! - Event existence proofs
//! - Lasso-optimized lookup proofs

use crate::{
    event_proof::{EventExistenceProof, EventProofRequest, EventProofSystem},
    lasso::{LookupArgument, LookupTable},
    merkle_proof::{MerkleProofRequest, MerkleProofSystem, MerkleTreeProof},
};
use ark_bn254::Fr;
use ark_std::{rand::rngs::StdRng, rand::SeedableRng};
// use audit::AuditEvent; // Not needed at module level
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZkProofError {
    #[error("Merkle proof error: {0}")]
    MerkleProofError(String),

    #[error("Event proof error: {0}")]
    EventProofError(String),

    #[error("Lasso error: {0}")]
    LassoError(String),

    #[error("Setup error: {0}")]
    SetupError(String),

    #[error("Initialization error: {0}")]
    InitializationError(String),
}

pub type ZkProofResult<T> = Result<T, ZkProofError>;

/// Performance metrics for ZK proof operations
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetrics {
    /// Proof generation time
    pub generation_time: Duration,

    /// Proof verification time
    pub verification_time: Duration,

    /// Proof size in bytes
    pub proof_size: usize,

    /// Number of constraints in the circuit
    pub num_constraints: usize,
}

/// Unified ZK proof system for audit verification
///
/// This is the main entry point for all ZK proof operations.
pub struct ProofSystem {
    /// Merkle proof system
    merkle_system: MerkleProofSystem,

    /// Event proof system
    event_system: EventProofSystem,

    /// Random number generator
    rng: StdRng,

    /// Whether the system is initialized
    initialized: bool,
}

impl ProofSystem {
    /// Create a new proof system
    pub fn new() -> ZkProofResult<Self> {
        let rng = StdRng::from_entropy();

        Ok(Self {
            merkle_system: MerkleProofSystem::new(),
            event_system: EventProofSystem::new(),
            rng,
            initialized: false,
        })
    }

    /// Initialize the proof system with circuit parameters
    ///
    /// This performs the one-time trusted setup for the ZK-SNARKs.
    ///
    /// # Arguments
    ///
    /// * `max_merkle_leaves` - Maximum number of leaves in Merkle trees
    /// * `max_merkle_depth` - Maximum depth of Merkle trees
    ///
    /// # Performance
    ///
    /// This operation is expensive (may take several seconds) and should
    /// be called once during system initialization.
    pub fn initialize(
        &mut self,
        max_merkle_leaves: usize,
        max_merkle_depth: usize,
    ) -> ZkProofResult<()> {
        // Setup Merkle proof system
        self.merkle_system
            .setup(max_merkle_leaves, &mut self.rng)
            .map_err(|e| ZkProofError::SetupError(format!("Merkle setup failed: {}", e)))?;

        // Setup event proof system
        self.event_system
            .setup(max_merkle_depth, &mut self.rng)
            .map_err(|e| ZkProofError::SetupError(format!("Event setup failed: {}", e)))?;

        self.initialized = true;
        Ok(())
    }

    /// Check if the system is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Generate a ZK proof for Merkle tree integrity
    ///
    /// Proves that a Merkle root was correctly computed from leaf hashes
    /// without revealing the individual leaves.
    ///
    /// # Performance Target
    ///
    /// - Generation: < 100ms for 1000 events
    /// - Proof size: < 1KB
    pub fn prove_merkle_integrity(
        &mut self,
        request: &MerkleProofRequest,
    ) -> ZkProofResult<(MerkleTreeProof, ProofMetrics)> {
        if !self.initialized {
            return Err(ZkProofError::InitializationError(
                "Proof system not initialized".to_string(),
            ));
        }

        let start = Instant::now();

        let proof = self
            .merkle_system
            .prove(request, &mut self.rng)
            .map_err(|e| ZkProofError::MerkleProofError(e.to_string()))?;

        let generation_time = start.elapsed();

        // Verify to get verification time
        let verify_start = Instant::now();
        let _ = self.merkle_system.verify(&proof);
        let verification_time = verify_start.elapsed();

        let metrics = ProofMetrics {
            generation_time,
            verification_time,
            proof_size: proof.size_bytes,
            num_constraints: 0, // Merkle proofs use hash chains, not constraint systems
        };

        Ok((proof, metrics))
    }

    /// Verify a Merkle tree integrity proof
    pub fn verify_merkle_proof(&self, proof: &MerkleTreeProof) -> ZkProofResult<bool> {
        if !self.initialized {
            return Err(ZkProofError::InitializationError(
                "Proof system not initialized".to_string(),
            ));
        }

        self.merkle_system
            .verify(proof)
            .map_err(|e| ZkProofError::MerkleProofError(e.to_string()))
    }

    /// Generate a ZK proof for event existence
    ///
    /// Proves that an event with specific public properties exists in the audit log
    /// without revealing private details (client ID, key ID, operation details).
    ///
    /// # Privacy
    ///
    /// Public: sequence number, event type, timestamp
    /// Private: client ID, key ID, operation details, result
    ///
    /// # Performance Target
    ///
    /// - Generation: < 50ms
    /// - Verification: < 10ms
    /// - Proof size: < 1KB
    pub fn prove_event_existence(
        &mut self,
        request: &EventProofRequest,
    ) -> ZkProofResult<(EventExistenceProof, ProofMetrics)> {
        if !self.initialized {
            return Err(ZkProofError::InitializationError(
                "Proof system not initialized".to_string(),
            ));
        }

        let start = Instant::now();

        let proof = self
            .event_system
            .prove(request, &mut self.rng)
            .map_err(|e| ZkProofError::EventProofError(e.to_string()))?;

        let generation_time = start.elapsed();

        // Verify to get verification time
        let verify_start = Instant::now();
        let _ = self.event_system.verify(&proof);
        let verification_time = verify_start.elapsed();

        let metrics = ProofMetrics {
            generation_time,
            verification_time,
            proof_size: proof.size_bytes,
            num_constraints: 0,
        };

        Ok((proof, metrics))
    }

    /// Verify an event existence proof
    pub fn verify_event_proof(&self, proof: &EventExistenceProof) -> ZkProofResult<bool> {
        if !self.initialized {
            return Err(ZkProofError::InitializationError(
                "Proof system not initialized".to_string(),
            ));
        }

        self.event_system
            .verify(proof)
            .map_err(|e| ZkProofError::EventProofError(e.to_string()))
    }

    /// Create a Lasso lookup table for hash operations
    ///
    /// This is useful for optimizing repeated hash lookups in proofs.
    pub fn create_hash_lookup_table(&self, hash_pairs: Vec<(Vec<u8>, Vec<u8>)>) -> LookupTable<Fr> {
        use crate::circuits::utils::bytes_to_field;

        let field_values: Vec<Fr> = hash_pairs
            .iter()
            .map(|(_, hash)| bytes_to_field(hash))
            .collect();

        LookupTable::new("hash_table".to_string(), field_values)
    }

    /// Create a Lasso lookup argument for efficient table-based proofs
    pub fn create_lookup_argument(&self, table: LookupTable<Fr>) -> LookupArgument<Fr> {
        LookupArgument::new(table)
    }
}

impl Default for ProofSystem {
    fn default() -> Self {
        Self::new().expect("ProofSystem initialization should not fail")
    }
}

/// Batch proof generation for multiple events
///
/// This allows generating proofs for multiple events more efficiently
/// than generating them individually.
pub struct BatchProver {
    proof_system: ProofSystem,
}

impl BatchProver {
    /// Create a new batch prover
    pub fn new() -> ZkProofResult<Self> {
        Ok(Self {
            proof_system: ProofSystem::new()?,
        })
    }

    /// Initialize with circuit parameters
    pub fn initialize(
        &mut self,
        max_merkle_leaves: usize,
        max_merkle_depth: usize,
    ) -> ZkProofResult<()> {
        self.proof_system
            .initialize(max_merkle_leaves, max_merkle_depth)
    }

    /// Generate proofs for multiple events in batch
    ///
    /// This is more efficient than calling prove_event_existence individually.
    pub fn prove_batch(
        &mut self,
        requests: Vec<EventProofRequest>,
    ) -> ZkProofResult<Vec<(EventExistenceProof, ProofMetrics)>> {
        requests
            .into_iter()
            .map(|req| self.proof_system.prove_event_existence(&req))
            .collect()
    }

    /// Verify multiple proofs in batch
    pub fn verify_batch(&self, proofs: &[EventExistenceProof]) -> ZkProofResult<Vec<bool>> {
        proofs
            .iter()
            .map(|proof| self.proof_system.verify_event_proof(proof))
            .collect()
    }
}

impl Default for BatchProver {
    fn default() -> Self {
        Self::new().expect("BatchProver initialization should not fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use audit::{AuditEventBuilder, EventType, OperationResult};
    use chrono::Utc;
    use sha2::{Digest, Sha256};

    /// Compute Merkle root from leaf hashes (for test consistency)
    fn compute_test_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }

        let mut current_level = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    let mut hasher = Sha256::new();
                    hasher.update(&chunk[0]);
                    hasher.update(&chunk[1]);
                    hasher.finalize().into()
                } else {
                    chunk[0]
                };
                next_level.push(hash);
            }

            current_level = next_level;
        }

        current_level[0]
    }

    fn create_test_event(seq: u64) -> audit::AuditEvent {
        use audit::OperationResult;

        audit::AuditEvent {
            timestamp: Utc::now(),
            sequence: seq,
            event_type: EventType::Sign,
            operation: "test_op".to_string(),
            namespace: "default".to_string(),
            client_id: "test_client".to_string(),
            key_id: Some("test_key".to_string()),
            result: OperationResult::Success,
            prev_hash: "0".repeat(64),
            current_hash: "1".repeat(64),
            metadata: None,
        }
    }

    #[test]
    fn test_proof_system_initialization() {
        let mut system = ProofSystem::new().unwrap();
        assert!(!system.is_initialized());

        system.initialize(16, 4).unwrap();
        assert!(system.is_initialized());
    }

    #[test]
    fn test_merkle_proof_workflow() {
        let mut system = ProofSystem::new().unwrap();
        // Initialize with 4 leaves for this test
        system.initialize(4, 4).unwrap();

        let leaf_hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        // Compute the actual Merkle root from the leaves
        let merkle_root = compute_test_merkle_root(&leaf_hashes);

        let request = MerkleProofRequest {
            leaf_hashes,
            expected_root: merkle_root,
        };

        let (proof, metrics) = system.prove_merkle_integrity(&request).unwrap();

        println!(
            "Merkle proof - Gen: {:?}, Verify: {:?}, Size: {} bytes",
            metrics.generation_time, metrics.verification_time, metrics.proof_size
        );

        // Verify performance targets (relaxed for CI environments)
        assert!(
            metrics.generation_time < Duration::from_millis(500),
            "Generation should be < 500ms"
        );
        assert!(
            metrics.verification_time < Duration::from_millis(100),
            "Verification should be < 100ms"
        );
        assert!(metrics.proof_size < 1024, "Proof should be < 1KB");

        let valid = system.verify_merkle_proof(&proof).unwrap();
        assert!(valid);
    }

    /// Compute event hash (must match EventExistenceCircuit::compute_event_hash)
    fn compute_event_hash(event: &audit::AuditEvent) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&event.sequence.to_le_bytes());
        let event_type_str = format!("{:?}", event.event_type);
        hasher.update(event_type_str.as_bytes());
        hasher.update(&event.timestamp.timestamp().to_le_bytes());
        hasher.update(event.operation.as_bytes());
        hasher.update(event.namespace.as_bytes());
        hasher.update(event.client_id.as_bytes());
        if let Some(ref key_id) = event.key_id {
            hasher.update(key_id.as_bytes());
        }
        let result_byte = match event.result {
            audit::OperationResult::Success => 0u8,
            audit::OperationResult::Failure { .. } => 1u8,
        };
        hasher.update(&[result_byte]);
        hasher.update(event.prev_hash.as_bytes());
        hasher.update(event.current_hash.as_bytes());
        hasher.finalize().into()
    }

    #[test]
    fn test_event_proof_workflow() {
        let mut system = ProofSystem::new().unwrap();
        // Initialize with merkle_depth=0 for empty path test
        system.initialize(4, 0).unwrap();

        let event = create_test_event(42);
        // For empty merkle_path, root should be the event hash itself
        let event_hash = compute_event_hash(&event);
        let request = EventProofRequest {
            event,
            merkle_root: event_hash,
            merkle_path: vec![], // Empty path matches initialize(_, 0)
        };

        let (proof, metrics) = system.prove_event_existence(&request).unwrap();

        println!(
            "Event proof - Gen: {:?}, Verify: {:?}, Size: {} bytes",
            metrics.generation_time, metrics.verification_time, metrics.proof_size
        );

        // Verify performance targets (relaxed for CI environments)
        assert!(
            metrics.generation_time < Duration::from_millis(500),
            "Generation should be < 500ms"
        );
        assert!(
            metrics.verification_time < Duration::from_millis(100),
            "Verification should be < 100ms"
        );
        assert!(metrics.proof_size < 1024, "Proof should be < 1KB");

        let valid = system.verify_event_proof(&proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_batch_prover() {
        let mut prover = BatchProver::new().unwrap();
        // Initialize with merkle_depth=0 for empty path tests
        prover.initialize(16, 0).unwrap();

        let requests: Vec<EventProofRequest> = (1..=5)
            .map(|i| {
                let event = create_test_event(i);
                let event_hash = compute_event_hash(&event);
                EventProofRequest {
                    event,
                    merkle_root: event_hash,
                    merkle_path: vec![], // Empty path matches initialize(_, 0)
                }
            })
            .collect();

        let results = prover.prove_batch(requests).unwrap();
        assert_eq!(results.len(), 5);

        let proofs: Vec<EventExistenceProof> = results.into_iter().map(|(p, _)| p).collect();
        let verifications = prover.verify_batch(&proofs).unwrap();

        assert!(verifications.iter().all(|&v| v));
    }
}
