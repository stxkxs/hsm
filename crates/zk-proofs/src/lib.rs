#![deny(unsafe_code)]
// Allow some clippy warnings for the experimental ZK proofs module
// These can be cleaned up in a future refactoring pass
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::get_first)]

//! # Zero-Knowledge Audit Proofs
//!
//! Privacy-preserving audit verification using ZK-SNARKs and Lasso lookup optimization.
//!
//! This crate implements zero-knowledge proofs for audit log verification, allowing
//! external auditors to verify log integrity without revealing sensitive event details.
//!
//! ## Features
//!
//! - **Lasso Lookup Argument**: 10-40x speedup for lookup-based operations
//! - **Merkle Tree Proofs**: Efficient proof of inclusion for audit events
//! - **Event Existence Proofs**: Prove an event exists without revealing details
//! - **Privacy-Preserving**: Hide event details, client ID, key ID (reveal only sequence, type)
//! - **Succinct Proofs**: < 1KB constant-size proofs
//! - **Fast Verification**: < 10ms verification time
//!
//! ## Architecture
//!
//! The ZK proof system consists of:
//!
//! - **Lasso**: Lookup argument for efficient table-based operations
//! - **MerkleProofCircuit**: Proves Merkle root is correctly computed
//! - **EventExistenceCircuit**: Proves event exists in log without revealing details
//! - **ProofSystem**: Main interface for proof generation and verification
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use hsm_zk_proofs::{ProofSystem, MerkleProofRequest};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize proof system
//! let mut proof_system = ProofSystem::new()?;
//!
//! // Generate proof for Merkle tree integrity
//! let leaf_hashes = vec![[0u8; 32]]; // Your audit event hashes
//! let expected_root = [0u8; 32]; // Expected Merkle root
//! let request = MerkleProofRequest {
//!     leaf_hashes,
//!     expected_root,
//! };
//! let (proof, _metrics) = proof_system.prove_merkle_integrity(&request)?;
//!
//! // Verify proof
//! let valid = proof_system.verify_merkle_proof(&proof)?;
//! assert!(valid);
//! # Ok(())
//! # }
//! ```

pub mod circuits;
pub mod event_proof;
pub mod lasso;
pub mod merkle_proof;
pub mod proof_system;

// Re-export main types
pub use circuits::{EventExistenceCircuit, MerkleProofCircuit};
pub use event_proof::{EventExistenceProof, EventProofRequest};
pub use lasso::{LassoProof, LookupArgument, LookupTable};
pub use merkle_proof::{MerkleProofRequest, MerkleTreeProof};
pub use proof_system::{ProofSystem, ZkProofError, ZkProofResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_system_initialization() {
        let proof_system = ProofSystem::new();
        assert!(proof_system.is_ok());
    }
}
