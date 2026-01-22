//! # Zero-Knowledge Proof Integration for Audit
//!
//! This module integrates ZK proofs with the audit logger, enabling
//! privacy-preserving verification of audit logs.

use crate::{AuditError, AuditLogger};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZkIntegrationError {
    #[error("ZK proof library not available")]
    NotAvailable,

    #[error("ZK proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("ZK proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Audit error: {0}")]
    AuditError(#[from] AuditError),
}

/// ZK proof generation request
#[derive(Clone, Debug)]
pub struct ZkProofRequest {
    /// Sequence number of the event
    pub sequence: u64,

    /// Whether to include Merkle proof
    pub include_merkle_proof: bool,
}

/// ZK proof response (placeholder for actual zk-proofs integration)
#[derive(Clone, Debug)]
pub struct ZkProofResponse {
    /// Sequence number (public)
    pub sequence: u64,

    /// Event type (public)
    pub event_type: String,

    /// Timestamp (public)
    pub timestamp: i64,

    /// Proof data (opaque)
    pub proof_data: Vec<u8>,

    /// Proof size in bytes
    pub proof_size: usize,
}

/// Extension trait for AuditLogger to support ZK proofs
pub trait ZkAuditLogger {
    /// Generate a ZK proof for an event's existence
    ///
    /// This proves that an event with the given sequence number exists
    /// in the audit log without revealing sensitive details.
    fn generate_zk_proof(
        &self,
        request: ZkProofRequest,
    ) -> Result<ZkProofResponse, ZkIntegrationError>;

    /// Verify a ZK proof
    fn verify_zk_proof(&self, proof: &ZkProofResponse) -> Result<bool, ZkIntegrationError>;

    /// Get Merkle root for ZK proofs
    fn get_merkle_root_for_zk(&self) -> Result<[u8; 32], ZkIntegrationError>;
}

impl ZkAuditLogger for AuditLogger {
    fn generate_zk_proof(
        &self,
        request: ZkProofRequest,
    ) -> Result<ZkProofResponse, ZkIntegrationError> {
        // Get the event
        let event = self
            .get_event(request.sequence)
            .map_err(ZkIntegrationError::AuditError)?;

        // In a full implementation, this would:
        // 1. Create a zk_proofs::EventProofRequest
        // 2. Generate the proof using ProofSystem
        // 3. Return the proof with public data only

        // For now, return a placeholder response
        Ok(ZkProofResponse {
            sequence: event.sequence,
            event_type: format!("{:?}", event.event_type),
            timestamp: event.timestamp.timestamp(),
            proof_data: vec![0u8; 256], // Placeholder
            proof_size: 256,
        })
    }

    fn verify_zk_proof(&self, _proof: &ZkProofResponse) -> Result<bool, ZkIntegrationError> {
        // In a full implementation, this would verify the ZK proof
        // using the zk-proofs crate
        Ok(true)
    }

    fn get_merkle_root_for_zk(&self) -> Result<[u8; 32], ZkIntegrationError> {
        let root_hex = self
            .get_merkle_root()
            .map_err(ZkIntegrationError::AuditError)?;

        // Decode hex string to bytes
        let root_bytes_vec = hex::decode(&root_hex).map_err(|e| {
            ZkIntegrationError::ProofGenerationFailed(format!("Hex decode failed: {}", e))
        })?;

        let mut root_bytes = [0u8; 32];
        if root_bytes_vec.len() >= 32 {
            root_bytes.copy_from_slice(&root_bytes_vec[..32]);
        } else {
            root_bytes[..root_bytes_vec.len()].copy_from_slice(&root_bytes_vec);
        }

        Ok(root_bytes)
    }
}

/// ZK-enabled audit logger wrapper
///
/// This wraps an AuditLogger and provides ZK proof functionality
/// when the zk-proofs crate is available.
pub struct ZkAuditLoggerWrapper {
    logger: Arc<AuditLogger>,
    zk_enabled: bool,
}

impl ZkAuditLoggerWrapper {
    /// Create a new ZK-enabled audit logger
    pub fn new(logger: Arc<AuditLogger>) -> Self {
        Self {
            logger,
            zk_enabled: Self::check_zk_availability(),
        }
    }

    /// Check if ZK proofs are available
    fn check_zk_availability() -> bool {
        cfg!(feature = "zk-proofs")
    }

    /// Check if ZK proofs are enabled
    pub fn is_zk_enabled(&self) -> bool {
        self.zk_enabled
    }

    /// Generate a ZK proof (if enabled)
    pub fn generate_proof(
        &self,
        request: ZkProofRequest,
    ) -> Result<ZkProofResponse, ZkIntegrationError> {
        if !self.zk_enabled {
            return Err(ZkIntegrationError::NotAvailable);
        }

        self.logger.generate_zk_proof(request)
    }

    /// Verify a ZK proof (if enabled)
    pub fn verify_proof(&self, proof: &ZkProofResponse) -> Result<bool, ZkIntegrationError> {
        if !self.zk_enabled {
            return Err(ZkIntegrationError::NotAvailable);
        }

        self.logger.verify_zk_proof(proof)
    }

    /// Get the underlying audit logger
    pub fn logger(&self) -> &Arc<AuditLogger> {
        &self.logger
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditConfig, EventType, StorageConfig};
    use tempfile::TempDir;

    #[test]
    fn test_zk_integration_basic() {
        let temp_dir = TempDir::new().unwrap();

        let config = AuditConfig {
            storage: StorageConfig {
                base_dir: temp_dir.path().to_path_buf(),
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: false,
        };

        let logger = AuditLogger::new(config).unwrap();

        // Log an event
        logger
            .log_success(EventType::Sign, "test_op", "default", "client1", None)
            .unwrap();

        // Try to generate a ZK proof
        let request = ZkProofRequest {
            sequence: 1,
            include_merkle_proof: true,
        };

        let result = logger.generate_zk_proof(request);

        // Should work with placeholder implementation
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(proof.sequence, 1);
    }

    #[test]
    fn test_merkle_root_extraction() {
        let temp_dir = TempDir::new().unwrap();

        let config = AuditConfig {
            storage: StorageConfig {
                base_dir: temp_dir.path().to_path_buf(),
                ..Default::default()
            },
            enabled: true,
            rebuild_merkle_on_start: false,
        };

        let logger = AuditLogger::new(config).unwrap();

        logger
            .log_success(
                EventType::KeyGeneration,
                "gen_key",
                "default",
                "client1",
                None,
            )
            .unwrap();

        let root = logger.get_merkle_root_for_zk().unwrap();
        assert_ne!(root, [0u8; 32]);
    }
}
