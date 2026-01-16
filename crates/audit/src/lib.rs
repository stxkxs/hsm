//! # Audit & Logging System
//!
//! A tamper-evident audit logging system using hash chains and Merkle trees
//! to ensure complete auditability of all HSM operations.
//!
//! ## Features
//!
//! - **Tamper-evident logging**: Uses hash chains to detect any modifications
//! - **Merkle tree verification**: Efficient proof of inclusion for events
//! - **High throughput**: Supports 10,000+ operations per second
//! - **Log rotation**: Automatic rotation based on file size
//! - **Structured logging**: JSON format for easy parsing
//! - **Integrity verification**: Built-in verification tools
//!
//! ## Quick Start
//!
//! ```rust
//! use audit::{AuditLogger, AuditConfig, EventType};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a logger
//! let config = AuditConfig::default();
//! let logger = AuditLogger::new(config)?;
//!
//! // Log an event
//! logger.log_success(
//!     EventType::KeyGeneration,
//!     "generate_rsa_key",
//!     "default",
//!     "client_123",
//!     Some("key_456".to_string()),
//! )?;
//!
//! // Verify integrity
//! logger.verify_integrity()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! The audit system consists of several key components:
//!
//! - **AuditEvent**: The basic unit of logging with metadata
//! - **HashChain**: Links events together to detect tampering
//! - **MerkleTree**: Provides efficient verification of event inclusion
//! - **AuditStorage**: Persists events to disk with rotation
//! - **AuditLogger**: Main interface combining all components
//! - **AuditVerifier**: Verifies the integrity of logged events

pub mod async_logger;
pub mod event;
pub mod hash_chain;
pub mod logger;
pub mod merkle_tree;
pub mod storage;
pub mod storage_enhanced;
pub mod tamper_detection;
pub mod verifier;

// Re-export main types for convenience
pub use event::{AuditEvent, AuditEventBuilder, EventType, OperationResult};
pub use hash_chain::{HashChain, HashChainError};
pub use logger::{AuditConfig, AuditError, AuditLogger};
pub use merkle_tree::{MerkleError, MerkleProof, MerkleTree, ProofElement};
pub use storage::{AuditStorage, StorageConfig, StorageError};
pub use verifier::{AuditVerifier, VerificationError, VerificationReport, VerificationResult};

// Re-export enhanced types
pub use async_logger::{AsyncAuditConfig, AsyncAuditError, AsyncAuditLogger};
pub use storage_enhanced::{EnhancedAuditStorage, EnhancedStorageConfig, EnhancedStorageError};
pub use tamper_detection::{IntegrityReport, TamperDetector, Violation};

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_end_to_end() {
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

        // Log various events
        logger
            .log_success(
                EventType::KeyGeneration,
                "generate_key",
                "default",
                "client_1",
                Some("key_123".to_string()),
            )
            .unwrap();

        logger
            .log_success(
                EventType::Sign,
                "sign_data",
                "default",
                "client_1",
                Some("key_123".to_string()),
            )
            .unwrap();

        logger
            .log_failure(
                EventType::Decrypt,
                "decrypt_data",
                "default",
                "client_2",
                None,
                "Unauthorized",
            )
            .unwrap();

        // Verify integrity
        assert!(logger.verify_integrity().is_ok());

        // Get events
        let events = logger.get_events_range(1, 3).unwrap();
        assert_eq!(events.len(), 3);

        // Verify with verifier
        let result = AuditVerifier::verify_events(&events).unwrap();
        assert!(result.passed);

        // Check Merkle root
        let root = logger.get_merkle_root().unwrap();
        assert!(!root.is_empty());
    }

    #[test]
    fn test_tamper_detection() {
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

        // Log events
        for i in 1..=5 {
            logger
                .log_success(
                    EventType::Sign,
                    format!("operation_{}", i),
                    "default",
                    "client_1",
                    None,
                )
                .unwrap();
        }

        // Get events and tamper with one
        let mut events = logger.get_events_range(1, 5).unwrap();
        events[2].operation = "tampered".to_string();

        // Verification should detect the tampering
        let result = AuditVerifier::verify_events(&events).unwrap();
        assert!(!result.passed);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_persistence_and_recovery() {
        let temp_dir = TempDir::new().unwrap();
        let base_dir = temp_dir.path().to_path_buf();

        // Create logger and log events
        {
            let config = AuditConfig {
                storage: StorageConfig {
                    base_dir: base_dir.clone(),
                    ..Default::default()
                },
                enabled: true,
                rebuild_merkle_on_start: false,
            };

            let logger = AuditLogger::new(config).unwrap();

            for i in 1..=10 {
                logger
                    .log_success(
                        EventType::Encrypt,
                        format!("op_{}", i),
                        "default",
                        "client_1",
                        None,
                    )
                    .unwrap();
            }

            logger.flush().unwrap();
        }

        // Recover from storage
        {
            let config = AuditConfig {
                storage: StorageConfig {
                    base_dir: base_dir.clone(),
                    ..Default::default()
                },
                enabled: true,
                rebuild_merkle_on_start: true,
            };

            let logger = AuditLogger::new(config).unwrap();

            assert_eq!(logger.current_sequence(), 10);
            assert!(logger.verify_integrity().is_ok());

            // Continue logging
            logger
                .log_success(EventType::Decrypt, "op_11", "default", "client_1", None)
                .unwrap();

            assert_eq!(logger.current_sequence(), 11);
            assert!(logger.verify_integrity().is_ok());
        }
    }

    #[test]
    fn test_merkle_proof_verification() {
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

        // Log events
        for i in 1..=8 {
            logger
                .log_success(
                    EventType::Sign,
                    format!("op_{}", i),
                    "default",
                    "client_1",
                    None,
                )
                .unwrap();
        }

        // Generate proof for an event
        let event = logger.get_event(5).unwrap();
        let merkle_tree = logger.merkle_tree().read();

        let proof = merkle_tree.generate_proof(&event.current_hash).unwrap();
        assert!(merkle_tree.verify_proof(&proof).unwrap());
    }

    #[test]
    fn test_verification_report() {
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

        // Log events
        for i in 1..=5 {
            logger
                .log_success(
                    EventType::Sign,
                    format!("op_{}", i),
                    "default",
                    "client_1",
                    None,
                )
                .unwrap();
        }

        let events = logger.get_events_range(1, 5).unwrap();
        let report = AuditVerifier::generate_report(&events);

        assert!(report.is_valid());
        assert_eq!(report.total_events, 5);
        assert!(report.all_hashes_valid);
        assert!(report.chain_intact);
        assert!(report.sequences_continuous);

        let summary = report.summary();
        assert!(summary.contains("VALID"));
    }
}
