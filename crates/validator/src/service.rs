//! Validator Service
//!
//! This module provides a high-level service for managing multiple validators
//! with anti-slashing protection.
//!
//! # Features
//!
//! - Multi-validator management
//! - Automatic key registration
//! - EIP-3076 import/export
//! - Statistics and monitoring
//!
//! # Example
//!
//! ```rust,ignore
//! use hsm_validator::{ValidatorService, ForkInfo};
//!
//! // Create the service
//! let service = ValidatorService::new("/var/lib/hsm/slashing-db").await?;
//!
//! // Configure fork info for mainnet
//! let fork_info = ForkInfo::new(
//!     [0x00, 0x00, 0x00, 0x00],  // Genesis fork version
//!     [0; 32],                    // Genesis validators root
//! );
//!
//! // Register a validator
//! let validator = service.create_ethereum_validator(&secret_key_bytes, fork_info)?;
//!
//! // Sign attestations with automatic anti-slashing protection
//! let signature = validator.sign_attestation(&attestation_data)?;
//! ```

#[cfg(feature = "babylon")]
use crate::babylon::{BabylonValidator, EotsKey, EotsSlashingDb};
use crate::error::Result;
use crate::ethereum::EthereumValidator;
use crate::interchange::{Eip3076Interchange, ImportResult};
use crate::slashing_db::SlashingProtectionDb;
use crate::types::*;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;

/// Validator service for managing multiple validators with anti-slashing protection.
///
/// This service provides:
/// - Registration and management of Ethereum validators
/// - Registration and management of Babylon validators (optional)
/// - EIP-3076 import/export for Ethereum validators
/// - Statistics and monitoring
pub struct ValidatorService {
    /// Base directory for databases
    base_dir: PathBuf,
    /// Ethereum slashing protection database
    eth_slashing_db: Arc<SlashingProtectionDb>,
    /// Babylon EOTS slashing database (optional)
    #[cfg(feature = "babylon")]
    babylon_slashing_db: Arc<EotsSlashingDb>,
    /// Registered Ethereum validators
    eth_validators: RwLock<HashMap<Vec<u8>, Arc<EthereumValidator>>>,
    /// Registered Babylon validators
    #[cfg(feature = "babylon")]
    babylon_validators: RwLock<HashMap<Vec<u8>, Arc<BabylonValidator>>>,
}

impl ValidatorService {
    /// Create a new validator service.
    ///
    /// # Arguments
    ///
    /// * `base_dir` - Directory for storing slashing protection databases
    ///
    /// # Databases Created
    ///
    /// - `{base_dir}/ethereum/` - Ethereum slashing protection
    /// - `{base_dir}/babylon/` - Babylon EOTS slashing protection (if feature enabled)
    pub async fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();

        // Create directories
        std::fs::create_dir_all(&base_dir)?;

        let eth_db_path = base_dir.join("ethereum");
        std::fs::create_dir_all(&eth_db_path)?;
        let eth_slashing_db = Arc::new(SlashingProtectionDb::open(&eth_db_path)?);

        #[cfg(feature = "babylon")]
        let babylon_slashing_db = {
            let babylon_db_path = base_dir.join("babylon");
            std::fs::create_dir_all(&babylon_db_path)?;
            Arc::new(EotsSlashingDb::open(&babylon_db_path)?)
        };

        info!(
            base_dir = %base_dir.display(),
            "Validator service initialized"
        );

        Ok(Self {
            base_dir,
            eth_slashing_db,
            #[cfg(feature = "babylon")]
            babylon_slashing_db,
            eth_validators: RwLock::new(HashMap::new()),
            #[cfg(feature = "babylon")]
            babylon_validators: RwLock::new(HashMap::new()),
        })
    }

    /// Create an in-memory validator service (for testing).
    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        let eth_slashing_db = Arc::new(SlashingProtectionDb::in_memory()?);

        #[cfg(feature = "babylon")]
        let babylon_slashing_db = Arc::new(EotsSlashingDb::in_memory()?);

        Ok(Self {
            base_dir: PathBuf::from("/tmp/validator-service"),
            eth_slashing_db,
            #[cfg(feature = "babylon")]
            babylon_slashing_db,
            eth_validators: RwLock::new(HashMap::new()),
            #[cfg(feature = "babylon")]
            babylon_validators: RwLock::new(HashMap::new()),
        })
    }

    /// Create and register an Ethereum validator.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - The 32-byte BLS secret key
    /// * `fork_info` - Fork information for the network
    ///
    /// # Returns
    ///
    /// A reference to the created validator, which can be used for signing.
    pub fn create_ethereum_validator(
        &self,
        secret_key: &[u8],
        fork_info: ForkInfo,
    ) -> Result<Arc<EthereumValidator>> {
        let validator =
            EthereumValidator::new(secret_key, self.eth_slashing_db.clone(), fork_info)?;

        let pubkey = validator.public_key().as_bytes().to_vec();
        let validator = Arc::new(validator);

        self.eth_validators
            .write()
            .insert(pubkey.clone(), validator.clone());

        info!(
            validator = %hex::encode(&pubkey[..8]),
            "Created Ethereum validator"
        );

        Ok(validator)
    }

    /// Get an existing Ethereum validator by public key.
    pub fn get_ethereum_validator(&self, public_key: &[u8]) -> Option<Arc<EthereumValidator>> {
        self.eth_validators.read().get(public_key).cloned()
    }

    /// List all Ethereum validators.
    pub fn list_ethereum_validators(&self) -> Vec<BlsPublicKey> {
        self.eth_validators
            .read()
            .keys()
            .map(|k| BlsPublicKey(k.clone()))
            .collect()
    }

    /// Create and register a Babylon validator.
    #[cfg(feature = "babylon")]
    pub fn create_babylon_validator(
        &self,
        secret_key: &[u8],
        chain_id: &str,
    ) -> Result<Arc<BabylonValidator>> {
        let eots_key = EotsKey::new(secret_key, chain_id, self.babylon_slashing_db.clone())?;

        let pubkey = eots_key.public_key().to_vec();
        let validator = Arc::new(BabylonValidator::new(eots_key));

        self.babylon_validators
            .write()
            .insert(pubkey.clone(), validator.clone());

        info!(
            validator = %hex::encode(&pubkey[..8]),
            chain_id,
            "Created Babylon validator"
        );

        Ok(validator)
    }

    /// Generate a new Babylon validator with a random key.
    #[cfg(feature = "babylon")]
    pub fn generate_babylon_validator(&self, chain_id: &str) -> Result<Arc<BabylonValidator>> {
        let eots_key = EotsKey::generate(chain_id, self.babylon_slashing_db.clone())?;

        let pubkey = eots_key.public_key().to_vec();
        let validator = Arc::new(BabylonValidator::new(eots_key));

        self.babylon_validators
            .write()
            .insert(pubkey.clone(), validator.clone());

        info!(
            validator = %hex::encode(&pubkey[..8]),
            chain_id,
            "Generated new Babylon validator"
        );

        Ok(validator)
    }

    /// Get an existing Babylon validator by public key.
    #[cfg(feature = "babylon")]
    pub fn get_babylon_validator(&self, public_key: &[u8]) -> Option<Arc<BabylonValidator>> {
        self.babylon_validators.read().get(public_key).cloned()
    }

    /// Export Ethereum slashing protection data (EIP-3076).
    ///
    /// # Arguments
    ///
    /// * `genesis_validators_root` - The network's genesis validators root
    /// * `public_keys` - Optional list of validators to export (exports all if None)
    pub fn export_ethereum_slashing_protection(
        &self,
        genesis_validators_root: &str,
        public_keys: Option<&[BlsPublicKey]>,
    ) -> Result<Eip3076Interchange> {
        Eip3076Interchange::export(&self.eth_slashing_db, genesis_validators_root, public_keys)
    }

    /// Import Ethereum slashing protection data (EIP-3076).
    ///
    /// # Security
    ///
    /// This will set minimum epochs/slots based on the imported data,
    /// preventing signing of any messages that could conflict.
    pub fn import_ethereum_slashing_protection(
        &self,
        interchange: &Eip3076Interchange,
    ) -> Result<ImportResult> {
        interchange.import(&self.eth_slashing_db)
    }

    /// Get Ethereum slashing protection statistics.
    pub fn ethereum_stats(&self) -> SlashingStats {
        self.eth_slashing_db.stats()
    }

    /// Get validator summary for an Ethereum validator.
    pub fn get_ethereum_validator_summary(&self, public_key: &[u8]) -> Result<ValidatorSummary> {
        self.eth_slashing_db.get_validator_summary(public_key)
    }

    /// Flush all databases to disk.
    pub fn flush(&self) -> Result<()> {
        self.eth_slashing_db.flush()?;

        #[cfg(feature = "babylon")]
        self.babylon_slashing_db.flush()?;

        Ok(())
    }

    /// Get the base directory.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

/// Builder for creating a ValidatorService with custom configuration.
pub struct ValidatorServiceBuilder {
    base_dir: PathBuf,
    enable_babylon: bool,
}

impl ValidatorServiceBuilder {
    /// Create a new builder.
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
            enable_babylon: false,
        }
    }

    /// Enable Babylon support.
    #[cfg(feature = "babylon")]
    pub fn with_babylon(mut self) -> Self {
        self.enable_babylon = true;
        self
    }

    /// Build the service.
    pub async fn build(self) -> Result<ValidatorService> {
        ValidatorService::new(&self.base_dir).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::SecretKey;

    fn generate_bls_secret_key() -> Vec<u8> {
        let mut ikm = [0u8; 32];
        getrandom::getrandom(&mut ikm).unwrap();
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        sk.to_bytes().to_vec()
    }

    #[test]
    fn test_service_creation() {
        let service = ValidatorService::in_memory().unwrap();
        assert!(service.list_ethereum_validators().is_empty());
    }

    #[test]
    fn test_create_ethereum_validator() {
        let service = ValidatorService::in_memory().unwrap();
        let secret_key = generate_bls_secret_key();
        let fork_info = ForkInfo::new([0; 4], [0; 32]);

        let validator = service
            .create_ethereum_validator(&secret_key, fork_info)
            .unwrap();

        assert_eq!(validator.public_key().as_bytes().len(), 48);
        assert_eq!(service.list_ethereum_validators().len(), 1);
    }

    #[test]
    fn test_get_ethereum_validator() {
        let service = ValidatorService::in_memory().unwrap();
        let secret_key = generate_bls_secret_key();
        let fork_info = ForkInfo::new([0; 4], [0; 32]);

        let validator = service
            .create_ethereum_validator(&secret_key, fork_info)
            .unwrap();
        let pubkey = validator.public_key().as_bytes();

        let retrieved = service.get_ethereum_validator(pubkey).unwrap();
        assert_eq!(retrieved.public_key().as_bytes(), pubkey);
    }

    #[test]
    fn test_export_import_roundtrip() {
        let service1 = ValidatorService::in_memory().unwrap();
        let secret_key = generate_bls_secret_key();
        let fork_info = ForkInfo::new([0; 4], [0; 32]);

        let validator = service1
            .create_ethereum_validator(&secret_key, fork_info.clone())
            .unwrap();

        // Sign some attestations
        use crate::ethereum::{AttestationData, Checkpoint};
        let attestation = AttestationData {
            slot: 100,
            index: 0,
            beacon_block_root: [0xab; 32],
            source: Checkpoint {
                epoch: 10,
                root: [0; 32],
            },
            target: Checkpoint {
                epoch: 11,
                root: [0; 32],
            },
        };
        validator.sign_attestation(&attestation).unwrap();

        // Export
        let interchange = service1
            .export_ethereum_slashing_protection("0x1234", None)
            .unwrap();
        let json = interchange.to_json().unwrap();

        // Import into new service
        let service2 = ValidatorService::in_memory().unwrap();
        let interchange2 = Eip3076Interchange::from_json(&json).unwrap();
        let result = service2
            .import_ethereum_slashing_protection(&interchange2)
            .unwrap();

        assert_eq!(result.attestations_imported, 1);
    }

    #[cfg(feature = "babylon")]
    #[test]
    fn test_create_babylon_validator() {
        let service = ValidatorService::in_memory().unwrap();
        let validator = service
            .generate_babylon_validator("babylon-testnet")
            .unwrap();

        assert_eq!(validator.public_key().len(), 33);
    }

    #[cfg(feature = "babylon")]
    #[test]
    fn test_babylon_validator_signing() {
        let service = ValidatorService::in_memory().unwrap();
        let validator = service
            .generate_babylon_validator("babylon-testnet")
            .unwrap();

        let height = 12345;
        let block_hash = [0xab; 32];

        // First signature succeeds
        let sig = validator.sign_finality_vote(height, &block_hash).unwrap();
        assert_eq!(sig.height, height);

        // Second signature at same height fails
        let result = validator.sign_finality_vote(height, &[0xcd; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_stats() {
        let service = ValidatorService::in_memory().unwrap();
        let secret_key = generate_bls_secret_key();
        let fork_info = ForkInfo::new([0; 4], [0; 32]);

        let validator = service
            .create_ethereum_validator(&secret_key, fork_info)
            .unwrap();

        // Sign some attestations
        use crate::ethereum::{AttestationData, Checkpoint};
        for i in 0..5 {
            let attestation = AttestationData {
                slot: i * 100,
                index: 0,
                beacon_block_root: [i as u8; 32],
                source: Checkpoint {
                    epoch: i * 10,
                    root: [0; 32],
                },
                target: Checkpoint {
                    epoch: i * 10 + 1,
                    root: [0; 32],
                },
            };
            validator.sign_attestation(&attestation).unwrap();
        }

        let stats = service.ethereum_stats();
        assert_eq!(stats.attestations_signed, 5);
    }
}
