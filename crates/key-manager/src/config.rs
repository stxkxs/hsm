//! Configuration for key manager backends
//!
//! Provides configuration types for selecting between software (in-memory) and
//! hardware-backed key managers.

#![cfg(feature = "hardware")]

use crate::{Error, Result};
use hsm_hardware_backend::{BackendType, HardwareBackend};
use hsm_storage::{HardwareStorageBackend, StorageConfig};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Key manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManagerConfig {
    /// Type of backend to use
    pub backend_type: KeyManagerBackendType,

    /// Storage path for persistent keys
    pub storage_path: PathBuf,

    /// Hardware backend configuration (required for Hardware backend type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_config: Option<HardwareBackendConfig>,
}

/// Key manager backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyManagerBackendType {
    /// In-memory storage (DefaultKeyManager)
    Software,
    /// Hardware-backed storage with TEE (HardwareKeyManager)
    Hardware,
}

/// Hardware backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareBackendConfig {
    /// Type of hardware backend
    pub backend_type: BackendType,

    /// AWS Nitro configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nitro_config: Option<NitroConfig>,

    /// Intel SGX configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sgx_config: Option<SgxConfig>,

    /// AMD SEV configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sev_config: Option<SevConfig>,
}

/// AWS Nitro Enclave configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NitroConfig {
    pub region: String,
    pub kms_key_arn: String,
    pub enclave_cid: Option<u32>,
    pub verify_attestation: bool,
    pub expected_pcrs: Option<Vec<(usize, Vec<u8>)>>,
}

/// Intel SGX configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SgxConfig {
    pub use_mrenclave_sealing: bool,
    pub verify_quote: bool,
    pub expected_mrenclave: Option<Vec<u8>>,
    pub expected_mrsigner: Option<Vec<u8>>,
}

/// AMD SEV configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SevConfig {
    pub use_snp: bool,
    pub verify_attestation: bool,
    pub expected_measurement: Option<Vec<u8>>,
}

impl KeyManagerConfig {
    /// Example configuration for AWS Nitro
    #[cfg(feature = "aws-nitro")]
    pub fn example_aws_nitro() -> Self {
        Self {
            backend_type: KeyManagerBackendType::Hardware,
            storage_path: PathBuf::from("/secure/hsm/keys"),
            hardware_config: Some(HardwareBackendConfig {
                backend_type: BackendType::AwsNitro,
                nitro_config: Some(NitroConfig {
                    region: "us-east-1".to_string(),
                    kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012".to_string(),
                    enclave_cid: Some(16),
                    verify_attestation: true,
                    expected_pcrs: None,
                }),
                sgx_config: None,
                sev_config: None,
            }),
        }
    }

    /// Example configuration for Intel SGX
    #[cfg(feature = "intel-sgx")]
    pub fn example_intel_sgx() -> Self {
        Self {
            backend_type: KeyManagerBackendType::Hardware,
            storage_path: PathBuf::from("/secure/hsm/keys"),
            hardware_config: Some(HardwareBackendConfig {
                backend_type: BackendType::IntelSgx,
                nitro_config: None,
                sgx_config: Some(SgxConfig {
                    use_mrenclave_sealing: true,
                    verify_quote: true,
                    expected_mrenclave: None,
                    expected_mrsigner: None,
                }),
                sev_config: None,
            }),
        }
    }

    /// Example configuration for AMD SEV
    #[cfg(feature = "amd-sev")]
    pub fn example_amd_sev() -> Self {
        Self {
            backend_type: KeyManagerBackendType::Hardware,
            storage_path: PathBuf::from("/secure/hsm/keys"),
            hardware_config: Some(HardwareBackendConfig {
                backend_type: BackendType::AmdSev,
                nitro_config: None,
                sgx_config: None,
                sev_config: Some(SevConfig {
                    use_snp: true,
                    verify_attestation: true,
                    expected_measurement: None,
                }),
            }),
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        match self.backend_type {
            KeyManagerBackendType::Software => {
                // Software backend doesn't need additional config
                Ok(())
            }
            KeyManagerBackendType::Hardware => {
                let hw_config = self.hardware_config.as_ref()
                    .ok_or_else(|| Error::InvalidKeyData("Hardware backend requires hardware_config".into()))?;

                // Validate that the appropriate config is present for the backend type
                match hw_config.backend_type {
                    BackendType::AwsNitro => {
                        if hw_config.nitro_config.is_none() {
                            return Err(Error::InvalidKeyData("AWS Nitro backend requires nitro_config".into()));
                        }
                    }
                    BackendType::IntelSgx => {
                        if hw_config.sgx_config.is_none() {
                            return Err(Error::InvalidKeyData("Intel SGX backend requires sgx_config".into()));
                        }
                    }
                    BackendType::AmdSev => {
                        if hw_config.sev_config.is_none() {
                            return Err(Error::InvalidKeyData("AMD SEV backend requires sev_config".into()));
                        }
                    }
                    BackendType::Software => {
                        return Err(Error::InvalidKeyData("Software backend should use Software manager type".into()));
                    }
                }

                Ok(())
            }
        }
    }
}

/// Factory function to create a hardware backend from configuration
pub async fn create_hardware_backend(
    config: &HardwareBackendConfig,
) -> Result<Box<dyn HardwareBackend>> {
    match config.backend_type {
        #[cfg(feature = "aws-nitro")]
        BackendType::AwsNitro => {
            let nitro_config = config.nitro_config.as_ref()
                .ok_or_else(|| Error::InvalidKeyData("Missing nitro_config".into()))?;

            let hw_config = hsm_hardware_backend::NitroConfig {
                region: nitro_config.region.clone(),
                kms_key_arn: nitro_config.kms_key_arn.clone(),
                enclave_cid: nitro_config.enclave_cid,
                verify_attestation: nitro_config.verify_attestation,
                expected_pcrs: nitro_config.expected_pcrs.clone(),
            };

            let backend = hsm_hardware_backend::NitroEnclaveBackend::new(hw_config)
                .await
                .map_err(|e| Error::HardwareError(e.to_string()))?;

            Ok(Box::new(backend))
        }

        #[cfg(feature = "intel-sgx")]
        BackendType::IntelSgx => {
            let sgx_config = config.sgx_config.as_ref()
                .ok_or_else(|| Error::InvalidKeyData("Missing sgx_config".into()))?;

            let hw_config = hsm_hardware_backend::SgxConfig {
                use_mrenclave_sealing: sgx_config.use_mrenclave_sealing,
                verify_quote: sgx_config.verify_quote,
                expected_mrenclave: sgx_config.expected_mrenclave.clone(),
                expected_mrsigner: sgx_config.expected_mrsigner.clone(),
            };

            let backend = hsm_hardware_backend::IntelSgxBackend::new(hw_config)
                .await
                .map_err(|e| Error::HardwareError(e.to_string()))?;

            Ok(Box::new(backend))
        }

        #[cfg(feature = "amd-sev")]
        BackendType::AmdSev => {
            let sev_config = config.sev_config.as_ref()
                .ok_or_else(|| Error::InvalidKeyData("Missing sev_config".into()))?;

            let hw_config = hsm_hardware_backend::SevConfig {
                use_snp: sev_config.use_snp,
                verify_attestation: sev_config.verify_attestation,
                expected_measurement: sev_config.expected_measurement.clone(),
            };

            let backend = hsm_hardware_backend::AmdSevBackend::new(hw_config)
                .await
                .map_err(|e| Error::HardwareError(e.to_string()))?;

            Ok(Box::new(backend))
        }

        #[allow(unreachable_patterns)]
        _ => Err(Error::InvalidKeyData(
            format!("Backend type {:?} not supported in this build", config.backend_type)
        )),
    }
}

/// Factory function to create a HardwareKeyManager from configuration
pub async fn create_hardware_key_manager(
    config: KeyManagerConfig,
) -> Result<crate::hardware::HardwareKeyManager> {
    // Validate configuration
    config.validate()?;

    // Extract hardware config
    let hw_config = config.hardware_config
        .ok_or_else(|| Error::InvalidKeyData("Missing hardware_config".into()))?;

    // Create hardware backend
    let hw_backend = create_hardware_backend(&hw_config).await?;

    // Create storage config
    let storage_config = StorageConfig {
        base_path: config.storage_path.clone(),
        backend_type: hsm_storage::StorageBackendType::Hardware,
        hardware_config: Some(convert_to_storage_hw_config(&hw_config)?),
        software_kek: None,
    };

    // Create hardware storage backend
    let hw_backend_clone = clone_hardware_backend(&hw_config).await?;
    let storage = HardwareStorageBackend::new(
        config.storage_path,
        hw_backend_clone,
    )
    .await
    .map_err(|e| Error::StorageError(e.to_string()))?;

    // Create hardware key manager
    crate::hardware::HardwareKeyManager::new(storage, hw_backend).await
}

// Helper function to convert BackendType to HardwareBackendType
fn convert_backend_type(backend_type: BackendType) -> Result<hsm_storage::storage_config::HardwareBackendType> {
    match backend_type {
        #[cfg(feature = "aws-nitro")]
        BackendType::AwsNitro => Ok(hsm_storage::storage_config::HardwareBackendType::AwsNitro),
        #[cfg(feature = "intel-sgx")]
        BackendType::IntelSgx => Ok(hsm_storage::storage_config::HardwareBackendType::IntelSgx),
        #[cfg(feature = "amd-sev")]
        BackendType::AmdSev => Ok(hsm_storage::storage_config::HardwareBackendType::AmdSev),
        BackendType::Software => Err(Error::InvalidKeyData(
            "Software backend type not supported for hardware storage".into()
        )),
        #[allow(unreachable_patterns)]
        _ => Err(Error::InvalidKeyData(
            format!("Backend type {:?} not supported in this build", backend_type)
        )),
    }
}

// Helper function to convert config to storage hardware config
fn convert_to_storage_hw_config(
    config: &HardwareBackendConfig,
) -> Result<hsm_storage::HardwareBackendConfig> {
    Ok(hsm_storage::HardwareBackendConfig {
        backend_type: convert_backend_type(config.backend_type)?,
        #[cfg(feature = "aws-nitro")]
        nitro: config.nitro_config.as_ref().map(|c| hsm_storage::NitroConfig {
            region: c.region.clone(),
            kms_key_arn: c.kms_key_arn.clone(),
            enclave_cid: c.enclave_cid,
            verify_attestation: c.verify_attestation,
            expected_pcrs: c.expected_pcrs.clone(),
        }),
        #[cfg(feature = "intel-sgx")]
        sgx: config.sgx_config.as_ref().map(|c| hsm_storage::SgxConfig {
            use_mrenclave_sealing: c.use_mrenclave_sealing,
            verify_quote: c.verify_quote,
            expected_mrenclave: c.expected_mrenclave.clone(),
            expected_mrsigner: c.expected_mrsigner.clone(),
        }),
        #[cfg(feature = "amd-sev")]
        sev: config.sev_config.as_ref().map(|c| hsm_storage::SevConfig {
            use_snp: c.use_snp,
            verify_attestation: c.verify_attestation,
            expected_measurement: c.expected_measurement.clone(),
        }),
    })
}

// Helper function to clone hardware backend (create a new instance with same config)
async fn clone_hardware_backend(
    config: &HardwareBackendConfig,
) -> Result<Box<dyn HardwareBackend>> {
    create_hardware_backend(config).await
}
