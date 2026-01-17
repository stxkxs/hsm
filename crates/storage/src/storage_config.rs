//! Storage configuration with hardware backend support
//!
//! This module provides configuration types for selecting between software-based
//! and hardware-based storage backends.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Base path for storage
    pub base_path: PathBuf,

    /// Backend type to use
    pub backend_type: StorageBackendType,

    /// Hardware backend configuration (if using hardware backend)
    #[cfg(feature = "hardware")]
    pub hardware_config: Option<HardwareBackendConfig>,

    /// Software encryption key (if using software backend)
    #[serde(skip_serializing)]
    pub software_kek: Option<Vec<u8>>,
}

/// Type of storage backend
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackendType {
    /// Software-based encryption (using master key)
    Software,

    /// Hardware-based encryption (using TEE)
    #[cfg(feature = "hardware")]
    Hardware,
}

/// Hardware backend configuration
#[cfg(feature = "hardware")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareBackendConfig {
    /// Type of hardware backend
    pub backend_type: HardwareBackendType,

    /// AWS Nitro Enclaves configuration
    #[cfg(feature = "aws-nitro")]
    pub nitro: Option<NitroConfig>,

    /// Intel SGX configuration
    #[cfg(feature = "intel-sgx")]
    pub sgx: Option<SgxConfig>,

    /// AMD SEV configuration
    #[cfg(feature = "amd-sev")]
    pub sev: Option<SevConfig>,
}

/// Type of hardware backend
#[cfg(feature = "hardware")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HardwareBackendType {
    /// AWS Nitro Enclaves
    #[cfg(feature = "aws-nitro")]
    AwsNitro,

    /// Intel SGX
    #[cfg(feature = "intel-sgx")]
    IntelSgx,

    /// AMD SEV
    #[cfg(feature = "amd-sev")]
    AmdSev,
}

/// AWS Nitro Enclaves configuration
#[cfg(feature = "aws-nitro")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NitroConfig {
    /// AWS region
    pub region: String,

    /// KMS key ARN for envelope encryption
    pub kms_key_arn: String,

    /// Enclave CID (Context ID)
    pub enclave_cid: Option<u32>,

    /// Verify attestation on operations
    pub verify_attestation: bool,
}

/// Intel SGX configuration
#[cfg(feature = "intel-sgx")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SgxConfig {
    /// Path to signed enclave file
    pub enclave_path: String,

    /// Expected MRENCLAVE (code measurement)
    pub expected_mrenclave: Option<String>,

    /// Expected MRSIGNER (signer measurement)
    pub expected_mrsigner: Option<String>,

    /// Enable remote attestation
    pub enable_remote_attestation: bool,

    /// IAS API key (for remote attestation)
    pub ias_api_key: Option<String>,
}

/// AMD SEV configuration
#[cfg(feature = "amd-sev")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SevConfig {
    /// SEV device path
    pub device_path: String,

    /// Expected launch measurement
    pub expected_measurement: Option<String>,

    /// Enable SEV-SNP features
    pub use_snp: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("/var/lib/hsm/storage"),
            backend_type: StorageBackendType::Software,
            #[cfg(feature = "hardware")]
            hardware_config: None,
            software_kek: None,
        }
    }
}

/// Example configurations for common deployment scenarios
#[cfg(feature = "hardware")]
impl StorageConfig {
    /// Example AWS Nitro Enclaves configuration
    #[cfg(feature = "aws-nitro")]
    pub fn example_aws_nitro() -> Self {
        Self {
            base_path: PathBuf::from("/secure/storage"),
            backend_type: StorageBackendType::Hardware,
            hardware_config: Some(HardwareBackendConfig {
                backend_type: HardwareBackendType::AwsNitro,
                nitro: Some(NitroConfig {
                    region: "us-east-1".to_string(),
                    kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/abcd1234".to_string(),
                    enclave_cid: Some(16),
                    verify_attestation: true,
                }),
                #[cfg(feature = "intel-sgx")]
                sgx: None,
                #[cfg(feature = "amd-sev")]
                sev: None,
            }),
            software_kek: None,
        }
    }

    /// Example Intel SGX configuration
    #[cfg(feature = "intel-sgx")]
    pub fn example_intel_sgx() -> Self {
        Self {
            base_path: PathBuf::from("/secure/storage"),
            backend_type: StorageBackendType::Hardware,
            hardware_config: Some(HardwareBackendConfig {
                backend_type: HardwareBackendType::IntelSgx,
                #[cfg(feature = "aws-nitro")]
                nitro: None,
                sgx: Some(SgxConfig {
                    enclave_path: "/opt/hsm/enclave.signed.so".to_string(),
                    expected_mrenclave: None,
                    expected_mrsigner: None,
                    enable_remote_attestation: true,
                    ias_api_key: Some("your-ias-api-key".to_string()),
                }),
                #[cfg(feature = "amd-sev")]
                sev: None,
            }),
            software_kek: None,
        }
    }

    /// Example AMD SEV configuration
    #[cfg(feature = "amd-sev")]
    pub fn example_amd_sev() -> Self {
        Self {
            base_path: PathBuf::from("/secure/storage"),
            backend_type: StorageBackendType::Hardware,
            hardware_config: Some(HardwareBackendConfig {
                backend_type: HardwareBackendType::AmdSev,
                #[cfg(feature = "aws-nitro")]
                nitro: None,
                #[cfg(feature = "intel-sgx")]
                sgx: None,
                sev: Some(SevConfig {
                    device_path: "/dev/sev".to_string(),
                    expected_measurement: None,
                    use_snp: false,
                }),
            }),
            software_kek: None,
        }
    }
}

/// Create a storage backend from configuration
#[cfg(feature = "hardware")]
pub async fn create_storage_backend(
    config: StorageConfig,
) -> crate::StorageResult<Box<dyn crate::StorageBackend>> {
    use crate::StorageError;

    match config.backend_type {
        StorageBackendType::Software => {
            // Create software-based storage
            let kek_vec = config
                .software_kek
                .ok_or_else(|| StorageError::OperationFailed("KEK not provided".to_string()))?;

            // Convert Vec to fixed-size array
            if kek_vec.len() != 32 {
                return Err(StorageError::OperationFailed(
                    "KEK must be exactly 32 bytes".to_string(),
                ));
            }
            let mut kek = [0u8; 32];
            kek.copy_from_slice(&kek_vec);

            let storage =
                crate::EncryptedFileStorage::create_with_new_key(config.base_path, &kek)?;

            Ok(Box::new(storage))
        }

        StorageBackendType::Hardware => {
            let hw_config = config.hardware_config.ok_or_else(|| {
                StorageError::OperationFailed("Hardware config not provided".to_string())
            })?;

            // Create appropriate hardware backend
            let hw_backend: Box<dyn hsm_hardware_backend::HardwareBackend> =
                match hw_config.backend_type {
                    #[cfg(feature = "aws-nitro")]
                    HardwareBackendType::AwsNitro => {
                        let nitro_config = hw_config.nitro.ok_or_else(|| {
                            StorageError::OperationFailed("Nitro config not provided".to_string())
                        })?;

                        let backend_config = hsm_hardware_backend::NitroConfig {
                            region: nitro_config.region,
                            kms_key_arn: nitro_config.kms_key_arn,
                            enclave_cid: nitro_config.enclave_cid,
                            verify_attestation: nitro_config.verify_attestation,
                            expected_pcrs: None,
                        };

                        Box::new(
                            hsm_hardware_backend::NitroEnclaveBackend::new(backend_config)
                                .await
                                .map_err(|e| StorageError::OperationFailed(e.to_string()))?,
                        )
                    }

                    #[cfg(feature = "intel-sgx")]
                    HardwareBackendType::IntelSgx => {
                        let sgx_config = hw_config.sgx.ok_or_else(|| {
                            StorageError::OperationFailed("SGX config not provided".to_string())
                        })?;

                        let backend_config = hsm_hardware_backend::SgxConfig {
                            enclave_path: sgx_config.enclave_path,
                            expected_mrenclave: sgx_config.expected_mrenclave.map(|s| s.into_bytes()),
                            expected_mrsigner: sgx_config.expected_mrsigner.map(|s| s.into_bytes()),
                            enable_remote_attestation: sgx_config.enable_remote_attestation,
                            ias_api_key: sgx_config.ias_api_key,
                            use_mrenclave_sealing: false,
                        };

                        Box::new(
                            hsm_hardware_backend::SgxBackend::new(backend_config)
                                .await
                                .map_err(|e| StorageError::OperationFailed(e.to_string()))?,
                        )
                    }

                    #[cfg(feature = "amd-sev")]
                    HardwareBackendType::AmdSev => {
                        let sev_config = hw_config.sev.ok_or_else(|| {
                            StorageError::OperationFailed("SEV config not provided".to_string())
                        })?;

                        let backend_config = hsm_hardware_backend::SevConfig {
                            device_path: sev_config.device_path,
                            expected_measurement: sev_config.expected_measurement.map(|s| s.into_bytes()),
                            enable_remote_attestation: false,
                            use_snp: sev_config.use_snp,
                        };

                        Box::new(
                            hsm_hardware_backend::SevBackend::new(backend_config)
                                .await
                                .map_err(|e| StorageError::OperationFailed(e.to_string()))?,
                        )
                    }

                    // Fallback for when no features are enabled
                    #[cfg(not(any(feature = "aws-nitro", feature = "intel-sgx", feature = "amd-sev")))]
                    _ => {
                        return Err(StorageError::OperationFailed(
                            "No hardware backend features enabled".to_string(),
                        ));
                    }
                };

            // Create hardware storage backend
            let storage =
                crate::HardwareStorageBackend::new(config.base_path, hw_backend).await?;

            Ok(Box::new(storage))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert_eq!(config.backend_type, StorageBackendType::Software);
    }

    #[cfg(feature = "aws-nitro")]
    #[test]
    fn test_example_aws_nitro() {
        let config = StorageConfig::example_aws_nitro();
        assert_eq!(config.backend_type, StorageBackendType::Hardware);
        assert!(config.hardware_config.is_some());
    }

    #[test]
    fn test_storage_config_serialization() {
        let config = StorageConfig::default();
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: StorageConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(config.backend_type, deserialized.backend_type);
    }
}
