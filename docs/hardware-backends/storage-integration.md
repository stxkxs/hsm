# Hardware Backend Storage Integration

This document explains how hardware backends are integrated with the HSM storage layer to provide TEE-backed key storage.

## Overview

The storage layer has been extended to support hardware-backed key encryption, where keys are sealed using Trusted Execution Environments (TEEs) instead of software-only encryption.

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│                (Key Manager, Crypto Operations)             │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  Storage Backend (trait)                    │
│         store_key() │ load_key() │ list_keys() │ etc.       │
└───────┬──────────────────────────────────────────┬──────────┘
        │                                          │
        ▼                                          ▼
┌───────────────────┐                  ┌────────────────────────┐
│ EncryptedFileStorage │              │ HardwareStorageBackend │
│ (Software-based)     │              │ (Hardware-based)        │
│                      │              │                         │
│ • AES-256-GCM        │              │ • TEE sealing           │
│ • Master key         │              │ • PCR binding           │
│ • Local encryption   │              │ • Attestation support   │
└───────────────────────┘              └────────┬───────────────┘
                                                │
                                                ▼
                                    ┌──────────────────────────┐
                                    │  HardwareBackend (trait) │
                                    │  seal_key() / unseal()   │
                                    └────┬─────────────────────┘
                                         │
                         ┌───────────────┼───────────────┐
                         ▼               ▼               ▼
                    ┌────────┐      ┌────────┐      ┌────────┐
                    │ Nitro  │      │  SGX   │      │  SEV   │
                    └────────┘      └────────┘      └────────┘
```

## Key Features

### 1. TEE-Sealed Keys

Keys are cryptographically bound to TEE measurements:
- **AWS Nitro**: Bound to enclave PCR values via KMS
- **Intel SGX**: Bound to MRENCLAVE or MRSIGNER
- **AMD SEV**: Bound to launch measurement

### 2. Transparent Integration

Application code doesn't need to know which backend is used:

```rust
// Same API for both software and hardware backends
storage.store_key(&key_id, key_data, "namespace")?;
let data = storage.load_key(&key_id, "namespace")?;
```

### 3. Configuration-Driven Selection

Choose backend via configuration file:

```toml
[storage]
backend_type = "hardware"  # or "software"

[storage.hardware]
backend_type = "aws-nitro"  # or "intel-sgx" or "amd-sev"

[storage.hardware.nitro]
region = "us-east-1"
kms_key_arn = "arn:aws:kms:..."
enclave_cid = 16
verify_attestation = true
```

## Usage Examples

### Software Backend (Default)

```rust
use hsm_storage::{EncryptedFileStorage, StorageBackend, KeyId};
use std::path::PathBuf;

// Create software-based storage
let kek = [0u8; 32];  // From secure source
let mut storage = EncryptedFileStorage::create_with_new_key(
    PathBuf::from("/var/lib/hsm/storage"),
    &kek
)?;

storage.create_namespace("production")?;

let key_id = KeyId::new("signing-key-001");
storage.store_key(&key_id, b"key material", "production")?;
```

### Hardware Backend (AWS Nitro)

```rust
use hsm_storage::{HardwareStorageBackend, StorageBackend, KeyId};
use hsm_hardware_backend::{NitroEnclaveBackend, NitroConfig};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create hardware backend
    let hw_config = NitroConfig {
        region: "us-east-1".to_string(),
        kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/abc123".to_string(),
        enclave_cid: Some(16),
        verify_attestation: true,
        expected_pcrs: None,
    };
    let hw_backend = NitroEnclaveBackend::new(hw_config).await?;

    // Create hardware-backed storage
    let mut storage = HardwareStorageBackend::new(
        PathBuf::from("/secure/storage"),
        Box::new(hw_backend)
    ).await?;

    // Use async API for operations
    storage.create_namespace_async("production").await?;

    let key_id = KeyId::new("signing-key-001");
    storage.store_key_async(&key_id, b"key material", "production").await?;

    // Keys are automatically sealed by TEE
    let data = storage.load_key_async(&key_id, "production").await?;

    Ok(())
}
```

### Using Configuration Helper

```rust
use hsm_storage::{create_storage_backend, StorageConfig, StorageBackendType};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load config from file or construct
    let config = StorageConfig::example_aws_nitro();  // Or load from TOML

    // Create backend based on configuration
    let mut storage = create_storage_backend(config).await?;

    // Use the storage backend (type is Box<dyn StorageBackend>)
    // ... operations ...

    Ok(())
}
```

## Storage Format

### Hardware-Backed Keys

Keys are stored in the following format:

```text
/secure/storage/
└── namespaces/
    └── production/
        └── keys/
            ├── signing-key-001.sealed  # Serialized SealedKey struct
            └── signing-key-001.meta    # Metadata (backend type, timestamp)
```

**sealed file contents** (postcard-serialized):
```rust
SealedKey {
    ciphertext: Vec<u8>,     // TEE-encrypted key material
    metadata: SealedKeyMetadata {
        algorithm: "AES-256-GCM + AWS-KMS",
        version: 1,
        sealed_at: 1234567890,
        backend_type: BackendType::AwsNitro,
        additional: {...}
    },
    backend_data: Vec<u8>,   // Backend-specific data (e.g., encrypted DEK)
}
```

**meta file contents**:
```rust
KeyMetadata {
    backend_type: BackendType::AwsNitro,
    sealed_at: 1234567890,
    algorithm: "AES-256-GCM + AWS-KMS",
}
```

## Performance Characteristics

### Software Backend
- **Store**: ~2ms (AES-256-GCM encryption)
- **Load**: ~1.5ms (AES-256-GCM decryption)
- **Cold start**: Instant (no initialization needed)

### Hardware Backend (AWS Nitro)
- **Store**: ~8ms (includes KMS envelope encryption)
- **Load**: ~7ms (includes KMS decryption)
- **Cold start**: ~2s (KMS client initialization)

### Hardware Backend (Intel SGX)
- **Store**: ~2ms (hardware sealing, local)
- **Load**: ~1ms (hardware unsealing, local)
- **Cold start**: ~500ms (enclave initialization)

### Hardware Backend (AMD SEV)
- **Store**: ~3ms (hardware sealing, local)
- **Load**: ~2ms (hardware unsealing, local)
- **Cold start**: ~200ms (SEV initialization)

## Migration Between Backends

### Software → Hardware

To migrate from software to hardware backend:

1. **Read all keys from software backend**
2. **Initialize hardware backend**
3. **Re-encrypt each key with hardware backend**
4. **Verify migration**

```rust
// 1. Load from software backend
let software_storage = EncryptedFileStorage::open(path, &kek)?;
let keys = software_storage.list_keys("production")?;

// 2. Create hardware backend
let hw_backend = NitroEnclaveBackend::new(config).await?;
let mut hardware_storage = HardwareStorageBackend::new(path2, Box::new(hw_backend)).await?;
hardware_storage.create_namespace_async("production").await?;

// 3. Migrate each key
for key_id in keys {
    let data = software_storage.load_key(&key_id, "production")?;
    hardware_storage.store_key_async(&key_id, &data, "production").await?;
}

// 4. Verify
for key_id in hardware_storage.list_keys_async("production").await? {
    let original = software_storage.load_key(&key_id, "production")?;
    let migrated = hardware_storage.load_key_async(&key_id, "production").await?;
    assert_eq!(original, migrated);
}
```

### Hardware → Hardware (Cross-Platform)

Migrating between hardware backends requires:

1. Unseal keys in source TEE
2. Re-seal keys in destination TEE

This typically requires both TEEs to be available simultaneously, or exporting keys in a secure intermediate format.

## Security Considerations

### Key Binding

**Software Backend**:
- Keys encrypted with master key
- Security depends on KEK protection
- Portable across systems

**Hardware Backend**:
- Keys cryptographically bound to TEE measurements
- Cannot be unsealed outside the TEE
- Non-portable (by design)

### Threat Model

| Threat | Software Backend | Hardware Backend |
|--------|------------------|------------------|
| Disk theft | ✅ Protected (encrypted) | ✅ Protected (sealed) |
| Memory dump | ⚠️ KEK may be in memory | ✅ Keys in TEE only |
| Code modification | ⚠️ No detection | ✅ Unsealing fails (PCR mismatch) |
| Hypervisor attack | ⚠️ Full access | ✅ Protected (Nitro/SEV) |
| Physical attack | ⚠️ Depends on KEK storage | ✅ Hardware root of trust |

### Best Practices

1. **Use hardware backend for production keys**
   - Signing keys for transactions
   - Root keys for key hierarchies
   - Long-lived encryption keys

2. **Use software backend for development/testing**
   - Easier to back up and restore
   - No hardware dependencies
   - Faster migration

3. **Implement key rotation**
   - Periodically rotate keys regardless of backend
   - Re-seal with updated TEE measurements

4. **Monitor attestation status**
   - Verify TEE measurements haven't changed unexpectedly
   - Alert on attestation failures

## Troubleshooting

### Issue: Keys won't unseal

**Symptom**: `UnsealingFailed` error when loading keys

**Causes**:
1. TEE measurements changed (code update, config change)
2. Different TEE instance (enclave restarted with different ID)
3. Hardware backend not available

**Solutions**:
- AWS Nitro: Check KMS key policy, verify PCR values match
- Intel SGX: Verify MRENCLAVE/MRSIGNER, check sealing policy
- AMD SEV: Verify launch measurement unchanged

### Issue: Slow storage operations

**Symptom**: > 100ms for store/load operations

**Causes**:
1. KMS throttling (AWS Nitro)
2. Network latency to KMS
3. Cold start initialization

**Solutions**:
- Pre-initialize hardware backend
- Use caching layer for hot keys
- Check KMS request limits
- Use VPC endpoint for KMS (reduce latency)

### Issue: Backend not available

**Symptom**: `BackendNotAvailable` error

**Causes**:
1. TEE not initialized
2. Missing credentials (AWS)
3. Hardware not present

**Solutions**:
- AWS Nitro: Check IAM role, verify enclave running
- Intel SGX: Enable SGX in BIOS, load kernel module
- AMD SEV: Enable SEV in BIOS, check /dev/sev

## Testing

### Unit Tests

```bash
# Test hardware storage with mock backend
cargo test --package hsm-storage --features hardware
```

### Integration Tests

```bash
# Requires actual hardware backend
cargo test --package hsm-storage --features aws-nitro
```

### Benchmarks

```bash
# Compare software vs hardware performance
cargo bench --package hsm-storage --features all-hardware
```

## References

- [Hardware Backend Documentation](./README.md)
- [AWS Nitro Deployment](./aws-nitro-deployment.md)
- [Intel SGX Deployment](./intel-sgx-deployment.md)
- [AMD SEV Deployment](./amd-sev-deployment.md)
- [Storage Layer Design](../../crates/storage/src/lib.rs)
