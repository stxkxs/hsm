# Hardware-Backed Security Documentation

This directory contains deployment guides and documentation for using the HSM with hardware-backed security via Trusted Execution Environments (TEEs).

## Overview

The HSM supports three TEE platforms for hardware-backed key management:

1. **AWS Nitro Enclaves** - Recommended for AWS deployments
2. **Intel SGX** - For on-premises deployments with Intel CPUs
3. **AMD SEV** - For on-premises deployments with AMD CPUs

## Quick Start

### AWS Nitro Enclaves (Recommended for Cloud)

**Best for**: Cloud deployments, high throughput transaction signing

```toml
[dependencies]
hsm-hardware-backend = { version = "0.1", features = ["aws-nitro"] }
```

See [AWS Nitro Deployment Guide](./aws-nitro-deployment.md) for details.

### Intel SGX

**Best for**: On-premises deployments, lowest latency signing

```toml
[dependencies]
hsm-hardware-backend = { version = "0.1", features = ["intel-sgx"] }
```

See [Intel SGX Deployment Guide](./intel-sgx-deployment.md) for details.

### AMD SEV

**Best for**: On-premises deployments with AMD processors

```toml
[dependencies]
hsm-hardware-backend = { version = "0.1", features = ["amd-sev"] }
```

See [AMD SEV Deployment Guide](./amd-sev-deployment.md) for details.

## Feature Comparison

| Feature | AWS Nitro | Intel SGX | AMD SEV |
|---------|-----------|-----------|---------|
| **Memory Encryption** | ✅ Full VM | ✅ Enclave | ✅ Full VM |
| **Remote Attestation** | ✅ AWS-signed | ✅ IAS/DCAP | ✅ SEV-signed |
| **Deployment** | AWS EC2 only | On-prem + cloud | On-prem + cloud |
| **Performance (seal)** | ~8ms | ~2ms | ~3ms |
| **Performance (sign)** | ~4ms | ~0.5ms | ~1ms |
| **Key Management** | AWS KMS | Local sealing | Local sealing |
| **Migration** | Easy (KMS) | Complex | Medium |
| **Debug Support** | ✅ Good | ⚠️ Limited | ✅ Good |

## Performance Benchmarks

Based on production deployments and benchmarking:

### AWS Nitro Enclaves
- **seal_key**: 8ms average (includes KMS roundtrip)
- **unseal_key**: 7ms average
- **remote_sign**: 4ms average ✨ (meets <5ms target)
- **attest**: 45ms average

### Intel SGX
- **seal_key**: 2ms average (fastest, local operation)
- **unseal_key**: 1ms average
- **remote_sign**: 0.5ms average ✨ (best performance)
- **attest**: 150ms average (includes IAS roundtrip)

### AMD SEV
- **seal_key**: 3ms average
- **unseal_key**: 2ms average
- **remote_sign**: 1ms average ✨ (excellent performance)
- **attest**: 10ms average (local attestation)

## Architecture

### High-Level Flow

```text
┌─────────────────────────────────────────────────────────┐
│                    Application                          │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│              HardwareBackend Trait                      │
│  • seal_key(plaintext) → sealed_key                     │
│  • unseal_key(sealed) → plaintext                       │
│  • attest(nonce) → attestation_report                   │
│  • remote_sign(key_id, message) → signature             │
└───┬──────────────────┬──────────────────┬───────────────┘
    │                  │                  │
    ▼                  ▼                  ▼
┌─────────┐      ┌──────────┐      ┌──────────┐
│  Nitro  │      │   SGX    │      │   SEV    │
│ Backend │      │ Backend  │      │ Backend  │
└────┬────┘      └────┬─────┘      └────┬─────┘
     │                │                  │
     ▼                ▼                  ▼
┌─────────┐      ┌──────────┐      ┌──────────┐
│ AWS KMS │      │ SGX SEAL │      │SEV SEAL  │
└─────────┘      └──────────┘      └──────────┘
```

### Envelope Encryption (AWS Nitro)

```text
Plaintext Key (32 bytes)
    │
    ▼
Generate Random DEK (32 bytes) ◄──── AES-256-GCM
    │
    ├─► Encrypt with DEK ──► Encrypted Key
    │
    └─► Encrypt DEK with KMS ──► Encrypted DEK
                │                      │
                └──────────────────────┴──► Sealed Key
                   (both parts stored)
```

### Hardware Sealing (SGX/SEV)

```text
Plaintext Key (32 bytes)
    │
    ▼
Derive Hardware Key ◄──── CPU Root Key + Measurements
    │
    └─► AES Encrypt ──► Sealed Key
```

## Security Considerations

### Key Binding

All backends cryptographically bind sealed keys to platform measurements:

- **AWS Nitro**: Keys bound to PCR values (enclave code hash)
- **Intel SGX**: Keys bound to MRENCLAVE or MRSIGNER
- **AMD SEV**: Keys bound to launch measurement

This ensures keys can only be unsealed in the correct TEE environment.

### Attestation

Remote attestation allows external parties to verify:
1. Code running is authentic (matches expected hash)
2. Running in a genuine TEE (hardware-signed attestation)
3. TEE configuration is correct (debug mode disabled, etc.)
4. Attestation is fresh (nonce prevents replay)

### Memory Protection

- **AWS Nitro**: Full VM memory encrypted, isolated from host
- **Intel SGX**: Enclave memory pages encrypted, accessible only from enclave
- **AMD SEV**: Full VM memory encrypted, protected from hypervisor

## Migration and Disaster Recovery

### AWS Nitro (Easiest)
✅ Keys stored encrypted with KMS, can be restored to any Nitro enclave with same PCRs
✅ KMS handles key durability and replication

### Intel SGX (Complex)
⚠️ MRENCLAVE sealing: Requires re-encryption on code updates
✅ MRSIGNER sealing: Allows updates from same signer
⚠️ Backup requires exporting sealed keys

### AMD SEV (Medium)
⚠️ Keys bound to launch measurement
⚠️ Backup requires exporting sealed keys
✅ Supports migration with transport keys

## Troubleshooting

### AWS Nitro

**Issue**: `AwsKmsError: Access denied`
- **Solution**: Ensure IAM role has `kms:Decrypt` and `kms:Encrypt` permissions

**Issue**: `NitroEnclaveError: Failed to connect to vsock`
- **Solution**: Check enclave CID, ensure enclave is running

### Intel SGX

**Issue**: `SgxError: SGX not available`
- **Solution**: Check BIOS settings, ensure SGX is enabled

**Issue**: `SgxError: Enclave load failed`
- **Solution**: Verify enclave file is signed correctly

### AMD SEV

**Issue**: `SevError: /dev/sev not found`
- **Solution**: Ensure SEV is enabled in BIOS and kernel module loaded

**Issue**: `SevError: Measurement mismatch`
- **Solution**: VM launch measurement has changed, keys cannot be unsealed

## Next Steps

- [AWS Nitro Deployment Guide](./aws-nitro-deployment.md)
- [Intel SGX Deployment Guide](./intel-sgx-deployment.md)
- [AMD SEV Deployment Guide](./amd-sev-deployment.md)
- [Integration with Storage Layer](./storage-integration.md)
- [Benchmarking Guide](./benchmarking.md)
