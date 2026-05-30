# hsm

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.93%2B-orange.svg)](https://www.rust-lang.org)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-78%25-green.svg)]()

A production-grade, software-based Hardware Security Module (HSM) implemented in Rust. Designed for cloud-native deployments with enterprise-grade security, auditability, and performance.

## Overview

This HSM provides cryptographic key management and operations as a service, with features typically found in hardware HSMs but implemented in hardened software for Kubernetes environments. It supports multi-tenancy, provides tamper-evident audit logs, and offers comprehensive key lifecycle management.

**Key Capabilities:**
- Cryptographic operations (sign, verify, encrypt, decrypt, key generation)
- Multi-tenant namespace isolation with RBAC
- Tamper-evident audit trail using hash chains and Merkle trees
- mTLS client authentication
- Prometheus metrics and health checks
- Encrypted key storage with atomic operations
- Disaster recovery via Shamir's Secret Sharing

## Quick Start

### Prerequisites

- Rust 1.93 or later
- Protocol Buffers compiler (`protoc`)
- OpenSSL development libraries

> **📚 Documentation**: After installation, run `cargo doc --workspace --no-deps --open` to view comprehensive API documentation with examples.

### Installation

```bash
# Clone the repository
git clone https://github.com/stxkxs/hsm
cd hsm

# Build the project
cargo build --release

# Run tests
cargo test --workspace

# Start the HSM server (development mode)
cargo run --bin hsm-server -- --config config/development.yaml
```

### Basic Usage

```bash
# Generate a signing key
grpcurl -plaintext -d '{
  "namespace": "default",
  "key_id": "signing-key-1",
  "algorithm": "Ed25519"
}' localhost:50051 hsm.HsmService/GenerateKey

# Sign data
grpcurl -plaintext -d '{
  "namespace": "default",
  "key_id": "signing-key-1",
  "data": "SGVsbG8gV29ybGQ="
}' localhost:50051 hsm.HsmService/Sign

# Verify signature
grpcurl -plaintext -d '{
  "namespace": "default",
  "key_id": "signing-key-1",
  "data": "SGVsbG8gV29ybGQ=",
  "signature": "<base64-signature>"
}' localhost:50051 hsm.HsmService/Verify
```

## Features

### Cryptographic Operations

**Asymmetric Algorithms:**
- **RSA**: 2048, 3072, 4096-bit keys (PKCS#1, PSS padding)
- **ECDSA**: P-256, P-384, P-521 curves
- **Ed25519**: EdDSA signatures (high performance)

**Symmetric Encryption:**
- **AES-GCM**: 128, 192, 256-bit keys
- **AES-CBC**: PKCS#7 padding

**Key Derivation:**
- **PBKDF2**: Password-based key derivation
- **HKDF**: HMAC-based key derivation
- **Argon2**: Memory-hard password hashing

**Hashing:**
- SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, BLAKE3

### Blockchain & Web3

**HD Key Derivation:**
- **BIP-32**: Hierarchical deterministic key derivation
- **BIP-39**: Mnemonic phrase generation (12/24 words)
- **BIP-44**: Multi-account hierarchy for multiple chains

**Ethereum Signing:**
- **EIP-191**: Personal message signing (`eth_sign`)
- **EIP-712**: Typed structured data signing (permits, swaps, etc.)
- **Transaction Signing**: RLP-encoded transaction support

**Multi-Chain Support:**
- **Ethereum**: Full signing and address derivation
- **Bitcoin**: Address generation and transaction signing
- **Solana**: Ed25519-based signing
- **StarkNet**: Stark curve ECDSA, SNIP-12 typed data

**Validator Protection:**
- **Ethereum Validators**: Anti-slashing for attestations and proposals
  - Double vote prevention
  - Surrounding/surrounded vote detection
  - EIP-3076 interchange format for client migration
- **Babylon EOTS**: Extractable one-time signatures for Bitcoin staking
  - Height-based double-sign prevention
  - Private key protection (double-sign reveals key)

### Transaction Policies

**WASM Policy Engine:**
- Write custom policies in Rust, AssemblyScript, or any WASM language
- Fuel-based execution limits (gas metering)
- Memory and time limits for sandboxed execution

**Policy Decisions:**
- `Allow`: Transaction approved
- `Deny`: Transaction rejected
- `RequireApproval`: Needs additional authorization

**Policy Context:**
- Transaction details (to, from, value, data)
- Signer information (key ID, namespace, roles)
- Environment (timestamp, chain ID, simulation mode)

### Security Model

#### Authentication
- **mTLS (Mutual TLS)**: All clients must present valid X.509 certificates signed by the HSM's CA
- **OIDC/OAuth2**: Integration with identity providers (Okta, Auth0, Azure AD, Google)
- **Session Management**: Time-limited sessions with automatic expiration
- **Rate Limiting**: Configurable per-client and per-namespace rate limits

#### Authorization
- **RBAC (Role-Based Access Control)**: Fine-grained permissions system
  - `KeyAdmin`: Create, delete, rotate keys
  - `KeyUser`: Sign, encrypt, decrypt operations
  - `Auditor`: Read-only access to audit logs
  - `NamespaceAdmin`: Manage namespace configuration
- **ACLs (Access Control Lists)**: Per-key access restrictions
- **Namespace Isolation**: Complete logical separation between tenants

#### Audit Trail
- **Hash Chain**: Every audit event links to the previous event via cryptographic hash
- **Merkle Tree**: Periodic batch verification using Merkle root
- **Tamper Detection**: Automatic integrity verification on startup
- **Immutable Logs**: Append-only with log rotation and archival

### Storage & Durability

#### Encrypted Storage
- **Encryption-at-Rest**: AES-256-GCM for all key material
- **Key Encryption Key (KEK)**: Derived from master password using Argon2
- **Atomic Writes**: Write-ahead logging ensures consistency
- **Journaling**: Crash recovery via journal replay

#### Backup & Recovery
- **Full Backup**: Export all keys and configuration
- **Incremental Backup**: Export only changed keys since last backup
- **Shamir's Secret Sharing**: Split KEK into N shares, require M to recover
- **Encrypted Export**: Backups are encrypted with separate passphrase
- **Integrity Verification**: SHA-256 checksums for all backup artifacts

### Monitoring & Observability

#### Metrics (Prometheus Format)
```
# Operations
hsm_operations_total{operation="sign",namespace="default",result="success"}
hsm_operation_duration_seconds{operation="sign",quantile="0.99"}

# Keys
hsm_keys_total{namespace="default",algorithm="Ed25519",state="active"}

# Sessions
hsm_active_sessions{namespace="default"}

# Audit
hsm_audit_events_total{event_type="sign",result="success"}
hsm_audit_integrity_violations_total
```

#### Health Checks
- **Liveness**: `/health/live` - Server is running
- **Readiness**: `/health/ready` - Ready to accept requests
- **Startup**: `/health/startup` - Initialization complete

## Architecture

The HSM is built as a modular monolith with 23 independent crates organized into functional groups:

```
┌─────────────────────────────────────────────────────────────────┐
│                        API Layer                                 │
│         gRPC API (50051)  │  REST API  │  KMIP Server           │
├─────────────────────────────────────────────────────────────────┤
│                     Security & Auth                              │
│     Auth/RBAC/OIDC  │  WASM Policy Engine  │  Webhooks          │
├─────────────────────────────────────────────────────────────────┤
│                    Core Services                                 │
│  Key Manager │ Crypto Engine │ Audit │ Metrics │ Secrets        │
├─────────────────────────────────────────────────────────────────┤
│                   Blockchain & Web3                              │
│   HD Keys (BIP-32/39/44) │ EIP-191/712 │ Validator/Anti-Slash   │
│   Bitcoin │ Solana │ StarkNet                                    │
├─────────────────────────────────────────────────────────────────┤
│                  Storage & Recovery                              │
│     Storage  │  Backup/Shamir  │  Config  │  Hardware Backend   │
├─────────────────────────────────────────────────────────────────┤
│                 Advanced Cryptography                            │
│         ZK Proofs  │  Verification  │  PKCS#11 Bridge           │
└─────────────────────────────────────────────────────────────────┘
```

### Module Responsibilities

**Core HSM:**
| Module | Purpose | Key Types |
|--------|---------|-----------|
| **crypto-engine** | Cryptographic primitives | `Ed25519Signer`, `RsaSigner`, `AesGcm` |
| **key-manager** | Key lifecycle & policies | `KeyStore`, `RotationPolicy` |
| **auth** | Authentication, RBAC, OIDC | `MtlsAuthenticator`, `RbacPolicy`, `OidcProvider` |
| **audit** | Tamper-evident logging | `AuditLogger`, `TamperDetector` |
| **metrics** | Prometheus metrics | `MetricsCollector` |
| **storage** | Encrypted persistence | `EncryptedFileStorage` |
| **backup** | Backup & recovery | `BackupManager`, `ShamirSecretSharing` |
| **config** | Configuration management | `HsmConfig` |

**Blockchain & Web3:**
| Module | Purpose | Key Types |
|--------|---------|-----------|
| **blockchain** | HD keys, chain signing | `HdWallet`, `Eip191Signer`, `Eip712TypedData`, `StarknetKey` |
| **validator** | Anti-slashing protection | `SlashingDb`, `EthereumValidator`, `BabylonEots` |

**Policy & Events:**
| Module | Purpose | Key Types |
|--------|---------|-----------|
| **wasm-policy** | Custom WASM policies | `PolicyEngine`, `PolicyContext`, `PolicyDecision` |
| **webhooks** | Event delivery | `WebhookDispatcher`, `WebhookRegistry` |

**APIs & Protocols:**
| Module | Purpose | Key Types |
|--------|---------|-----------|
| **grpc-api** | gRPC server | `HsmServiceImpl` |
| **rest-api** | REST server | `RestService` |
| **kmip-server** | KMIP protocol | `KmipServer` |
| **pkcs11-bridge** | PKCS#11 interface | `Pkcs11Provider` |

**Advanced:**
| Module | Purpose | Key Types |
|--------|---------|-----------|
| **verification** | Signature verification | `SignatureVerifier` |
| **zk-proofs** | Zero-knowledge proofs | `ZkProver`, `ZkVerifier` |
| **hardware-backend** | Hardware HSM support | `HardwareProvider` |
| **secrets** | Secret management | `SecretStore` |

## Configuration

### Configuration File

Create `config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 50051
  max_connections: 1000
  timeout_seconds: 30
  tls_enabled: true
  tls_cert_path: "/etc/hsm/server-cert.pem"
  tls_key_path: "/etc/hsm/server-key.pem"
  tls_ca_cert_path: "/etc/hsm/ca-cert.pem"

storage:
  backend: "encrypted_file"
  data_dir: "/var/lib/hsm"
  cache_size_bytes: 104857600  # 100 MB
  wal_enabled: true
  sync_mode: "full"  # full | normal | none

security:
  key_derivation_iterations: 100000
  encryption_at_rest: true
  encryption_algorithm: "aes256gcm"
  session_timeout_seconds: 3600
  max_auth_attempts: 5
  lockout_duration_seconds: 300
  audit_log_enabled: true
  audit_log_path: "/var/log/hsm/audit.log"
  require_strong_passwords: true
  min_password_length: 12

logging:
  level: "info"  # trace | debug | info | warn | error
  format: "json"
  output: "both"  # console | file | both
  file_path: "/var/log/hsm/hsm.log"
  max_file_size_bytes: 104857600
  max_backup_files: 10

metrics:
  enabled: true
  format: "prometheus"
  listen_addr: "0.0.0.0"
  listen_port: 9090
  collection_interval_seconds: 60
  enable_histograms: true
  histogram_buckets: [0.001, 0.01, 0.1, 1.0, 10.0]

namespaces:
  default:
    description: "Default namespace"
    max_keys: 10000
    access_control:
      allowed_ips: []
      denied_ips: []
      max_concurrent_sessions: 100
```

### Environment Variables

Override configuration via environment variables:

```bash
export HSM_SERVER__PORT=50051
export HSM_STORAGE__DATA_DIR=/var/lib/hsm
export HSM_SECURITY__SESSION_TIMEOUT_SECONDS=7200
```

### Presets

Use configuration presets for common scenarios:

```rust
// Development (insecure, fast)
HsmConfig::development()

// Production (secure defaults)
HsmConfig::production()

// Testing (in-memory, minimal)
HsmConfig::test()
```

## Documentation

### API Documentation

Comprehensive API documentation is available as Rust documentation (rustdoc):

```bash
# Generate and open documentation for all crates
cargo doc --workspace --no-deps --open

# Or view specific crate documentation
cargo doc -p crypto-engine --no-deps --open
cargo doc -p audit --no-deps --open
cargo doc -p key-manager --no-deps --open
```

**What's Documented:**
- All public APIs with examples and error handling
- Module-level architecture overviews
- Security considerations for cryptographic functions
- Performance characteristics and complexity analysis
- Algorithm explanations (Merkle trees, hash chains, Shamir's Secret Sharing)

**Direct Links** (after building):
- [crypto-engine](target/doc/crypto_engine/index.html) - Cryptographic primitives
- [audit](target/doc/audit/index.html) - Tamper-evident logging
- [key-manager](target/doc/key_manager/index.html) - Key lifecycle management
- [auth](target/doc/auth/index.html) - Authentication & authorization
- [grpc-api](target/doc/grpc_api/index.html) - gRPC service implementation
- [storage](target/doc/storage/index.html) - Encrypted persistence
- [backup](target/doc/backup/index.html) - Backup & recovery
- [config](target/doc/hsm_config/index.html) - Configuration management
- [metrics](target/doc/metrics/index.html) - Prometheus metrics

### gRPC Service Definition

See `crates/grpc-api/proto/hsm.proto` for the complete API specification.

**Core Operations:**
- `GenerateKey(GenerateKeyRequest) -> GenerateKeyResponse`
- `ImportKey(ImportKeyRequest) -> ImportKeyResponse`
- `DeleteKey(DeleteKeyRequest) -> DeleteKeyResponse`
- `ListKeys(ListKeysRequest) -> ListKeysResponse`
- `RotateKey(RotateKeyRequest) -> RotateKeyResponse`

**Cryptographic Operations:**
- `Sign(SignRequest) -> SignResponse`
- `Verify(VerifyRequest) -> VerifyResponse`
- `Encrypt(EncryptRequest) -> EncryptResponse`
- `Decrypt(DecryptRequest) -> DecryptResponse`
- `Hash(HashRequest) -> HashResponse`

**Administrative:**
- `CreateNamespace(CreateNamespaceRequest) -> CreateNamespaceResponse`
- `GetAuditLog(GetAuditLogRequest) -> GetAuditLogResponse`
- `CreateBackup(CreateBackupRequest) -> CreateBackupResponse`
- `RestoreBackup(RestoreBackupRequest) -> RestoreBackupResponse`

### Client Libraries

```rust
// Rust client example
use tonic::transport::Channel;
use hsm_proto::hsm_service_client::HsmServiceClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = Channel::from_static("https://hsm.example.com:50051")
        .tls_config(tls_config)?
        .connect()
        .await?;

    let mut client = HsmServiceClient::new(channel);

    let request = tonic::Request::new(GenerateKeyRequest {
        namespace: "production".to_string(),
        key_id: "api-signing-key".to_string(),
        algorithm: Algorithm::Ed25519 as i32,
        ..Default::default()
    });

    let response = client.generate_key(request).await?;
    println!("Generated key: {:?}", response.get_ref());

    Ok(())
}
```

## Deployment

### Kubernetes

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: hsm
spec:
  serviceName: hsm
  replicas: 3
  selector:
    matchLabels:
      app: hsm
  template:
    metadata:
      labels:
        app: hsm
    spec:
      containers:
      - name: hsm
        image: stxkxs/hsm:latest
        ports:
        - containerPort: 50051
          name: grpc
        - containerPort: 9090
          name: metrics
        volumeMounts:
        - name: data
          mountPath: /var/lib/hsm
        - name: config
          mountPath: /etc/hsm
        env:
        - name: HSM_STORAGE__DATA_DIR
          value: /var/lib/hsm
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: hsm-config
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

### Docker Compose

```yaml
version: '3.8'
services:
  hsm:
    build: .
    ports:
      - "50051:50051"
      - "9090:9090"
    volumes:
      - ./data:/var/lib/hsm
      - ./config.yaml:/etc/hsm/config.yaml:ro
      - ./certs:/etc/hsm/certs:ro
    environment:
      RUST_LOG: info
```

## Performance

### Benchmarks

Measured on Apple M1 Pro (single-threaded):

| Operation                | Throughput        | Latency (p99) |
|--------------------------|-------------------|---------------|
| Ed25519 Sign             | 12,000 ops/sec    | 0.2 ms        |
| Ed25519 Verify           | 8,500 ops/sec     | 0.3 ms        |
| ECDSA P-256 Sign         | 3,200 ops/sec     | 0.8 ms        |
| AES-256-GCM Encrypt      | 850 MB/sec        | 0.1 ms        |
| Key Generation (Ed25519) | 9,000 ops/sec     | 0.3 ms        |
| Audit Log Write          | 15,000 events/sec | 0.15 ms       |

Run benchmarks:
```bash
cargo bench --workspace
```

### Optimization Tips

1. **Batch Operations**: Use batch APIs for multiple operations
2. **Session Reuse**: Keep sessions alive to avoid re-authentication
3. **Connection Pooling**: Maintain persistent gRPC connections
4. **Disable Sync Writes**: Set `sync_mode: "normal"` for non-critical data (testing only)
5. **Tune Cache Size**: Increase `cache_size_bytes` for key-heavy workloads

## Development

### Project Structure

```
hsm/
├── crates/
│   ├── crypto-engine/      # Cryptographic primitives
│   ├── key-manager/        # Key lifecycle management
│   ├── auth/               # Authentication, RBAC, OIDC
│   ├── grpc-api/           # gRPC server implementation
│   ├── rest-api/           # REST server implementation
│   ├── audit/              # Audit logging & tamper detection
│   ├── metrics/            # Prometheus metrics
│   ├── storage/            # Encrypted storage backend
│   ├── backup/             # Backup & recovery
│   ├── config/             # Configuration management
│   ├── hsm-server/         # Main binary
│   ├── blockchain/         # HD keys, EIP-191/712, multi-chain
│   ├── validator/          # Anti-slashing for ETH/Babylon
│   ├── wasm-policy/        # WASM policy engine
│   ├── webhooks/           # Event delivery system
│   ├── verification/       # Signature verification
│   ├── zk-proofs/          # Zero-knowledge proofs
│   ├── hardware-backend/   # Hardware HSM support
│   ├── pkcs11-bridge/      # PKCS#11 interface
│   ├── secrets/            # Secret management
│   ├── kmip-server/        # KMIP protocol support
│   ├── cluster/            # Raft-based high availability
│   └── bridge-monitor/     # Cross-chain bridge monitoring
├── docs/
│   ├── architecture/       # Design documents
│   └── phases/             # Implementation plans
├── .claude/                # Claude Code configuration
│   ├── skills/             # Custom development skills
│   └── settings.json       # Hooks and preferences
└── config/                 # Example configurations
```

### Running Tests

```bash
# All tests
cargo test --workspace

# Specific module
cargo test -p crypto-engine

# Integration tests
cargo test --test integration_tests

# With output
cargo test -- --nocapture

# Performance tests (with warnings, not failures)
cargo test performance
```

### Code Quality

```bash
# Format code
cargo fmt --all

# Linting
cargo clippy --all -- -D warnings

# Security audit
cargo audit

# Test coverage
cargo install cargo-llvm-cov
cargo llvm-cov --workspace --lib --summary-only

# Generate HTML coverage report
cargo llvm-cov --workspace --lib --html
open target/llvm-cov/html/index.html

# Check for outdated dependencies
cargo outdated

# Fuzzing (crypto-engine only)
cd crates/crypto-engine
cargo fuzz run fuzz_ed25519_sign
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`cargo test --workspace`)
5. Run clippy (`cargo clippy --all -- -D warnings`)
6. Commit your changes (`git commit -m 'add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

**Code Style:**
- Follow Rust standard formatting (`cargo fmt`)
- Write comprehensive tests for new features
- Update rustdoc documentation for API changes (use `///` for functions, `//!` for modules)
- Include examples in documentation where applicable
- Document security considerations for crypto/auth code
- Remove trivial comments - prefer self-documenting code

## Security Considerations

### Threat Model

**Protected Against:**
- Unauthorized access to key material
- Tampering with audit logs
- Replay attacks
- Session hijacking
- Insider threats (via RBAC and audit)

**Not Protected Against:**
- Memory attacks on running process (use hardware HSM for this)
- Physical access to storage media (encryption at rest mitigates)
- Compromise of CA private key (rotate CA periodically)
- Side-channel attacks (constant-time crypto used where possible)

### Known Vulnerabilities

**RUSTSEC-2023-0071: RSA Marvin Attack** (Medium Severity)
- **Affected**: RSA encryption/decryption operations
- **Issue**: Potential key recovery through timing sidechannels in PKCS#1 v1.5 decryption
- **Mitigation**: No upstream fix available. Recommend using OAEP padding instead of PKCS#1 v1.5 when possible
- **Reference**: https://rustsec.org/advisories/RUSTSEC-2023-0071

**RUSTSEC-2024-0398: Shamir Secret Sharing Coefficient Bias**
- **Affected**: Backup and recovery using Shamir's Secret Sharing
- **Issue**: Potential bias in polynomial coefficients during secret splitting
- **Mitigation**: No upstream fix available. Consider additional randomness sources for critical key splits
- **Reference**: https://rustsec.org/advisories/RUSTSEC-2024-0398

The two advisories above carry security-relevant mitigations. The full, canonical list of
accepted transitive advisories (all unmaintained-crate warnings with no upstream fix and no
runtime exposure — e.g. `paste`, `fxhash`, `derivative`, `serde_cbor`) is tracked with
per-entry rationale in [`.cargo/audit.toml`](.cargo/audit.toml). `cargo audit --deny warnings`
passes against that ignore list.

### Best Practices

1. **Key Rotation**: Rotate KEK and data keys regularly
2. **Access Control**: Use least-privilege RBAC policies
3. **Audit Review**: Monitor audit logs for suspicious activity
4. **Backup Security**: Store backups in separate, secure location
5. **TLS Configuration**: Use strong cipher suites and TLS 1.3+
6. **Rate Limiting**: Configure appropriate rate limits per namespace
7. **Monitoring**: Set up alerts for metric anomalies

### Compliance

This HSM implementation can help meet requirements for:
- **PCI DSS**: Key management and audit logging
- **HIPAA**: Encryption at rest and access controls
- **SOC 2**: Audit trails and access management
- **GDPR**: Data encryption and access logging

## Troubleshooting

### Common Issues

**HSM fails to start:**
```bash
# Check logs
tail -f /var/log/hsm/hsm.log

# Verify configuration
cargo run --bin hsm-server -- --config config.yaml --validate

# Check permissions
ls -la /var/lib/hsm
```

**Authentication failures:**
```bash
# Verify certificates
openssl verify -CAfile ca-cert.pem client-cert.pem

# Check certificate dates
openssl x509 -in client-cert.pem -noout -dates

# Enable debug logging
export RUST_LOG=debug
```

**Performance degradation:**
```bash
# Check metrics
curl http://localhost:9090/metrics | grep hsm_operation_duration

# Monitor resource usage
htop

# Check storage I/O
iostat -x 1
```

## License

Dual-licensed under your choice of:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

## Acknowledgments

Built with:
- [RustCrypto](https://github.com/RustCrypto) - Cryptographic implementations
- [Tonic](https://github.com/hyperium/tonic) - gRPC framework
- [Tokio](https://github.com/tokio-rs/tokio) - Async runtime
- [Prometheus](https://prometheus.io/) - Metrics and monitoring
