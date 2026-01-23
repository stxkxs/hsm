# Hardware Security Module (HSM) Specification

## Executive Summary

Build a production-grade, software-based HSM in Rust that runs as a secure service in Kubernetes (EKS). The HSM will provide multi-purpose cryptographic operations with enterprise-grade security, multi-tenancy, comprehensive audit logging, and high performance.

## Requirements

### Functional Requirements

#### Cryptographic Operations
- **Asymmetric Algorithms**
  - RSA: 2048, 3072, 4096-bit (PKCS#1 v1.5 and PSS padding)
  - ECDSA: P-256, P-384, P-521 (NIST curves)
  - Ed25519/Ed448 (EdDSA)
- **Symmetric Algorithms**
  - AES: 128, 256-bit (GCM, CBC, CTR modes)
- **Hashing**
  - SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512
- **Key Derivation**
  - HKDF, PBKDF2, Argon2

#### Key Management
- Key generation with cryptographically secure randomness
- Key import (wrapped and unwrapped)
- Key export (encrypted only, never plaintext)
- Key rotation with version tracking
- Key deletion (secure wiping)
- Key lifecycle states: pending, active, deactivated, compromised, destroyed
- Key attributes: usage policy, expiration, owner namespace

#### Authentication & Authorization
- mTLS for client authentication
- Namespace-based multi-tenancy isolation
- Role-Based Access Control (RBAC):
  - `admin`: Full control within namespace
  - `operator`: Create/use keys, cannot delete
  - `user`: Use existing keys only
  - `auditor`: Read-only access to logs and metadata
- Per-key access control lists (ACLs)

#### Storage & Persistence
- Encrypted key storage on persistent volume
- Master key encryption using envelope encryption
- Storage format: encrypted protobuf or custom binary format
- Atomic write operations with journaling
- Automatic corruption detection via checksums

#### Backup & Recovery
- Encrypted key export to external storage
- Master key escrow/split (Shamir's Secret Sharing)
- Disaster recovery procedures
- Point-in-time recovery support

#### Audit & Compliance
- Comprehensive audit logging:
  - Every cryptographic operation
  - All administrative actions
  - Authentication attempts (success/failure)
  - Key lifecycle events
- Tamper-evident logs using Merkle tree or hash chain
- Structured logging (JSON) for easy parsing
- Log retention policies

#### Monitoring & Observability
- Prometheus metrics:
  - Operation counters (by type, namespace, status)
  - Latency histograms (p50, p95, p99)
  - Key count gauges (by type, namespace, state)
  - Error rates
  - TLS handshake metrics
- Health check endpoints
- Liveness and readiness probes

### Non-Functional Requirements

#### Security
- Keys never exposed in plaintext outside secure boundary
- Memory encryption for sensitive data (using `secrecy`, `zeroize` crates)
- Constant-time operations where possible
- Side-channel attack mitigation
- Regular security dependency updates
- FIPS 140-2 considerations (document deviations)

#### Performance
- Target: 1000+ signing operations/second (Ed25519)
- Target: 500+ RSA-2048 operations/second
- Concurrent request handling (tokio async runtime)
- Connection pooling and keep-alive
- Batch operation support

#### Reliability
- 99.9% availability target
- Graceful degradation
- Circuit breaker for external dependencies
- Automatic recovery from transient failures
- No single point of failure (when clustered)

#### Scalability
- Horizontal scaling via StatefulSet
- Support 10,000+ keys per instance
- Support 100+ concurrent connections
- Namespace isolation for multi-tenancy

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                           HSM Service                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                      API Layer                               │    │
│  │   gRPC Server (50051)  │  REST API  │  KMIP  │  PKCS#11     │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                        │
│  ┌───────────────────────────┼─────────────────────────────────┐    │
│  │                  Security Layer                              │    │
│  │   mTLS/OIDC Auth  │  RBAC  │  WASM Policy Engine            │    │
│  └───────────────────────────┼─────────────────────────────────┘    │
│                              │                                        │
│  ┌───────────────────────────┼─────────────────────────────────┐    │
│  │                  Core Services                               │    │
│  │  ┌─────────────┐  ┌─────────────────┐  ┌────────────────┐   │    │
│  │  │Crypto Engine│  │  Key Manager    │  │ Audit Logger   │   │    │
│  │  │- RSA/ECDSA  │  │  - Generation   │  │ - Hash chain   │   │    │
│  │  │- Ed25519    │  │  - Rotation     │  │ - Merkle tree  │   │    │
│  │  │- AES-GCM    │  │  - HD Derivation│  │ - Webhooks     │   │    │
│  │  └─────────────┘  └─────────────────┘  └────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                  Blockchain & Web3                           │    │
│  │   BIP-32/39/44  │  EIP-191/712  │  Multi-chain Signing      │    │
│  │   Validator Anti-Slashing (Ethereum, Babylon)                │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                  Storage & Infrastructure                    │    │
│  │   Encrypted Storage  │  Backup/SSS  │  Metrics  │  Config   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Request Flow**
   - Client establishes mTLS connection
   - gRPC request received and authenticated
   - Namespace and RBAC checks applied
   - Request routed to appropriate handler
   - Cryptographic operation performed
   - Audit log entry created
   - Response returned with metrics updated

2. **Key Storage Flow**
   - Key generated in memory (encrypted immediately)
   - Key metadata created
   - Key encrypted with master key (AES-256-GCM)
   - Encrypted key + metadata written to persistent storage
   - Audit log entry created

3. **Audit Log Flow**
   - Operation logged with full context
   - Log entry hashed and linked to previous entry (hash chain)
   - Merkle tree updated
   - Log persisted to disk and optionally forwarded to external log aggregator

## Module Breakdown

### Module 1: Core Cryptographic Engine
**Purpose**: Perform all cryptographic operations securely and efficiently

**Responsibilities**:
- Asymmetric operations: sign, verify, encrypt, decrypt
- Symmetric operations: encrypt, decrypt (AES-GCM, AES-CBC)
- Hashing and digest computation
- Key derivation functions
- Secure random number generation

**Dependencies**:
- `ring` or `RustCrypto` crates for crypto primitives
- `ed25519-dalek` for Ed25519
- `p256`, `p384`, `p521` for ECDSA
- `rsa` crate for RSA operations
- `aes-gcm` for symmetric encryption

**Key Interfaces**:
```rust
pub trait CryptoEngine {
    fn sign(&self, key: &Key, data: &[u8], algorithm: SignAlgorithm) -> Result<Vec<u8>>;
    fn verify(&self, key: &Key, data: &[u8], signature: &[u8]) -> Result<bool>;
    fn encrypt(&self, key: &Key, plaintext: &[u8], algorithm: EncryptAlgorithm) -> Result<Vec<u8>>;
    fn decrypt(&self, key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn hash(&self, data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>>;
}
```

**Testing**:
- Unit tests for each algorithm
- Known-answer tests (KAT) from NIST
- Fuzz testing with `cargo-fuzz`
- Performance benchmarks

---

### Module 2: Key Management Module
**Purpose**: Manage the complete lifecycle of cryptographic keys

**Responsibilities**:
- Key generation with secure entropy
- Key storage and retrieval
- Key metadata management (creation time, usage policy, expiration)
- Key rotation and versioning
- Key state management (active, deactivated, compromised, destroyed)
- Key deletion with secure memory wiping

**Dependencies**:
- `getrandom` for secure randomness
- `zeroize` for secure memory wiping
- `secrecy` for protecting sensitive data in memory

**Key Interfaces**:
```rust
pub trait KeyManager {
    fn generate_key(&mut self, spec: KeySpec, namespace: &str) -> Result<KeyId>;
    fn import_key(&mut self, key_data: EncryptedKey, namespace: &str) -> Result<KeyId>;
    fn get_key(&self, key_id: &KeyId, namespace: &str) -> Result<Key>;
    fn list_keys(&self, namespace: &str, filter: KeyFilter) -> Result<Vec<KeyMetadata>>;
    fn rotate_key(&mut self, key_id: &KeyId) -> Result<KeyId>;
    fn update_key_state(&mut self, key_id: &KeyId, state: KeyState) -> Result<()>;
    fn delete_key(&mut self, key_id: &KeyId) -> Result<()>;
}
```

**Testing**:
- Key lifecycle tests
- Concurrent access tests
- Key isolation tests (namespace separation)
- Memory leak tests (valgrind)

---

### Module 3: Authentication & Authorization
**Purpose**: Secure client authentication and fine-grained access control

**Responsibilities**:
- mTLS handshake and certificate validation
- Client identity extraction from certificates
- Namespace mapping and isolation
- RBAC policy enforcement
- Per-key ACL checks
- Session management

**Dependencies**:
- `rustls` for TLS 1.3
- `tokio-rustls` for async TLS
- `x509-parser` for certificate parsing
- `webpki` for certificate validation

**Key Interfaces**:
```rust
pub trait Authenticator {
    fn authenticate(&self, cert: &Certificate) -> Result<ClientIdentity>;
}

pub trait Authorizer {
    fn authorize(&self, identity: &ClientIdentity, operation: Operation, resource: &Resource) -> Result<()>;
    fn check_namespace_access(&self, identity: &ClientIdentity, namespace: &str) -> Result<()>;
}
```

**Testing**:
- Certificate validation tests
- RBAC policy tests
- Namespace isolation tests
- Negative tests (unauthorized access attempts)

---

### Module 4: gRPC API Server
**Purpose**: Expose HSM functionality via high-performance gRPC API

**Responsibilities**:
- gRPC service implementation
- Request/response serialization (protobuf)
- Connection management
- Rate limiting and throttling
- Request validation
- Error handling and status codes

**Dependencies**:
- `tonic` for gRPC framework
- `prost` for protobuf serialization
- `tokio` for async runtime

**API Definitions** (`proto/hsm.proto`):
```protobuf
service HSM {
  // Key Management
  rpc GenerateKey(GenerateKeyRequest) returns (GenerateKeyResponse);
  rpc ImportKey(ImportKeyRequest) returns (ImportKeyResponse);
  rpc ExportKey(ExportKeyRequest) returns (ExportKeyResponse);
  rpc DeleteKey(DeleteKeyRequest) returns (DeleteKeyResponse);
  rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);
  rpc GetKeyMetadata(GetKeyMetadataRequest) returns (GetKeyMetadataResponse);
  rpc RotateKey(RotateKeyRequest) returns (RotateKeyResponse);

  // Cryptographic Operations
  rpc Sign(SignRequest) returns (SignResponse);
  rpc Verify(VerifyRequest) returns (VerifyResponse);
  rpc Encrypt(EncryptRequest) returns (EncryptResponse);
  rpc Decrypt(DecryptRequest) returns (DecryptResponse);
  rpc Hash(HashRequest) returns (HashResponse);
  rpc DeriveKey(DeriveKeyRequest) returns (DeriveKeyResponse);

  // Batch Operations
  rpc BatchSign(BatchSignRequest) returns (BatchSignResponse);

  // Audit & Monitoring
  rpc GetAuditLogs(GetAuditLogsRequest) returns (stream AuditLogEntry);
  rpc VerifyAuditLog(VerifyAuditLogRequest) returns (VerifyAuditLogResponse);

  // Health
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}
```

**Testing**:
- Integration tests with gRPC clients
- Load testing with `ghz`
- Error handling tests
- Timeout and retry tests

---

### Module 5: Audit & Logging System
**Purpose**: Comprehensive, tamper-evident audit trail of all operations

**Responsibilities**:
- Log all cryptographic operations
- Log authentication/authorization events
- Log key lifecycle events
- Create tamper-evident log chain (Merkle tree)
- Periodic log verification
- Log rotation and archival
- Integration with external log systems (optional)

**Dependencies**:
- `tracing` for structured logging
- `tracing-subscriber` for log formatting
- `serde_json` for JSON serialization
- Custom Merkle tree implementation

**Key Interfaces**:
```rust
pub trait AuditLogger {
    fn log_operation(&mut self, event: AuditEvent) -> Result<()>;
    fn get_logs(&self, filter: LogFilter) -> Result<Vec<AuditEvent>>;
    fn verify_log_integrity(&self, from: LogIndex, to: LogIndex) -> Result<bool>;
    fn get_merkle_root(&self) -> Result<Hash>;
}
```

**Log Format**:
```json
{
  "timestamp": "2026-01-15T10:30:45.123Z",
  "sequence": 12345,
  "event_type": "crypto_operation",
  "operation": "sign",
  "namespace": "production",
  "client_id": "service-a",
  "key_id": "key-abc123",
  "algorithm": "Ed25519",
  "result": "success",
  "latency_ms": 2.3,
  "prev_hash": "a1b2c3...",
  "current_hash": "d4e5f6..."
}
```

**Testing**:
- Log integrity tests
- Tamper detection tests
- Performance tests (high-throughput logging)
- Log verification tests

---

### Module 6: Metrics & Monitoring
**Purpose**: Real-time observability and performance monitoring

**Responsibilities**:
- Expose Prometheus metrics
- Track operation counters, latencies, errors
- Monitor key usage and storage
- Health check endpoints
- Custom dashboards support

**Dependencies**:
- `prometheus` crate for metrics
- `axum` or `warp` for HTTP metrics endpoint

**Metrics**:
```
# Counters
hsm_operations_total{operation="sign",algorithm="Ed25519",namespace="prod",status="success"}
hsm_keys_total{namespace="prod",type="Ed25519",state="active"}
hsm_auth_attempts_total{status="success"}

# Histograms
hsm_operation_duration_seconds{operation="sign",algorithm="Ed25519"}
hsm_key_generation_duration_seconds{type="RSA-2048"}

# Gauges
hsm_active_connections
hsm_memory_usage_bytes
hsm_storage_usage_bytes
```

**Testing**:
- Metrics accuracy tests
- Scraping endpoint tests
- Dashboard validation

---

### Module 7: Storage Backend
**Purpose**: Secure, reliable persistence of encrypted keys

**Responsibilities**:
- Encrypt keys before writing to disk (AES-256-GCM)
- Atomic write operations with journaling
- Corruption detection via checksums
- Concurrent access control
- Namespace-based directory structure
- Automatic compaction and cleanup

**Dependencies**:
- `sled` or `rocksdb` for embedded database (optional)
- `aes-gcm` for encryption
- `sha2` for checksums

**Storage Layout**:
```
/data/hsm/
├── master_key.enc          # Encrypted master key
├── namespaces/
│   ├── production/
│   │   ├── keys/
│   │   │   ├── key-abc123.enc
│   │   │   └── key-def456.enc
│   │   └── metadata.db
│   └── staging/
│       └── ...
└── audit/
    └── logs/
        ├── 2026-01-15.log
        └── merkle_tree.dat
```

**Key Interfaces**:
```rust
pub trait StorageBackend {
    fn store_key(&mut self, key_id: &KeyId, encrypted_key: &[u8], namespace: &str) -> Result<()>;
    fn load_key(&self, key_id: &KeyId, namespace: &str) -> Result<Vec<u8>>;
    fn delete_key(&mut self, key_id: &KeyId, namespace: &str) -> Result<()>;
    fn list_keys(&self, namespace: &str) -> Result<Vec<KeyId>>;
    fn sync(&mut self) -> Result<()>;
}
```

**Testing**:
- Encryption/decryption tests
- Corruption recovery tests
- Concurrent access tests
- Performance benchmarks

---

### Module 8: Backup & Recovery
**Purpose**: Disaster recovery and key export/import

**Responsibilities**:
- Encrypted key export (AES-256-GCM with user-provided password or key)
- Key import with validation
- Master key split/recovery (Shamir's Secret Sharing)
- Backup verification
- Point-in-time recovery support

**Dependencies**:
- `sharks` for Shamir's Secret Sharing
- `aes-gcm` for encryption
- `argon2` for key derivation from passwords

**Key Interfaces**:
```rust
pub trait BackupManager {
    fn export_keys(&self, namespace: &str, encryption_key: &[u8]) -> Result<Vec<u8>>;
    fn import_keys(&mut self, backup_data: &[u8], encryption_key: &[u8]) -> Result<usize>;
    fn split_master_key(&self, threshold: u8, shares: u8) -> Result<Vec<Vec<u8>>>;
    fn recover_master_key(&mut self, shares: &[Vec<u8>]) -> Result<()>;
}
```

**Testing**:
- Export/import round-trip tests
- Master key recovery tests
- Encryption strength tests

---

### Module 9: Configuration Management
**Purpose**: Runtime configuration and policy management

**Responsibilities**:
- Load configuration from files (YAML/TOML)
- Environment variable overrides
- Hot reload of policies (where safe)
- Configuration validation
- Default policies

**Dependencies**:
- `serde` for serialization
- `config` crate for configuration management
- `toml` or `serde_yaml`

**Configuration Structure**:
```yaml
server:
  bind_address: "0.0.0.0:8443"
  tls_cert: "/etc/hsm/certs/server.crt"
  tls_key: "/etc/hsm/certs/server.key"
  ca_cert: "/etc/hsm/certs/ca.crt"
  max_connections: 1000
  request_timeout: "30s"

storage:
  data_dir: "/data/hsm"
  sync_interval: "5s"
  backup_dir: "/backups/hsm"

security:
  master_key_path: "/secrets/master.key"
  key_rotation_interval: "90d"
  min_key_size:
    rsa: 2048
    ecdsa: 256

logging:
  level: "info"
  format: "json"
  output: "/var/log/hsm/audit.log"
  rotation: "daily"
  retention: "365d"

metrics:
  enabled: true
  bind_address: "0.0.0.0:9090"

namespaces:
  production:
    max_keys: 10000
    allowed_algorithms: ["Ed25519", "ECDSA-P256", "RSA-2048"]
  staging:
    max_keys: 1000
    allowed_algorithms: ["Ed25519"]
```

**Testing**:
- Configuration parsing tests
- Validation tests
- Default value tests

---

### Module 10: Blockchain & Web3
**Purpose**: HD key derivation, multi-chain signing, and blockchain-specific transaction support

**Responsibilities**:
- BIP-32/39/44 hierarchical deterministic key derivation
- Mnemonic phrase generation and recovery (12/24 words)
- Ethereum signing (EIP-191 personal messages, EIP-712 typed data)
- Bitcoin address generation and transaction signing
- Solana Ed25519-based signing
- StarkNet Stark curve ECDSA and SNIP-12 typed data

**Dependencies**:
- `bip32`, `bip39` for HD key derivation
- `alloy-primitives`, `alloy-rlp` for Ethereum types
- `k256` for secp256k1 operations
- `bitcoin` crate for Bitcoin support
- `ed25519-dalek` for Solana
- `starknet-crypto` for StarkNet

**Key Types**:
```rust
pub struct HdWallet {
    mnemonic: Mnemonic,
    seed: [u8; 64],
}

pub struct Eip712TypedData {
    types: HashMap<String, Vec<TypedDataField>>,
    primary_type: String,
    domain: EIP712Domain,
    message: Value,
}
```

**Testing**:
- BIP-32/39/44 test vectors from specifications
- EIP-712 test vectors from Ethereum Foundation
- Cross-chain address derivation tests

---

### Module 11: Transaction Policy Engine
**Purpose**: WASM-based custom transaction authorization policies

**Responsibilities**:
- Load and validate WASM policy modules
- Execute policies in sandboxed environment
- Enforce resource limits (fuel/gas, memory, time)
- Cache compiled policies for performance
- Provide host functions for policy context access

**Dependencies**:
- `wasmtime` for WASM runtime
- `lru` for module caching
- `dashmap` for concurrent policy storage

**Policy Interface**:
```rust
// WASM policies export this function
fn evaluate(context_ptr: i32, context_len: i32) -> i32
// Returns: 0 = deny, 1 = allow, 2 = require_approval

pub struct PolicyContext {
    pub transaction: TransactionContext,  // to, from, value, data
    pub signer: SignerContext,             // key_id, namespace, roles
    pub environment: EnvironmentContext,  // timestamp, chain_id
}
```

**Resource Limits**:
- Fuel-based instruction limiting (gas metering)
- Memory limits per policy execution
- Execution time limits
- Host call limits

**Testing**:
- Policy evaluation with WAT test modules
- Resource limit enforcement tests
- Policy caching performance tests

---

### Module 12: Validator Anti-Slashing
**Purpose**: Protect validator keys from slashable offenses

**Responsibilities**:
- Ethereum validator slashing protection
  - Double vote prevention (same target epoch, different root)
  - Surrounding vote detection
  - Surrounded vote detection
  - Double block proposal prevention
- Babylon EOTS (Extractable One-Time Signatures)
  - Height-based double-sign prevention
  - Private key protection (double-sign reveals key)
- EIP-3076 slashing protection interchange format
- Persistent slashing database with atomic operations

**Dependencies**:
- `sled` for persistent storage
- `serde` for serialization

**Key Types**:
```rust
pub struct SlashingDb {
    db: sled::Db,
    validators: Tree,    // pubkey -> ValidatorRecord
    attestations: Tree,  // pubkey:epoch -> AttestationRecord
    blocks: Tree,        // pubkey:slot -> BlockRecord
}

pub struct AttestationRecord {
    source_epoch: u64,
    target_epoch: u64,
    signing_root: [u8; 32],
}
```

**Security Properties**:
- Protection cannot be disabled (no bypass API)
- Atomic check-and-record prevents TOCTOU attacks
- Crash-safe via write-ahead logging
- Survives restarts with persistent storage

**Testing**:
- Double vote detection tests
- Surrounding vote detection tests
- EIP-3076 interchange import/export tests
- Crash recovery tests

---

### Module 13: Webhooks
**Purpose**: Event-driven notifications for external integrations

**Responsibilities**:
- Webhook registration and management
- Async event dispatch with retry logic
- HMAC-SHA256 signature for payload verification
- Event filtering by type and namespace
- Delivery tracking and metrics

**Dependencies**:
- `reqwest` for HTTP delivery
- `tokio` for async dispatch

**Event Types**:
- `key.created`, `key.deleted`, `key.rotated`, `key.used`
- `session.created`, `session.expired`, `session.revoked`
- `policy.violated`, `policy.updated`
- `backup.started`, `backup.completed`

**Webhook Payload**:
```json
{
  "id": "evt_abc123",
  "type": "key.created",
  "timestamp": "2024-01-15T10:30:00Z",
  "namespace": "production",
  "data": {
    "key_id": "signing-key-1",
    "algorithm": "Ed25519"
  }
}
```

**Testing**:
- Webhook delivery tests with mock server
- Retry logic tests
- Signature verification tests

---

## Parallel Development Plan

The HSM is built using **13 core modules** that can be developed independently with well-defined interfaces. Additional utility crates (rest-api, verification, zk-proofs, hardware-backend, pkcs11-bridge, secrets, kmip-server) provide specialized functionality.

### Phase 1: Foundation (Weeks 1-2)

**Track 1: Project Setup**
- Initialize Rust workspace with cargo workspaces
- Set up CI/CD pipeline (GitHub Actions)
- Configure linting (clippy, rustfmt)
- Set up security scanning (cargo-audit, cargo-deny)

**Track 2: Core Crypto Engine**
- Implement cryptographic primitives wrapper
- Add RSA, ECDSA, Ed25519, AES support
- Write comprehensive unit tests
- Run KAT tests

**Track 3: Key Management Module**
- Design key data structures
- Implement key generation
- Implement in-memory key store (stub storage)
- Add key lifecycle management

**Track 4: Storage Backend**
- Design storage schema
- Implement encrypted file storage
- Add journaling and atomic writes
- Write persistence tests

### Phase 2: API & Security (Weeks 3-4)

**Track 5: Authentication & Authorization**
- Implement mTLS authenticator
- Build RBAC engine
- Add namespace isolation
- Write security tests

**Track 6: gRPC API Server**
- Define protobuf schemas
- Implement gRPC services
- Add request validation
- Wire up to crypto engine and key manager

**Track 7: Configuration Management**
- Design configuration schema
- Implement config loader
- Add validation logic
- Create default configurations

### Phase 3: Observability & Resilience (Weeks 5-6)

**Track 8: Audit & Logging**
- Implement structured logging
- Build tamper-evident log chain
- Add Merkle tree for log verification
- Create log query interface

**Track 9: Metrics & Monitoring**
- Implement Prometheus exporter
- Add operation metrics
- Create health check endpoints
- Build sample Grafana dashboards

**Track 10: Backup & Recovery**
- Implement key export/import
- Add Shamir secret sharing for master key
- Create backup verification
- Write disaster recovery tests

### Phase 4: Integration & Hardening (Weeks 7-8)

**All Tracks: Integration**
- Integration testing across all modules
- End-to-end testing
- Performance testing and optimization
- Security audit and penetration testing
- Load testing (target: 1000 ops/sec)
- Documentation and runbooks

---

## Security Model

### Threat Model

**Assets**:
1. Cryptographic keys (primary asset)
2. Master encryption key
3. Audit logs
4. Client certificates and credentials

**Threats**:
1. **Key Extraction**: Attacker gains access to keys in plaintext
2. **Unauthorized Operations**: Attacker performs crypto operations without authorization
3. **Log Tampering**: Attacker modifies or deletes audit logs
4. **Denial of Service**: Attacker overwhelms HSM with requests
5. **Side-Channel Attacks**: Attacker infers key material via timing/power analysis
6. **Insider Threats**: Malicious administrator abuses privileges
7. **Supply Chain**: Compromised dependencies

**Mitigations**:
1. **Key Extraction**
   - Keys encrypted at rest (AES-256-GCM)
   - Keys encrypted in memory (`secrecy` crate)
   - No plaintext key export
   - Secure memory wiping (`zeroize`)

2. **Unauthorized Operations**
   - mTLS client authentication
   - RBAC with principle of least privilege
   - Per-key ACLs
   - Namespace isolation

3. **Log Tampering**
   - Tamper-evident logs (hash chain + Merkle tree)
   - Write-once audit logs
   - External log forwarding (optional)

4. **Denial of Service**
   - Rate limiting per client
   - Connection limits
   - Request timeouts
   - Resource quotas per namespace

5. **Side-Channel Attacks**
   - Constant-time crypto operations (where available)
   - Memory access pattern obfuscation
   - Limited scope (software HSM)

6. **Insider Threats**
   - Principle of least privilege
   - Comprehensive audit logging
   - Master key split (Shamir)
   - Separation of duties

7. **Supply Chain**
   - Dependency pinning
   - Regular security audits (`cargo-audit`)
   - Minimal dependencies
   - Reproducible builds

### Security Best Practices

1. **Defense in Depth**: Multiple layers of security
2. **Fail Secure**: Default deny, fail closed
3. **Least Privilege**: Minimum necessary permissions
4. **Separation of Concerns**: Isolate security-critical code
5. **Secure Defaults**: Safe configuration out-of-the-box
6. **Audit Everything**: Complete audit trail
7. **Regular Updates**: Keep dependencies current
8. **Code Reviews**: All security-critical code reviewed

---

## Performance Targets

| Operation                 | Target Throughput | Target Latency (p99) |
|---------------------------|-------------------|----------------------|
| Ed25519 Sign              | 1000+ ops/sec     | < 5ms                |
| Ed25519 Verify            | 500+ ops/sec      | < 10ms               |
| ECDSA-P256 Sign           | 500+ ops/sec      | < 10ms               |
| RSA-2048 Sign             | 300+ ops/sec      | < 20ms               |
| AES-256-GCM Encrypt       | 5000+ ops/sec     | < 2ms                |
| Key Generation (Ed25519)  | 100+ ops/sec      | < 50ms               |
| Key Generation (RSA-2048) | 10+ ops/sec       | < 500ms              |

---

## Testing Strategy

### Unit Tests
- Each module has >80% code coverage
- Focus on edge cases and error paths
- Mock external dependencies

### Integration Tests
- Test module interactions
- Test complete request flows
- Test failure scenarios

### Security Tests
- Penetration testing
- Fuzzing with `cargo-fuzz`
- Static analysis with `cargo-clippy`
- Dependency scanning with `cargo-audit`

### Performance Tests
- Benchmark all crypto operations
- Load testing with `ghz` or custom clients
- Latency profiling
- Memory profiling

### Chaos Engineering
- Random pod termination
- Network partitions
- Disk failures
- Concurrent access stress tests

---

## Deployment

### Kubernetes Deployment

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
        image: hsm:latest
        ports:
        - containerPort: 8443
          name: grpc
        - containerPort: 9090
          name: metrics
        volumeMounts:
        - name: data
          mountPath: /data/hsm
        - name: config
          mountPath: /etc/hsm
        - name: certs
          mountPath: /etc/hsm/certs
        env:
        - name: HSM_MASTER_KEY
          valueFrom:
            secretKeyRef:
              name: hsm-master-key
              key: key
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          grpc:
            port: 8443
            service: liveness
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          grpc:
            port: 8443
            service: readiness
          initialDelaySeconds: 5
          periodSeconds: 5
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 10Gi
```

---

## Future Enhancements

1. **Hardware Integration**: Support for HSM hardware backends (YubiHSM, AWS CloudHSM)
2. **Clustering**: Active-active replication for high availability
3. **Key Federation**: Cross-cluster key synchronization
4. **Advanced Algorithms**: Post-quantum cryptography (Kyber, Dilithium)
5. **PKCS#11 Interface**: Standard HSM interface support
6. **TPM Integration**: Leverage TPM for root of trust
7. **Distributed Key Generation**: MPC-based key generation
8. **Compliance Certifications**: FIPS 140-3, Common Criteria

---

## Success Criteria

1. **Functionality**: All cryptographic operations work correctly with KAT validation
2. **Security**: Pass security audit with no critical vulnerabilities
3. **Performance**: Meet all performance targets under load
4. **Reliability**: 99.9% uptime in test environment over 30 days
5. **Observability**: Complete audit trail and metrics for all operations
6. **Usability**: Clear documentation and easy deployment to EKS
7. **Multi-tenancy**: Proven namespace isolation in testing

---

## Dependencies & Crates

### Core Dependencies
```toml
[dependencies]
# Async runtime
tokio = { version = "1.35", features = ["full"] }
tokio-rustls = "0.25"

# gRPC
tonic = "0.11"
prost = "0.12"

# Cryptography
ring = "0.17"
ed25519-dalek = "2.1"
p256 = "0.13"
p384 = "0.13"
rsa = "0.9"
aes-gcm = "0.10"
sha2 = "0.10"
sha3 = "0.10"
hkdf = "0.12"
argon2 = "0.5"

# TLS
rustls = "0.22"
rustls-pemfile = "2.0"
webpki = "0.22"
x509-parser = "0.16"

# Security
secrecy = "0.8"
zeroize = "1.7"
getrandom = "0.2"
sharks = "0.5"  # Shamir secret sharing

# Storage
sled = "0.34"  # or rocksdb

# Logging & Metrics
tracing = "0.1"
tracing-subscriber = "0.3"
prometheus = "0.13"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
prost = "0.12"

# Configuration
config = "0.14"
toml = "0.8"

# Error handling
thiserror = "1.0"
anyhow = "1.0"

[dev-dependencies]
criterion = "0.5"
proptest = "1.4"
```

---

## Build & Run Instructions

### Build
```bash
cargo build --release
```

### Run Tests
```bash
cargo test --all
cargo test --all -- --test-threads=1  # For tests requiring serialization
```

### Run Benchmarks
```bash
cargo bench
```

### Run HSM
```bash
./target/release/hsm --config /etc/hsm/config.yaml
```

### Generate Certificates (for testing)
```bash
./scripts/generate-certs.sh
```

---

## Documentation Plan

1. **Architecture Documentation**: System design, component interactions
2. **API Documentation**: gRPC API reference with examples
3. **Security Documentation**: Threat model, security controls, compliance
4. **Operations Runbook**: Deployment, monitoring, troubleshooting
5. **Developer Guide**: How to contribute, coding standards
6. **User Guide**: How to use the HSM from client applications

---

## Conclusion

This specification provides a comprehensive blueprint for building a production-grade HSM in Rust. The modular architecture enables parallel development across 9+ independent tracks, with clear interfaces and responsibilities. The focus on security, performance, and observability ensures the HSM meets enterprise requirements while being deployable in Kubernetes environments like EKS.
