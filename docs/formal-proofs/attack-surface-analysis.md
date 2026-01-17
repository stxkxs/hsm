# HSM Attack Surface Analysis

## Executive Summary

This document provides a comprehensive analysis of the HSM's attack surface, identifying all entry points, data flows, trust boundaries, and potential attack vectors. The analysis is structured to align with the Universal Composability (UC) framework and the four ideal functionalities (F_auth, F_keymgmt, F_crypto, F_audit).

## Attack Surface Taxonomy

```
Attack Surface = {Network, API, Authentication, Storage, Memory, Dependencies}
```

For each surface, we analyze:
- **Entry Points**: How adversaries interact
- **Data Flow**: What data crosses the boundary
- **Trust Assumptions**: What we trust/distrust
- **Attack Vectors**: Specific exploitation techniques
- **Mitigations**: Security controls in place
- **UC Coverage**: Which ideal functionality provides protection

---

## 1. Network Attack Surface

### Entry Point: gRPC API (Port 8443)

**Description**: Primary external interface for clients

**Data Flow**:
```
Client → mTLS Handshake → gRPC Request → HSM
HSM → gRPC Response → mTLS → Client
```

**Trust Assumptions**:
- Network is **untrusted** (Dolev-Yao adversary)
- Clients possess **valid mTLS certificates** (trusted CA)
- TLS 1.3 library is **correct** (RustTLS)

**Attack Vectors**:

| Attack Vector | Threat | Mitigation | UC Module |
|--------------|--------|------------|-----------|
| **MitM** | Intercept/modify traffic | mTLS mutual auth | F_auth |
| **Replay** | Replay old requests | TLS sequence numbers, nonces | F_auth |
| **Eavesdropping** | Extract sensitive data | TLS 1.3 encryption | F_auth |
| **Certificate Spoofing** | Fake client identity | CA validation, cert pinning | F_auth |
| **Downgrade Attack** | Force weak crypto | TLS 1.3 only, no fallback | F_auth |
| **DoS (Connection Flood)** | Exhaust connections | Connection limits, rate limiting | - |

**Code Locations**:
- `crates/grpc-api/src/server.rs` - gRPC server
- `crates/auth/src/mtls.rs` - mTLS validation

**Metrics**:
- **Attack Surface Score**: MEDIUM (requires valid cert for meaningful attack)
- **Exposure**: PUBLIC (internet-facing)
- **Criticality**: HIGH

---

### Entry Point: Metrics Endpoint (Port 9090)

**Description**: Prometheus metrics scraping endpoint

**Data Flow**:
```
Prometheus → HTTP GET /metrics → HSM
HSM → Metrics (JSON/Text) → Prometheus
```

**Trust Assumptions**:
- Metrics endpoint is **read-only**
- No sensitive data in metrics (key IDs redacted)

**Attack Vectors**:

| Attack Vector | Threat | Mitigation | UC Module |
|--------------|--------|------------|-----------|
| **Information Disclosure** | Enumerate namespaces/algorithms | Aggregate metrics, no PII | - |
| **DoS (Scrape Flood)** | Exhaust CPU | Rate limiting | - |
| **Timing Analysis** | Infer operations via metrics | Coarse-grained metrics | - |

**Code Locations**:
- `crates/metrics/src/prometheus_exporter.rs`

**Metrics**:
- **Attack Surface Score**: LOW (read-only, limited info)
- **Exposure**: INTERNAL (Kubernetes network)
- **Criticality**: LOW

---

## 2. API Attack Surface

### gRPC Endpoints

#### 2.1 Key Management Endpoints

**Endpoints**:
- `GenerateKey(spec, namespace) → key_id`
- `ImportKey(encrypted_key, namespace) → key_id`
- `DeleteKey(key_id, namespace) → success`
- `RotateKey(key_id) → new_key_id`
- `ListKeys(namespace, filter) → key_metadata[]`

**Attack Vectors**:

| Endpoint | Attack | Impact | Mitigation | UC Module |
|----------|--------|--------|------------|-----------|
| **GenerateKey** | Key generation exhaustion | DoS, storage full | Rate limiting, quotas | - |
| **ImportKey** | Import malicious key | Backdoored key | Key validation, size limits | F_keymgmt |
| **DeleteKey** | Unauthorized deletion | Data loss | RBAC (Admin only), audit log | F_auth, F_audit |
| **RotateKey** | Force rotation loop | DoS | Rate limiting | - |
| **ListKeys** | Enumerate all keys | Info disclosure | Namespace isolation, ACL | F_keymgmt |

**Code Locations**:
- `crates/grpc-api/src/key_management_service.rs`
- `crates/key-manager/src/lib.rs`

---

#### 2.2 Cryptographic Operation Endpoints

**Endpoints**:
- `Sign(key_id, message, algorithm) → signature`
- `Verify(key_id, message, signature, algorithm) → bool`
- `Encrypt(key_id, plaintext, algorithm) → ciphertext`
- `Decrypt(key_id, ciphertext, algorithm) → plaintext`

**Attack Vectors**:

| Endpoint | Attack | Impact | Mitigation | UC Module |
|----------|--------|--------|------------|-----------|
| **Sign** | Chosen-message attack | Signature forgery (adaptive) | SUF-CMA signatures (Ed25519) | F_crypto |
| **Verify** | Timing side-channel | Extract signature bits | Constant-time verification (FaCT) | F_crypto |
| **Encrypt** | Chosen-plaintext attack | Ciphertext oracle | IND-CPA (AES-GCM) | F_crypto |
| **Decrypt** | Chosen-ciphertext attack | Decryption oracle | IND-CCA2 (authenticated encryption) | F_crypto |
| **All** | Large message attack | Memory exhaustion | 64 MB size limit | - |

**Code Locations**:
- `crates/grpc-api/src/crypto_service.rs`
- `crates/crypto-engine/src/lib.rs`

---

#### 2.3 Audit Endpoints

**Endpoints**:
- `GetAuditLogs(namespace, filter) → logs`
- `VerifyAuditLog(from, to) → integrity_status`

**Attack Vectors**:

| Endpoint | Attack | Impact | Mitigation | UC Module |
|----------|--------|--------|------------|-----------|
| **GetAuditLogs** | Unauthorized log access | Info disclosure | RBAC (Auditor role), namespace filter | F_auth, F_audit |
| **VerifyAuditLog** | Tamper concealment | Hide malicious activity | Hash chain, Merkle tree | F_audit |

**Code Locations**:
- `crates/grpc-api/src/audit_service.rs`
- `crates/audit/src/lib.rs`

---

## 3. Authentication Attack Surface

### mTLS Certificate Validation

**Entry Point**: TLS handshake during connection

**Data Flow**:
```
Client → Client Certificate → HSM
HSM → Validate against CA → Extract Identity
```

**Attack Vectors**:

| Attack | Technique | Mitigation | UC Module |
|--------|-----------|------------|-----------|
| **Certificate Forgery** | Create fake cert with valid CA | CA private key protection, HSM | F_auth |
| **Certificate Theft** | Steal client cert from disk | Client-side protection (out of scope) | - |
| **Revocation Bypass** | Use revoked cert | CRL/OCSP checking (future work) | F_auth |
| **Weak Crypto** | Use old RSA-1024 cert | Reject weak algorithms in TLS config | F_auth |

**Code Locations**:
- `crates/auth/src/mtls.rs:validate_certificate()`
- `crates/auth/src/mtls.rs:extract_identity()`

**Residual Risk**: **CRL/OCSP not implemented** (accepted risk, manual revocation)

---

### RBAC Authorization

**Entry Point**: Every API request after authentication

**Data Flow**:
```
Identity → Get Role → Check Permission → Check Namespace → Allow/Deny
```

**Attack Vectors**:

| Attack | Technique | Mitigation | UC Module |
|--------|-----------|------------|-----------|
| **Privilege Escalation** | User → Admin | RBAC enforcement, no role modification | F_auth |
| **Namespace Hopping** | Access other namespace | Namespace bound to cert OU | F_auth |
| **Permission Bypass** | Call unauthorized endpoint | Permission checks on every request | F_auth |

**Code Locations**:
- `crates/auth/src/rbac.rs:authorize()`
- `crates/auth/src/rbac.rs:has_permission()`

**UC Proof**: Theorem `authorization_soundness` in `auth-ideal-functionality.v`

---

## 4. Storage Attack Surface

### Encrypted Key Storage

**Entry Point**: File system (persistent volume)

**Data Flow**:
```
Key (plaintext) → Encrypt with Master Key (AES-256-GCM) → Write to Disk
Read from Disk → Decrypt with Master Key → Key (plaintext)
```

**Attack Vectors**:

| Attack | Technique | Mitigation | UC Module |
|--------|-----------|------------|-----------|
| **Disk Exfiltration** | Copy encrypted keys from disk | Envelope encryption (keys unusable without master key) | F_keymgmt |
| **Backup Theft** | Steal backup archive | Encrypted backups (user-provided key) | F_keymgmt |
| **Corruption** | Bit flips on disk | Integrity checks (AEAD tag) | F_keymgmt |
| **Master Key Compromise** | Extract master key from memory | `secrecy` crate, TEE sealing (Agent 3) | F_keymgmt |

**Code Locations**:
- `crates/storage/src/encrypted_storage.rs`
- `crates/key-manager/src/storage.rs`

**Residual Risk**: **Master key in process memory** (mitigated by `secrecy`, future: TEE)

---

### Audit Log Storage

**Entry Point**: Append-only log files

**Data Flow**:
```
Event → Hash with prev_hash → Append to Log → Update Merkle Tree
```

**Attack Vectors**:

| Attack | Technique | Mitigation | UC Module |
|--------|-----------|------------|-----------|
| **Log Deletion** | Delete log entries | Append-only filesystem, hash chain breaks | F_audit |
| **Log Modification** | Alter past entry | Hash chain verification fails | F_audit |
| **Log Injection** | Insert fake entry | Sequence numbers, hash chain | F_audit |

**Code Locations**:
- `crates/audit/src/logger.rs`
- `crates/audit/src/verifier.rs`

**UC Proof**: Theorems `log_append_only`, `tamper_evidence` in `audit-ideal-functionality.v`

---

## 5. Memory Attack Surface

### In-Memory Keys

**Entry Point**: Process memory during cryptographic operations

**Data Flow**:
```
Load Key from Storage → Decrypt → Use in Crypto Op → Zeroize → Drop
```

**Attack Vectors**:

| Attack | Technique | Mitigation | UC Module |
|--------|-----------|------------|-----------|
| **Memory Dump** | Core dump, debugger attach | Disable core dumps, `secrecy::Secret` | - |
| **Spectre/Meltdown** | Speculative execution | Memory fences, `lfence` (Agent 5) | - |
| **Cache Timing** | Observe cache hits/misses | Constant-time code (FaCT, Agent 2) | - |
| **Memory Leak** | Key not zeroized on panic | `ZeroizeOnDrop` trait | - |

**Code Locations**:
- `crates/crypto-engine/src/key_material.rs`
- All code using `secrecy::Secret<Vec<u8>>`

**Verification**:
- Agent 5: Valgrind memory checks
- Agent 5: MIRI undefined behavior detection
- Agent 2: Constant-time verification (dudect)

**Out-of-Scope for UC**: Memory safety is **implementation-level**, not protocol-level

---

### Buffer Overflows

**Entry Point**: Message parsing, key deserialization

**Attack Vectors**:

| Attack | Technique | Mitigation | Language |
|--------|-----------|------------|----------|
| **Buffer Overflow** | Write past buffer end | Rust bounds checking | Rust |
| **Use-After-Free** | Access freed memory | Rust borrow checker | Rust |
| **Type Confusion** | Cast to wrong type | Rust type safety | Rust |

**Residual Risk**: **MINIMAL** (Rust memory safety guarantees)

**Exceptions**:
- `unsafe` blocks (minimized, audited)
- FFI to C libraries (ed25519-dalek, p256 are safe Rust)

---

## 6. Dependency Attack Surface

### Rust Crate Dependencies

**Entry Point**: Cargo dependencies

**Critical Dependencies**:

| Crate | Version | Purpose | Risk | Mitigation |
|-------|---------|---------|------|------------|
| **ed25519-dalek** | 2.1 | Ed25519 signatures | LOW | Well-audited, pure Rust |
| **p256** | 0.13 | ECDSA P-256 | LOW | RustCrypto, constant-time |
| **rsa** | 0.9.10 | RSA operations | **MEDIUM** | RUSTSEC-2023-0071 (Marvin Attack) |
| **aes-gcm** | 0.10 | AES-GCM encryption | LOW | RustCrypto, hardware AES-NI |
| **rustls** | 0.22 | TLS 1.3 | LOW | Memory-safe TLS, no OpenSSL |
| **tokio** | 1.35 | Async runtime | LOW | Widely used, audited |
| **tonic** | 0.11 | gRPC framework | LOW | Standard gRPC |

**Attack Vectors**:

| Attack | Technique | Mitigation |
|--------|-----------|------------|
| **Malicious Dependency** | Typosquatting, compromised crate | Pin versions, `cargo audit` |
| **Vulnerability** | Known CVE in dependency | `cargo audit` in CI, Dependabot |
| **Supply Chain** | Compromised crates.io | Verify checksums, audit critical deps |

**Tools**:
- `cargo audit` - Check for known vulnerabilities
- `cargo deny` - License and dependency policy
- Dependabot - Automated security updates

**Code Locations**:
- `Cargo.toml` - All dependencies listed

---

## 7. Configuration Attack Surface

### Configuration Files

**Entry Point**: YAML/TOML config files

**Data Flow**:
```
Config File → Parse → Validate → Apply
```

**Attack Vectors**:

| Attack | Technique | Mitigation | UC Module |
|--------|-----------|------------|-----------|
| **Config Injection** | Modify config file | File permissions (root-owned) | - |
| **Weak Crypto Config** | Enable weak algorithms | Validation, reject weak configs | F_crypto |
| **Open Permissions** | Disable mTLS | Fail-secure defaults | F_auth |

**Code Locations**:
- `crates/config/src/lib.rs:validate_config()`

**Fail-Secure Defaults**:
- mTLS **required** (cannot disable)
- TLS 1.3 **only** (no 1.2 fallback)
- Strong algorithms **only** (Ed25519, P-256, AES-256)

---

## Trust Boundaries

### Trust Boundary Matrix

```
┌─────────────────────────────────────────────────────────────────┐
│                    HSM Trust Boundaries                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  UNTRUSTED                                                        │
│  ┌─────────────────────────────────────────────┐                │
│  │  Network (Dolev-Yao Adversary)              │                │
│  │  - Can intercept, modify, replay             │                │
│  └─────────────┬───────────────────────────────┘                │
│                │ mTLS (F_auth)                                    │
│                ▼                                                  │
│  ┌─────────────────────────────────────────────┐                │
│  │  Authenticated Client (Malicious Possible)  │                │
│  │  - Valid certificate, confined to namespace │                │
│  └─────────────┬───────────────────────────────┘                │
│                │ RBAC (F_auth)                                    │
│                ▼                                                  │
│  TRUSTED (Authorized Client)                                      │
│  ┌─────────────────────────────────────────────┐                │
│  │  HSM Module Boundary                        │                │
│  │  ┌───────────┐  ┌───────────┐  ┌──────────┐│                │
│  │  │  F_auth   │→ │ F_keymgmt │→ │ F_crypto ││                │
│  │  └───────────┘  └───────────┘  └──────────┘│                │
│  │  ┌───────────┐                              │                │
│  │  │  F_audit  │  (all operations logged)     │                │
│  │  └───────────┘                              │                │
│  └─────────────┬───────────────────────────────┘                │
│                │ Envelope Encryption                              │
│                ▼                                                  │
│  ┌─────────────────────────────────────────────┐                │
│  │  Persistent Storage (Disk)                  │                │
│  │  - Encrypted keys, append-only logs         │                │
│  └─────────────────────────────────────────────┘                │
│                                                                   │
│  KERNEL / HARDWARE                                                │
│  ┌─────────────────────────────────────────────┐                │
│  │  Operating System (Assumed Trusted)         │                │
│  │  - Process isolation, file permissions      │                │
│  └─────────────────────────────────────────────┘                │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Attack Surface Reduction Strategies

### 1. Minimize Network Exposure

**Current**:
- gRPC API on port 8443 (mTLS)
- Metrics on port 9090 (HTTP, Kubernetes-internal)

**Improvements**:
- [ ] Firewall rules (allow only known IPs)
- [ ] VPN/private network for admin endpoints
- [ ] Separate admin API (different port, stricter auth)

---

### 2. Input Validation

**Current**:
- gRPC protobuf schema validation
- Message size limits (64 MB)
- Key ID format validation

**Improvements**:
- [x] Reject weak algorithms (Ed25519/ECDSA only)
- [x] Namespace validation (alphanumeric + hyphens)
- [ ] Rate limiting per endpoint (not just per client)

---

### 3. Least Privilege

**Current**:
- RBAC with 4 roles (Admin, Operator, User, Auditor)
- Namespace isolation
- Per-key ACLs

**Improvements**:
- [ ] Fine-grained permissions (sign-only, decrypt-only keys)
- [ ] Time-based restrictions (key valid 9am-5pm)
- [ ] IP-based restrictions (key only from specific IPs)

---

### 4. Defense in Depth

**Layers**:
1. **Network**: mTLS, TLS 1.3
2. **Authentication**: Certificate validation, CA trust
3. **Authorization**: RBAC, namespace isolation, ACLs
4. **Cryptography**: Envelope encryption, authenticated encryption
5. **Audit**: Tamper-evident logs, external forwarding
6. **Implementation**: Rust memory safety, constant-time code

---

## Attack Surface Metrics

### Quantitative Analysis

| Surface | Entry Points | Attack Vectors | Mitigations | UC Coverage | Risk |
|---------|--------------|----------------|-------------|-------------|------|
| **Network** | 2 | 6 | 5 | F_auth | MEDIUM |
| **API** | 12 | 14 | 12 | F_auth, F_crypto, F_keymgmt, F_audit | MEDIUM |
| **Authentication** | 1 | 4 | 3 | F_auth | LOW |
| **Storage** | 2 | 7 | 6 | F_keymgmt, F_audit | LOW |
| **Memory** | 3 | 5 | 5 | - | LOW |
| **Dependencies** | ~40 crates | 3 | 3 | - | LOW |
| **Configuration** | 1 | 3 | 3 | - | LOW |

**Overall Attack Surface Score**: **MEDIUM** (requires valid certificate for most attacks)

---

## Recommendations

### High Priority

1. **Implement FaCT Constant-Time Code** (Agent 2)
   - Mitigates RSA Marvin Attack (RUSTSEC-2023-0071)
   - Eliminates timing side-channels

2. **Add TEE Support** (Agent 3)
   - Hardware-sealed master key (AWS Nitro, Intel SGX)
   - Reduces attack surface for master key compromise

3. **Implement CRL/OCSP**
   - Check certificate revocation status
   - Closes gap in mTLS authentication

### Medium Priority

4. **Add ZK Audit Proofs** (Agent 4)
   - Privacy-preserving audit verification
   - Allows external verification without revealing details

5. **Implement Per-Endpoint Rate Limiting**
   - Prevent abuse of expensive operations (key generation, signing)

6. **Add Fine-Grained Permissions**
   - Sign-only, decrypt-only keys
   - Time/IP-based restrictions

### Low Priority

7. **Post-Quantum Cryptography**
   - Plan for Dilithium (signatures), Kyber (encryption)
   - 10+ year timeline

---

## Conclusion

The HSM attack surface analysis identifies:
- **7 major attack surfaces** (network, API, auth, storage, memory, dependencies, config)
- **47+ attack vectors** with mitigations
- **4 trust boundaries** with UC formal proofs

**Key Findings**:
1. **Network attack surface** requires valid mTLS certificate (high barrier)
2. **UC framework** provides formal security guarantees for protocol-level attacks
3. **Rust memory safety** eliminates most memory corruption attacks
4. **Residual risks** identified (RSA timing, master key in memory, no CRL)

**Next Steps**:
- Agent 2: Constant-time verification (FaCT, dudect)
- Agent 3: TEE integration (AWS Nitro, SGX)
- Agent 5: Memory safety verification (Valgrind, MIRI)
