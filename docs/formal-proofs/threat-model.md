# HSM Threat Model

## Executive Summary

This document defines the threat model for the HSM, specifying adversary capabilities, attack vectors, security boundaries, and mitigations. The threat model aligns with the Universal Composability (UC) framework proofs defined in the ideal functionalities.

## Scope

### In-Scope Threats

1. **Network-Level Attacks**: Interception, modification, replay of network traffic
2. **Malicious Authenticated Clients**: Clients with valid certificates attempting unauthorized operations
3. **Module Compromise**: Adversary gains control of one HSM module
4. **Namespace Attacks**: Cross-namespace access attempts
5. **Cryptographic Attacks**: Chosen ciphertext, signature forgery, key extraction
6. **Audit Log Tampering**: Modification or deletion of audit logs
7. **Side-Channel Attacks**: Timing, cache, speculative execution leaks
8. **Denial of Service**: Resource exhaustion, request flooding

### Out-of-Scope Threats

1. **Physical Server Compromise**: Adversary with physical access (mitigated by TEE in Agent 3)
2. **Root/Admin Compromise**: Insider with root access to host OS (assumed trusted)
3. **Compiler/Toolchain Attacks**: Malicious Rust compiler (trust GCC/LLVM)
4. **Supply Chain Attacks**: Compromised dependencies (mitigated by `cargo audit`)
5. **Quantum Adversary**: Post-quantum cryptanalysis (classical crypto assumptions)
6. **Covert Channels**: Timing/bandwidth covert channels (future work)

## Adversary Models

### A1: Dolev-Yao Network Adversary

**Capabilities**:
- **Intercept**: Read all network traffic between clients and HSM
- **Modify**: Alter messages in transit
- **Replay**: Store and replay old messages
- **Drop**: Prevent message delivery
- **Cannot**: Break cryptography (IND-CPA, SUF-CMA security)

**Attack Vectors**:
- Man-in-the-Middle (MitM) attacks
- Message replay attacks
- Traffic analysis (observe patterns)

**Mitigations**:
- **mTLS** (F_auth): Mutual authentication prevents MitM
- **Authenticated Encryption**: AES-GCM prevents modification
- **Nonces/Timestamps**: Prevent replay attacks
- **TLS 1.3**: Forward secrecy, encrypted handshake

**UC Model**: Standard Dolev-Yao adversary defined in `uc-framework.v`

**Proof**: Theorem `resist_network_attack` in `composition-theorem.v`

---

### A2: Malicious Authenticated Client

**Capabilities**:
- **Authenticate**: Possesses valid mTLS certificate
- **Request Operations**: Can invoke any gRPC endpoint
- **Namespace**: Confined to authorized namespace
- **Cannot**: Access keys/operations outside authorization

**Attack Vectors**:
- Privilege escalation (User → Admin)
- Cross-namespace access
- Unauthorized key deletion
- Brute-force key discovery
- Resource exhaustion (DoS within namespace)

**Mitigations**:
- **RBAC** (F_auth): Role-based authorization enforced
- **Namespace Isolation** (F_keymgmt): Keys isolated by namespace
- **ACLs** (F_keymgmt): Per-key access control lists
- **Rate Limiting**: Request throttling per client
- **Audit Logging** (F_audit): All operations logged

**UC Model**: `MaliciousClient` adversary in `uc-framework.v`

**Proof**: Theorems `namespace_isolation`, `access_control` in `keymgmt-ideal-functionality.v`

---

### A3: Adaptive Adversary

**Capabilities**:
- **Adaptive Attacks**: Choose attacks based on observed outputs
- **Concurrent Execution**: Run multiple protocol instances
- **Polynomial Time**: Computationally bounded (classical security)
- **Cannot**: Distinguish real from ideal execution

**Attack Vectors**:
- Chosen-plaintext attacks (CPA)
- Chosen-ciphertext attacks (CCA)
- Adaptive chosen-message attacks (CMA)

**Mitigations**:
- **UC Framework**: Designed for adaptive adversaries
- **IND-CCA2 Encryption**: AES-256-GCM with authenticated encryption
- **SUF-CMA Signatures**: Ed25519, ECDSA with random nonces
- **Stateless Operations**: No internal state leakage

**UC Model**: Adversary in `UCRealizes` definition handles adaptive attacks

**Proof**: UC composition theorem guarantees security against adaptive adversaries

---

### A4: Compromised Single Module

**Capabilities**:
- **Module Control**: Full control of one HSM module (e.g., audit logger)
- **Cannot**: Break security of other modules
- **Cannot**: Access master keys or encryption keys

**Attack Vectors**:
- Audit log manipulation (if audit module compromised)
- Metrics falsification (if metrics module compromised)
- Configuration tampering (if config module compromised)

**Mitigations**:
- **Module Isolation**: Each module runs independently
- **UC Composition**: Security of uncompromised modules preserved
- **Least Privilege**: Modules only access needed interfaces
- **Integrity Checks**: Critical modules (crypto, key-manager) tamper-protected

**UC Model**: `compromised_modules` field in `AdversaryCapabilities`

**Proof**: Theorem `resist_module_compromise` in `composition-theorem.v`

---

### A5: Side-Channel Adversary

**Capabilities**:
- **Timing Attacks**: Measure operation execution time
- **Cache Attacks**: Observe cache hits/misses
- **Speculative Execution**: Spectre/Meltdown-style attacks
- **Cannot**: Break constant-time implementations

**Attack Vectors**:
- **RSA Marvin Attack** (RUSTSEC-2023-0071): Timing leak in padding check
- **ECDSA Nonce Bias**: Timing correlation with nonce bits
- **Cache-Timing**: AES T-table cache timing

**Mitigations**:
- **Constant-Time Operations** (Agent 2): FaCT DSL, ct-verif
- **Timing Hardening**: `subtle::ConstantTimeEq` for comparisons
- **Cache Mitigations**: AES-NI (hardware AES), avoid T-tables
- **Speculative Execution Barriers**: Memory fences, `lfence`

**Out-of-Scope for UC**: Side-channels are **implementation-level** attacks, not covered by UC proofs

**Verification Approach**: Separate constant-time verification (Agent 2: dudect, FaCT)

---

### A6: Denial-of-Service (DoS) Adversary

**Capabilities**:
- **Request Flooding**: Send massive number of requests
- **Resource Exhaustion**: Consume CPU, memory, disk
- **Connection Exhaustion**: Open many concurrent connections
- **Cannot**: Permanently disable HSM (availability guarantees)

**Attack Vectors**:
- SYN flood (TCP-level)
- Slowloris (slow HTTP requests)
- Key generation spam (expensive operations)
- Large message amplification

**Mitigations**:
- **Rate Limiting**: Requests per client per second
- **Connection Limits**: Max concurrent connections
- **Resource Quotas**: Per-namespace limits
- **Timeouts**: Request timeouts prevent slowloris
- **Graceful Degradation**: Drop low-priority requests under load

**UC Model**: Availability property in `F_audit`

**Proof**: Theorem `F_audit_available` (logs always writable)

---

## Asset Classification

### Critical Assets (Must Protect)

| Asset | Confidentiality | Integrity | Availability |
|-------|-----------------|-----------|--------------|
| **Private Keys** | **CRITICAL** | **CRITICAL** | HIGH |
| **Master Encryption Key** | **CRITICAL** | **CRITICAL** | **CRITICAL** |
| **Client Certificates** | MEDIUM | **CRITICAL** | HIGH |
| **Audit Logs** | LOW | **CRITICAL** | MEDIUM |
| **Configuration** | MEDIUM | **CRITICAL** | MEDIUM |

### Cryptographic Keys

**Protection Mechanisms**:
- **At Rest**: AES-256-GCM envelope encryption (F_keymgmt)
- **In Memory**: `secrecy` crate, `zeroize` on drop (Agent 5)
- **In Transit**: Never transmitted in plaintext
- **Access Control**: Namespace isolation + RBAC (F_auth)

**Threat**: Key Extraction

**Mitigations**:
- Memory encryption (`secrecy`)
- Secure deletion (`zeroize`)
- No plaintext export (only wrapped export)

---

### Master Encryption Key

**Protection Mechanisms**:
- **Storage**: Encrypted with hardware-backed key (Agent 3: TEE)
- **Escrow**: Shamir's Secret Sharing (k-of-n threshold)
- **Access**: Only crypto-engine and key-manager modules

**Threat**: Master Key Compromise

**Mitigations**:
- TEE sealing (AWS Nitro, Intel SGX)
- Secret sharing (no single point of compromise)
- Audit logging of master key usage

---

### Audit Logs

**Protection Mechanisms**:
- **Tamper Evidence**: Hash chain + Merkle tree (F_audit)
- **Integrity**: Cryptographic binding to events
- **Append-Only**: No deletion or modification

**Threat**: Log Tampering

**Mitigations**:
- Hash chain (any modification breaks chain)
- External log forwarding (backup to immutable storage)
- ZK proofs for privacy-preserving verification (Agent 4)

---

## Attack Scenarios

### Scenario 1: Unauthorized Key Access

**Attacker**: Malicious client in namespace `prod-ns1`
**Goal**: Access key in namespace `prod-ns2`
**Attack**: Request `GetKey(key-id-ns2, prod-ns2)` with valid credentials

**Defense**:
1. **F_auth**: Extract identity from mTLS cert → `identity.namespace = prod-ns1`
2. **F_auth**: Authorize request → Check `identity.namespace == prod-ns2` → **FAIL**
3. **Return**: `PermissionDenied` error
4. **F_audit**: Log failed authorization attempt

**UC Proof**: Theorem `namespace_isolation` in `keymgmt-ideal-functionality.v`

**Outcome**: Attack detected and blocked, logged for forensics

---

### Scenario 2: Signature Forgery

**Attacker**: Network adversary (MitM position)
**Goal**: Forge signature for message M without key access
**Attack**: Intercept signature S for message M', create signature for M

**Defense**:
1. **F_crypto**: Signature generated using `ideal_sign(key_id, M)` → random oracle
2. **Adversary**: Cannot create `S' = sign(key, M)` without key
3. **F_crypto**: Verification checks `(key_id, M, S') in signature_table` → **FAIL**

**UC Proof**: Theorem `signature_unforgeability` in `crypto-ideal-functionality.v`

**Outcome**: Forgery detected, verification fails

---

### Scenario 3: Ciphertext Manipulation

**Attacker**: Network adversary
**Goal**: Modify ciphertext C to decrypt to related plaintext
**Attack**: Flip bit in C, send to decrypt endpoint

**Defense**:
1. **F_crypto**: Ciphertext uses AES-256-GCM (authenticated encryption)
2. **Adversary**: Modifies ciphertext C → C'
3. **F_crypto**: Decryption checks authentication tag → **FAIL** (tag invalid)
4. **Return**: `DecryptionError`

**UC Proof**: Theorem `encryption_confidentiality` (CCA2 security)

**Outcome**: Tampering detected, decryption fails

---

### Scenario 4: Audit Log Tampering

**Attacker**: Compromised audit module
**Goal**: Delete log entry to hide malicious activity
**Attack**: Remove entry from log file

**Defense**:
1. **F_audit**: Log uses hash chain: `entry_n.prev_hash = hash(entry_{n-1})`
2. **Adversary**: Deletes entry_k
3. **Verifier**: Computes `verify_chain(entries)` → detects broken chain
4. **Alert**: Tamper evidence triggered

**UC Proof**: Theorem `tamper_evidence` in `audit-ideal-functionality.v`

**Outcome**: Tampering detected via cryptographic verification

---

### Scenario 5: Replay Attack

**Attacker**: Network adversary
**Goal**: Replay old signature request to exhaust key usage quota
**Attack**: Capture `SignRequest(key_id, message)`, replay 1000 times

**Defense**:
1. **TLS 1.3**: Includes sequence numbers, nonces in handshake
2. **gRPC**: Connection-level replay protection
3. **Rate Limiting**: Detect 1000 identical requests → throttle client
4. **Audit**: Log all requests → forensic analysis

**Outcome**: Replay detected via rate limiting and audit trail

---

## Security Boundaries

### Boundary 1: Network ↔ HSM (gRPC API)

**Interface**: mTLS over TCP (port 8443)

**Threats**:
- MitM attacks
- Eavesdropping
- Replay attacks

**Controls**:
- mTLS (mutual authentication)
- TLS 1.3 (forward secrecy, encrypted SNI)
- Certificate validation
- Rate limiting

**UC Module**: F_auth (authentication layer)

---

### Boundary 2: Namespace Isolation

**Interface**: Namespace parameter in all operations

**Threats**:
- Cross-namespace key access
- Privilege escalation
- Namespace enumeration

**Controls**:
- Identity-namespace binding (from mTLS cert)
- Namespace checks in F_auth and F_keymgmt
- ACLs per key

**UC Module**: F_auth (authorization), F_keymgmt (isolation)

**Proof**: Theorem `namespace_isolation_auth`

---

### Boundary 3: Module Interfaces

**Interface**: Internal APIs between modules

**Threats**:
- Compromised module infecting others
- Information flow between modules
- Unauthorized cross-module calls

**Controls**:
- Well-defined APIs (trait-based interfaces)
- Minimal inter-module trust
- No shared mutable state
- UC composition guarantees

**UC Module**: Composition structure in `composition-theorem.v`

**Proof**: Theorem `HSM_UC_Security`

---

### Boundary 4: Storage Layer

**Interface**: Encrypted file system

**Threats**:
- Disk tampering
- Backup exfiltration
- Storage exhaustion

**Controls**:
- Envelope encryption (keys encrypted with master key)
- Integrity checks (checksums)
- Secure deletion (overwrite)
- Storage quotas

**UC Module**: F_keymgmt (secure storage)

---

## Residual Risks

### Risk 1: RSA Marvin Attack (RUSTSEC-2023-0071)

**Threat**: Timing side-channel in RSA PKCS#1 v1.5 padding check
**Impact**: Potential private key recovery via timing oracle
**Likelihood**: LOW (requires local network, precise timing)
**Mitigation**:
- Agent 2: Rewrite in FaCT (constant-time)
- **Short-term**: Prefer Ed25519/ECDSA over RSA
- **Long-term**: Wait for `rsa` crate fix or use FaCT

**Status**: **ACCEPTED** (low impact, low likelihood, mitigation in progress)

---

### Risk 2: Supply Chain Compromise

**Threat**: Malicious code in Rust dependencies
**Impact**: Arbitrary code execution, key exfiltration
**Likelihood**: VERY LOW (vetted crates, active ecosystem)
**Mitigation**:
- `cargo audit` in CI
- Pin dependency versions
- Manual review of critical crates (ed25519-dalek, p256, aes-gcm)

**Status**: **MONITORED**

---

### Risk 3: Quantum Adversary (Future)

**Threat**: Quantum computer breaks RSA, ECDSA
**Impact**: Signature forgery, decryption of archived data
**Likelihood**: LOW (10+ years until large-scale quantum)
**Mitigation**:
- Plan for post-quantum algorithms (Dilithium, Kyber)
- Use hybrid schemes (classical + PQC)

**Status**: **PLANNED** (future enhancement)

---

## Compliance Mapping

### FIPS 140-2/140-3 Considerations

| Requirement | HSM Implementation | Gap |
|-------------|-------------------|-----|
| **Physical Security** | Software HSM | ❌ Requires hardware module |
| **Cryptographic Module** | Validated algorithms (AES, RSA, Ed25519) | ✅ Uses FIPS-approved |
| **Roles & Services** | RBAC (Admin, Operator, User, Auditor) | ✅ Implemented |
| **Self-Tests** | Startup KAT tests | ⚠️ Need continuous self-tests |
| **Zeroization** | `zeroize` crate | ✅ Implemented |
| **Audit** | Tamper-evident logs | ✅ Implemented |

**Note**: Full FIPS certification requires hardware module and formal validation process.

---

### GDPR / Data Privacy

| Requirement | HSM Implementation |
|-------------|-------------------|
| **Data Minimization** | Keys stored encrypted, no PII in logs |
| **Right to Erasure** | Secure key deletion (F_keymgmt) |
| **Audit Trail** | Complete operation logs (F_audit) |
| **Encryption** | AES-256-GCM (strong encryption) |

---

## Conclusion

The HSM threat model provides:
1. **Formal Adversary Models**: Dolev-Yao, malicious client, adaptive adversary
2. **UC Security Proofs**: Rigorous security guarantees via ideal functionalities
3. **Attack Scenarios**: Concrete examples with defenses
4. **Security Boundaries**: Clear trust boundaries and controls
5. **Residual Risks**: Transparent risk disclosure

The UC framework ensures that security properties proven for ideal functionalities (F_crypto, F_keymgmt, F_auth, F_audit) hold for the composed real-world HSM implementation.
