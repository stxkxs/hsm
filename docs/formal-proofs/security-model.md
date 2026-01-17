# HSM Security Model (Universal Composability Framework)

## Executive Summary

This document presents the **comprehensive security model** for the HSM based on the **Universal Composability (UC) framework**. The HSM is proven secure by decomposing it into four ideal functionalities (F_auth, F_keymgmt, F_crypto, F_audit) and proving that the real-world implementation UC-realizes the composed ideal functionality.

**Key Results**:
1. **F_crypto**, **F_keymgmt**, **F_auth**, **F_audit** defined as UC ideal functionalities
2. **Composition theorem** proven: HSM_real ≈ F_auth ∘ F_keymgmt ∘ F_crypto ∘ F_audit
3. **Security properties** proven: Correctness, Confidentiality, Integrity, Authenticity, Availability
4. **Threat model** documented with formal adversary definitions
5. **Attack surface** analyzed with mitigation mappings

**Audience**:
- Security auditors
- Cryptographers
- Compliance officers
- HSM developers

---

## 1. Introduction to Universal Composability

### 1.1 Why UC for HSM Security?

The HSM is a **complex composed system** with multiple modules interacting concurrently. Traditional security proofs (game-based security) do not compose:
- Proving `π₁` secure and `π₂` secure does NOT imply `π₁ ∘ π₂` secure
- Concurrent execution can break security (e.g., shared state)

The **UC framework** solves this:
- **Modular proofs**: Prove each module secure independently
- **Composition theorem**: Secure modules remain secure when composed
- **Concurrent security**: Security holds even with arbitrary concurrent protocols

### 1.2 UC Security Definition

A protocol `π` **UC-realizes** an ideal functionality `F` if:

```
∀ adversary A, ∃ simulator S such that:
  REAL_{π,A,Z} ≈ IDEAL_{F,S,Z}
```

**Meaning**: For any environment Z (which can run arbitrary concurrent protocols), the real-world execution with adversary A is computationally indistinguishable from the ideal-world execution with simulator S.

**Why this matters**: If the real world looks like the ideal world, then `π` is as secure as `F`. Since `F` is perfectly secure by design, `π` inherits that security.

---

## 2. HSM Ideal Functionalities

We decompose the HSM into four ideal functionalities, each representing a perfect version of an HSM module.

### 2.1 F_crypto: Perfect Cryptographic Operations

**File**: `coq/crypto-ideal-functionality.v`

**Purpose**: Provides perfect encryption, signing, and hashing

**Interface**:
- `Sign(key_id, message) → signature`
- `Verify(key_id, message, signature) → {accept, reject}`
- `Encrypt(key_id, plaintext) → ciphertext`
- `Decrypt(key_id, ciphertext) → plaintext`
- `Hash(message) → digest`

**Security Properties Proven**:

| Property | Theorem | Meaning |
|----------|---------|---------|
| **Correctness** | `decrypt_encrypt_correctness` | Decrypt(Encrypt(m)) = m |
| **Correctness** | `verify_sign_correctness` | Verify(Sign(m)) = true |
| **Unforgeability** | `signature_unforgeability` | Cannot create valid sig without Sign |
| **Confidentiality** | `encryption_confidentiality` | Ciphertext reveals nothing about plaintext |

**Implementation Mapping**:
- Real-world module: `crates/crypto-engine/`
- Algorithms: Ed25519, ECDSA, RSA, AES-GCM
- Libraries: ed25519-dalek, p256, rsa, aes-gcm

---

### 2.2 F_keymgmt: Perfect Key Isolation

**File**: `coq/keymgmt-ideal-functionality.v`

**Purpose**: Provides perfect key lifecycle management and namespace isolation

**Interface**:
- `GenerateKey(spec, namespace) → key_id`
- `GetKey(key_id, namespace) → key`
- `DeleteKey(key_id, namespace) → ⊤`
- `RotateKey(key_id) → new_key_id`

**Security Properties Proven**:

| Property | Theorem | Meaning |
|----------|---------|---------|
| **Namespace Isolation** | `namespace_isolation` | Keys in ns1 invisible from ns2 |
| **Secure Deletion** | `secure_deletion` | Deleted keys unrecoverable |
| **Non-Recovery** | `deleted_key_non_recovery` | Once deleted, never reappears |
| **Access Control** | `access_control` | Only ACL members access keys |

**Implementation Mapping**:
- Real-world module: `crates/key-manager/`
- Storage: `crates/storage/` (encrypted with master key)
- Features: Namespace isolation, key states, ACLs

---

### 2.3 F_auth: Perfect Authentication

**File**: `coq/auth-ideal-functionality.v`

**Purpose**: Provides perfect mTLS authentication and RBAC authorization

**Interface**:
- `Authenticate(cert) → identity`
- `Authorize(identity, operation, resource) → {allow, deny}`
- `CreateSession(identity) → session_id`
- `ValidateSession(session_id) → identity`

**Security Properties Proven**:

| Property | Theorem | Meaning |
|----------|---------|---------|
| **Authentication Correctness** | `authentication_correctness` | Valid cert → valid identity |
| **Authorization Soundness** | `authorization_soundness` | Authorized ⇒ has permission + namespace |
| **Session Integrity** | `session_hijacking_prevention` | Sessions cannot be hijacked |
| **Namespace Isolation** | `namespace_isolation_auth` | Identity bound to namespace |

**Implementation Mapping**:
- Real-world module: `crates/auth/`
- mTLS: RustTLS, TLS 1.3
- RBAC: 4 roles (Admin, Operator, User, Auditor)

---

### 2.4 F_audit: Perfect Tamper Evidence

**File**: `coq/audit-ideal-functionality.v`

**Purpose**: Provides perfect tamper-evident audit logging

**Interface**:
- `Log(event) → ⊤`
- `GetLogs(filter) → events`
- `VerifyIntegrity(from, to) → {valid, tampered}`

**Security Properties Proven**:

| Property | Theorem | Meaning |
|----------|---------|---------|
| **Completeness** | `log_completeness` | All logged events appear in log |
| **Append-Only** | `log_append_only` | Old entries not removed |
| **Hash Chain Integrity** | `hash_chain_integrity` | Valid chain ⇒ no tampering |
| **Tamper Evidence** | `tamper_evidence` | Any modification breaks chain |

**Implementation Mapping**:
- Real-world module: `crates/audit/`
- Tamper evidence: Hash chain + Merkle tree
- Format: JSON structured logs

---

## 3. Composition Theorem

**File**: `coq/composition-theorem.v`

### 3.1 Main Result

**Theorem (HSM_UC_Security)**:

```coq
∀ π_auth π_keymgmt π_crypto π_audit,
  UCRealizes π_auth F_auth →
  UCRealizes π_keymgmt F_keymgmt →
  UCRealizes π_crypto F_crypto →
  UCRealizes π_audit F_audit →
  UCRealizes (π_auth ⊗ π_keymgmt ⊗ π_crypto ⊗ π_audit)
             (F_auth ∘ F_keymgmt ∘ F_crypto ∘ F_audit)
```

**Meaning**: If each real module UC-realizes its ideal functionality, then the composed real HSM UC-realizes the composed ideal HSM.

**Proof Strategy**: Apply the **Universal Composition Theorem** three times:
1. Compose `π_crypto` and `π_audit` → `F_crypto ∘ F_audit`
2. Compose with `π_keymgmt` → `F_keymgmt ∘ F_crypto ∘ F_audit`
3. Compose with `π_auth` → `F_auth ∘ F_keymgmt ∘ F_crypto ∘ F_audit`

---

### 3.2 Composition Structure

```
HSM_ideal = F_auth ∘ F_keymgmt ∘ F_crypto ∘ F_audit
```

**Request Flow**:

```
Client Request
    ↓
┌───────────┐
│  F_auth   │ ← Authenticate client cert, authorize operation
└─────┬─────┘
      ↓
┌───────────┐
│ F_keymgmt │ ← Retrieve key, check namespace + ACL
└─────┬─────┘
      ↓
┌───────────┐
│  F_crypto │ ← Perform cryptographic operation (sign, encrypt)
└─────┬─────┘
      ↓
┌───────────┐
│  F_audit  │ ← Log operation with tamper evidence
└─────┬─────┘
      ↓
 Response
```

---

### 3.3 End-to-End Security Properties

**Theorem (composition_authentication)**:
```
Successful response ⇒ Client was authenticated
```

**Theorem (composition_authorization)**:
```
Successful response ⇒ Operation was authorized
```

**Theorem (composition_audit_trail)**:
```
Successful response ⇒ Operation was logged
```

**Theorem (composition_namespace_isolation)**:
```
Identity.namespace ≠ Request.namespace ⇒ Request fails
```

---

### 3.4 Security Guarantees

**Theorem (HSM_ideal_security)**:

```
Correctness(HSM_ideal) ∧
Confidentiality(HSM_ideal) ∧
Integrity(HSM_ideal) ∧
Authenticity(HSM_ideal) ∧
Availability(HSM_ideal)
```

**Proof**: Composition preserves security properties. Each ideal functionality has proven security properties, which are preserved through composition via the UC framework.

---

## 4. Adversary Models

### 4.1 Dolev-Yao Network Adversary

**Definition** (`uc-framework.v:DolevYaoAdversary`):

```coq
Record AdversaryCapabilities := {
  can_intercept : true;
  can_modify : true;
  can_replay : true;
  can_authenticate : false;
  compromised_modules : [];
}.
```

**Attack Capabilities**:
- Intercept, modify, drop, replay network messages
- Traffic analysis (observe patterns)

**Cannot**:
- Break cryptography (IND-CPA, SUF-CMA)
- Forge mTLS certificates

**Mitigations**:
- **mTLS**: Mutual authentication prevents MitM
- **TLS 1.3**: Forward secrecy, authenticated encryption
- **Nonces**: Prevent replay attacks

**UC Proof**: Theorem `resist_network_attack` in `composition-theorem.v`

---

### 4.2 Malicious Authenticated Client

**Definition** (`uc-framework.v:MaliciousClient`):

```coq
Record AdversaryCapabilities := {
  can_intercept : false;
  can_modify : false;
  can_replay : false;
  can_authenticate : true;
  compromised_modules : [];
}.
```

**Attack Capabilities**:
- Authenticate with valid certificate
- Request any operation
- Adaptive attacks (choose based on responses)

**Cannot**:
- Access keys outside assigned namespace
- Perform operations without RBAC permission
- Modify audit logs

**Mitigations**:
- **RBAC**: Role-based authorization
- **Namespace Isolation**: F_keymgmt enforces boundaries
- **ACLs**: Per-key access control

**UC Proof**: Theorem `resist_malicious_client` in `composition-theorem.v`

---

### 4.3 Compromised Module Adversary

**Definition**: Adversary controls one HSM module

**Attack Capabilities**:
- Full control of one module (e.g., audit logger)
- Can corrupt data within that module

**Cannot**:
- Break security of other modules
- Access master keys or encryption keys

**Mitigations**:
- **Module Isolation**: UC composition guarantees
- **Least Privilege**: Modules have minimal interfaces
- **Integrity Checks**: Critical modules tamper-protected

**UC Proof**: Theorem `resist_module_compromise` in `composition-theorem.v`

---

## 5. Security Boundaries

### 5.1 Trust Boundaries

```
┌────────────────────────────────────────────────────────┐
│                   Trust Boundaries                      │
├────────────────────────────────────────────────────────┤
│                                                          │
│  UNTRUSTED: Network (Dolev-Yao)                          │
│      ↓ mTLS (F_auth)                                     │
│  PARTIALLY TRUSTED: Authenticated Client                 │
│      ↓ RBAC (F_auth)                                     │
│  TRUSTED: Authorized Client in Namespace                 │
│      ↓ Module Interfaces                                 │
│  TRUSTED: HSM Modules (F_auth, F_keymgmt, F_crypto)      │
│      ↓ Envelope Encryption                               │
│  UNTRUSTED: Persistent Storage (Disk)                    │
│                                                          │
└────────────────────────────────────────────────────────┘
```

### 5.2 Security Controls at Each Boundary

| Boundary | Entry | Exit | Control | UC Module |
|----------|-------|------|---------|-----------|
| **Network → HSM** | gRPC request | gRPC response | mTLS, TLS 1.3 | F_auth |
| **Client → HSM** | Operation request | Result | RBAC, namespace check | F_auth |
| **Module → Module** | Internal API call | Return value | Well-defined interfaces | Composition |
| **HSM → Storage** | Write key | Read key | Envelope encryption | F_keymgmt |

---

## 6. What UC Proofs Guarantee

### 6.1 In-Scope Security Guarantees

✅ **Protocol-Level Security**:
- Cryptographic operations (F_crypto)
- Key isolation (F_keymgmt)
- Authentication/authorization (F_auth)
- Audit integrity (F_audit)

✅ **Composition Security**:
- Modules compose securely
- No unintended interactions
- Concurrent execution safe

✅ **Adversary Resistance**:
- Dolev-Yao network adversary
- Malicious authenticated clients
- Adaptive adversaries

---

### 6.2 Out-of-Scope (Require Other Verification)

❌ **Implementation Bugs**:
- Memory safety → Rust type system + MIRI (Agent 5)
- Buffer overflows → Rust bounds checking
- Logic errors → Property tests, fuzzing

❌ **Side-Channel Attacks**:
- Timing attacks → Constant-time verification (Agent 2: FaCT, dudect)
- Cache attacks → Cache-grind analysis (Agent 2)
- Speculative execution → Memory fences (Agent 5)

❌ **Physical Attacks**:
- Hardware tampering → TEE integration (Agent 3: AWS Nitro, SGX)
- Power analysis → Hardware countermeasures

❌ **Compiler/Toolchain**:
- Compiler correctness → Trust LLVM/rustc
- Dependency vulnerabilities → `cargo audit` (CI)

---

## 7. Verification Methodology

### 7.1 Multi-Layer Verification

The HSM employs **defense-in-depth verification**:

| Layer | Technique | Agent | Coverage |
|-------|-----------|-------|----------|
| **Protocol** | UC proofs (this work) | Agent 6 | Compositional security |
| **Cryptography** | SMT solvers, bounded verification | Agent 1 | Algorithm correctness |
| **Timing** | FaCT, dudect, cache-grind | Agent 2 | Constant-time execution |
| **Hardware** | TEE attestation | Agent 3 | Hardware-backed security |
| **Privacy** | ZK proofs (Lasso) | Agent 4 | Privacy-preserving audit |
| **Memory** | MIRI, Valgrind, fault injection | Agent 5 | Memory safety, zeroization |

### 7.2 Formal Methods Stack

```
┌─────────────────────────────────────────────────────────┐
│  Universal Composability (Coq)                           │ ← Agent 6
│  - Protocol composition security                         │
│  - Ideal functionalities                                │
├─────────────────────────────────────────────────────────┤
│  SMT Solvers (Z3, cvc5)                                  │ ← Agent 1
│  - Finite-field verification                             │
│  - Bounded model checking                               │
├─────────────────────────────────────────────────────────┤
│  Constant-Time Verification (FaCT, ct-verif)             │ ← Agent 2
│  - Timing side-channel elimination                       │
│  - Cache-grind analysis                                 │
├─────────────────────────────────────────────────────────┤
│  ZK Proof Systems (Lasso, PLONK)                         │ ← Agent 4
│  - Privacy-preserving verification                       │
│  - Audit log proofs                                     │
├─────────────────────────────────────────────────────────┤
│  Memory Safety (Rust, MIRI, Valgrind)                    │ ← Agent 5
│  - Undefined behavior detection                          │
│  - Memory zeroization verification                       │
└─────────────────────────────────────────────────────────┘
```

---

## 8. Security Claims

### 8.1 Proven Claims (UC Framework)

**Claim 1: Compositional Security**
```
If π_auth, π_keymgmt, π_crypto, π_audit UC-realize their ideal functionalities,
then HSM_real UC-realizes HSM_ideal.
```
**Status**: ✅ **Proven** (Theorem `HSM_UC_Security`)

---

**Claim 2: Namespace Isolation**
```
Keys in namespace N₁ cannot be accessed from namespace N₂ (N₁ ≠ N₂).
```
**Status**: ✅ **Proven** (Theorems `namespace_isolation`, `namespace_isolation_auth`)

---

**Claim 3: Signature Unforgeability**
```
Cannot create valid signature without calling F_crypto.Sign.
```
**Status**: ✅ **Proven** (Theorem `signature_unforgeability`)

---

**Claim 4: Audit Tamper Evidence**
```
Any modification to audit logs is detectable via hash chain verification.
```
**Status**: ✅ **Proven** (Theorem `tamper_evidence`)

---

### 8.2 Implementation Claims (Require Additional Verification)

**Claim 5: Constant-Time Execution**
```
Cryptographic operations execute in constant time (no timing leaks).
```
**Status**: ⚠️ **Partial** (requires Agent 2: FaCT, dudect verification)
**Known Gap**: RSA Marvin Attack (RUSTSEC-2023-0071)

---

**Claim 6: Memory Zeroization**
```
All sensitive key material is zeroized on drop (no memory leaks).
```
**Status**: ⚠️ **Partial** (requires Agent 5: Valgrind verification)

---

**Claim 7: Hardware-Backed Security**
```
Master key is sealed with hardware TEE (AWS Nitro, Intel SGX).
```
**Status**: ⏳ **Planned** (Agent 3: TEE integration)

---

## 9. Threat Model Summary

**See**: `threat-model.md` for full details

**Adversaries Considered**:
1. **Dolev-Yao Network** (can intercept, modify, replay)
2. **Malicious Client** (valid cert, attempts unauthorized ops)
3. **Adaptive Adversary** (chooses attacks based on outputs)
4. **Compromised Module** (controls one module)
5. **Side-Channel Adversary** (timing, cache attacks)
6. **DoS Adversary** (resource exhaustion)

**Residual Risks**:
- RSA Marvin Attack (timing leak) - **Accepted** (mitigation in Agent 2)
- Supply chain compromise - **Monitored** (`cargo audit`)
- Quantum adversary - **Planned** (10+ years)

---

## 10. Attack Surface Summary

**See**: `attack-surface-analysis.md` for full details

**Attack Surfaces**:
1. **Network** (gRPC port 8443, metrics port 9090)
2. **API** (12 gRPC endpoints)
3. **Authentication** (mTLS, RBAC)
4. **Storage** (encrypted keys, audit logs)
5. **Memory** (in-memory keys, buffers)
6. **Dependencies** (~40 Rust crates)
7. **Configuration** (YAML/TOML files)

**Attack Surface Score**: **MEDIUM** (requires valid cert for meaningful attack)

---

## 11. For Security Auditors

### 11.1 How to Verify UC Proofs

1. **Read UC Framework Introduction** (Section 1)
2. **Review Ideal Functionalities** (Section 2):
   - `coq/crypto-ideal-functionality.v`
   - `coq/keymgmt-ideal-functionality.v`
   - `coq/auth-ideal-functionality.v`
   - `coq/audit-ideal-functionality.v`
3. **Examine Composition Theorem** (Section 3):
   - `coq/composition-theorem.v`
4. **Check Security Properties** (Section 8.1):
   - Namespace isolation
   - Signature unforgeability
   - Audit tamper evidence

### 11.2 Integration with Code Audit

**UC proofs are protocol-level**. Combine with:
- **Code review**: Verify real implementation matches protocol
- **Constant-time audit**: Check for timing leaks (Agent 2)
- **Memory safety audit**: Check zeroization (Agent 5)
- **Penetration testing**: Validate mitigations

---

## 12. Conclusion

The HSM security model based on the Universal Composability framework provides:

1. **Rigorous Formal Foundations**:
   - UC ideal functionalities (F_crypto, F_keymgmt, F_auth, F_audit)
   - Composition theorem (HSM_real ≈ HSM_ideal)
   - Security properties with machine-checked proofs (Coq)

2. **Comprehensive Threat Coverage**:
   - Dolev-Yao network adversary
   - Malicious authenticated clients
   - Adaptive and concurrent adversaries
   - Compromised single modules

3. **Multi-Layer Defense**:
   - Protocol security (UC proofs)
   - Cryptographic correctness (SMT verification)
   - Constant-time execution (FaCT verification)
   - Memory safety (Rust + MIRI)
   - Hardware backing (TEE integration)

4. **Transparent Risk Disclosure**:
   - Known gaps (RSA Marvin Attack)
   - Out-of-scope threats (quantum adversary)
   - Residual risks (supply chain)

**Confidence Level**: **HIGH** for protocol-level security, **MEDIUM** for implementation-level security (pending Agent 2-5 verification).

**Recommendation**: Deploy with current mitigations, complete constant-time and memory safety verification (Agents 2, 5) for production.
