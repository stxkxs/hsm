# Universal Composability Proofs for HSM

## Overview

This directory contains formal proofs of compositional security for the HSM modules using the **Universal Composability (UC) framework**. The UC framework provides a rigorous foundation for proving that cryptographic protocols compose securely, even when run concurrently in arbitrary environments.

## Research Foundation

This work is based on:
- **"Universal Composability is Robust Compilation"** (Patrignani, Künnemann, Cecchetti, Wahby, 2024/2025)
- **"Universal Composition with Joint State"** (Canetti, Rabin, 2003)
- **"Universally Composable Security"** (Canetti, 2001)

## What is Universal Composability?

The Universal Composability framework provides a way to:
1. **Define ideal functionalities** - Perfect, trusted implementations of cryptographic operations
2. **Prove protocol security** - Show that real-world implementations are indistinguishable from ideal versions
3. **Compose securely** - Prove that secure protocols remain secure when composed

### Key Concepts

#### Ideal Functionality (F)
An **ideal functionality** is a trusted third party that performs a cryptographic operation perfectly:
- **F_crypto**: Perfect encryption/signing oracle
- **F_keymgmt**: Perfect key isolation and management
- **F_auth**: Perfect authentication
- **F_audit**: Perfect tamper-evident logging

#### Real-World Protocol (π)
The **real-world protocol** is the actual implementation (our HSM modules).

#### Simulator (S)
A **simulator** translates between the real and ideal worlds, proving they're indistinguishable.

#### UC Security Definition
A protocol π **UC-realizes** an ideal functionality F if:
```
∀ adversary A, ∃ simulator S such that:
REAL_{π,A,Z} ≈ IDEAL_{F,S,Z}
```

For any environment Z (which can run arbitrary concurrent protocols), the real-world execution with adversary A is computationally indistinguishable from the ideal-world execution with simulator S.

#### Composition Theorem
The power of UC is the **universal composition theorem**:
```
If π₁ UC-realizes F₁ and π₂ UC-realizes F₂, then:
  Compose(π₁, π₂) UC-realizes Compose(F₁, F₂)
```

This means we can prove modules secure independently, then compose them without re-proving security.

## HSM Module Decomposition

We model the HSM as a composition of four core ideal functionalities:

### 1. F_crypto (Cryptographic Engine)
**Purpose**: Perfect cryptographic operations

**Interface**:
- `Sign(key_id, message) → signature`
- `Verify(key_id, message, signature) → {accept, reject}`
- `Encrypt(key_id, plaintext) → ciphertext`
- `Decrypt(key_id, ciphertext) → plaintext`

**Security Properties**:
- **Correctness**: Decrypt(Encrypt(m)) = m, Verify(Sign(m)) = accept
- **Confidentiality**: Ciphertext reveals no information about plaintext
- **Unforgeability**: Cannot create valid signatures without key access
- **Non-malleability**: Cannot transform ciphertext to decrypt to related plaintext

### 2. F_keymgmt (Key Manager)
**Purpose**: Perfect key isolation and lifecycle management

**Interface**:
- `GenerateKey(spec, namespace) → key_id`
- `GetKey(key_id, namespace) → key`
- `DeleteKey(key_id, namespace) → ⊤`
- `RotateKey(key_id) → new_key_id`

**Security Properties**:
- **Isolation**: Keys in namespace N₁ are invisible to namespace N₂ (N₁ ≠ N₂)
- **Secure Deletion**: Deleted keys cannot be recovered
- **Access Control**: Only authorized identities can access keys
- **Key Binding**: Key operations are cryptographically bound to key_id

### 3. F_auth (Authentication & Authorization)
**Purpose**: Perfect client authentication and access control

**Interface**:
- `Authenticate(cert) → identity`
- `Authorize(identity, operation, resource) → {allow, deny}`
- `CreateSession(identity) → session_id`
- `ValidateSession(session_id) → identity`

**Security Properties**:
- **Authenticity**: Identity extraction is unforgeable
- **Integrity**: Session IDs cannot be hijacked or forged
- **Authorization**: Only authorized operations succeed
- **Isolation**: Namespaces provide perfect separation

### 4. F_audit (Audit Logger)
**Purpose**: Perfect tamper-evident logging

**Interface**:
- `Log(event) → ⊤`
- `GetLogs(filter) → events`
- `VerifyIntegrity(from, to) → {valid, tampered}`

**Security Properties**:
- **Completeness**: All events are logged
- **Integrity**: Logs cannot be modified or deleted
- **Tamper Evidence**: Any modification is detectable
- **Authenticity**: Log entries are cryptographically bound to events

## Composition Structure

The HSM is modeled as the composition:

```
HSM = F_auth ∘ F_keymgmt ∘ F_crypto ∘ F_audit
```

Where `∘` denotes secure composition. The composition theorem guarantees:

```
If:
  π_auth UC-realizes F_auth
  π_keymgmt UC-realizes F_keymgmt
  π_crypto UC-realizes F_crypto
  π_audit UC-realizes F_audit
Then:
  HSM_real UC-realizes HSM_ideal
```

### Composition Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Request Flow                              │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Client Request                                               │
│       │                                                       │
│       ▼                                                       │
│  ┌──────────┐     authenticate(cert)                         │
│  │  F_auth  │────────────────────────────▶ identity          │
│  └──────────┘                                                 │
│       │                                                       │
│       │ authorize(identity, "sign", key_id)                   │
│       ▼                                                       │
│  ┌──────────┐     get_key(key_id, namespace)                 │
│  │ F_keymgmt│────────────────────────────▶ key               │
│  └──────────┘                                                 │
│       │                                                       │
│       │ (key, message)                                        │
│       ▼                                                       │
│  ┌──────────┐     sign(key, message)                         │
│  │ F_crypto │────────────────────────────▶ signature         │
│  └──────────┘                                                 │
│       │                                                       │
│       │ (identity, operation, result)                         │
│       ▼                                                       │
│  ┌──────────┐     log(event)                                 │
│  │ F_audit  │────────────────────────────▶ logged            │
│  └──────────┘                                                 │
│       │                                                       │
│       ▼                                                       │
│  signature returned to client                                 │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
formal-proofs/
├── README.md                          # This file
├── coq/                               # Coq formalization
│   ├── crypto-ideal-functionality.v   # F_crypto definition
│   ├── keymgmt-ideal-functionality.v  # F_keymgmt definition
│   ├── auth-ideal-functionality.v     # F_auth definition
│   ├── audit-ideal-functionality.v    # F_audit definition
│   ├── composition-theorem.v          # Main composition proof
│   └── uc-framework.v                 # UC framework definitions
├── isabelle/                          # Alternative Isabelle/HOL proofs
│   └── (future work)
├── proof-sketches/                    # Informal proof sketches
│   ├── crypto-security-proof.md       # F_crypto UC proof sketch
│   ├── composition-proof.md           # Composition theorem sketch
│   └── attack-scenarios.md            # Adversary model examples
├── diagrams/                          # Visual diagrams
│   └── uc-composition-diagram.svg
├── security-model.md                  # Comprehensive threat model
├── attack-surface-analysis.md         # Security boundary analysis
└── threat-model.md                    # Adversary capabilities

```

## Security Guarantees

### What UC Proofs Give Us

1. **Modular Security**: Each module can be proven secure independently
2. **Composition Safety**: Secure modules remain secure when composed
3. **Concurrent Security**: Security holds even with arbitrary concurrent protocols
4. **Formal Guarantees**: Mathematical proof of security properties

### What UC Proofs Don't Cover

UC proofs operate at the **cryptographic protocol level**. They do **not** cover:

1. **Implementation Bugs**: Memory safety, buffer overflows (use Rust's type system + MIRI)
2. **Side Channels**: Timing attacks, cache attacks (need constant-time verification - see Agent 2)
3. **Physical Attacks**: Hardware tampering, power analysis (need TEE - see Agent 3)
4. **Compiler Correctness**: Rust → LLVM → Assembly (assume correct compilation)
5. **Operating System**: Assume trusted OS kernel

These are addressed by **other verification techniques** in the parallel agent tracks.

## Threat Model

### Adversary Capabilities

We consider adversaries with the following capabilities:

#### Network Adversary (Dolev-Yao)
- **Can**: Intercept, drop, modify, replay network messages
- **Cannot**: Break cryptography (e.g., forge signatures, decrypt without key)
- **Mitigation**: mTLS + authenticated encryption (F_auth, F_crypto)

#### Malicious Client
- **Can**: Authenticate with valid certificate, request operations
- **Cannot**: Access keys/namespaces outside authorization
- **Mitigation**: RBAC + namespace isolation (F_auth, F_keymgmt)

#### Compromised Module
- **Can**: Control one HSM module (e.g., audit logger)
- **Cannot**: Break security of other modules
- **Mitigation**: Module isolation + composition security

#### Adaptive Adversary
- **Can**: Choose attacks based on observed outputs (adaptive)
- **Cannot**: Distinguish real from ideal execution
- **Mitigation**: UC framework handles adaptive adversaries

### Out-of-Scope Threats

1. **Insider with Root Access**: Assumed trusted (key escrow via Shamir SSS)
2. **Physical Server Compromise**: Need hardware TEE (Agent 3)
3. **Supply Chain Attacks**: Trust Rust compiler and dependencies (audit via cargo-audit)
4. **Quantum Adversary**: Classical cryptography (future: post-quantum algorithms)

## Proof Status

### Completed
- [x] UC ideal functionalities defined (Coq and informal)
- [x] Composition theorem statement (informal proof sketch)
- [x] Threat model documented
- [x] Attack surface analysis

### In Progress
- [ ] F_crypto UC proof (Coq formalization)
- [ ] F_keymgmt UC proof (Coq formalization)
- [ ] F_auth UC proof (Coq formalization)
- [ ] F_audit UC proof (Coq formalization)

### Future Work
- [ ] Complete Coq proofs (mechanized verification)
- [ ] Isabelle/HOL alternative formalization
- [ ] Proof-carrying code generation
- [ ] Integration with Agent 1 (SMT verification)

## How to Use This Documentation

### For Security Auditors
1. Read **security-model.md** for the threat model
2. Read **attack-surface-analysis.md** for security boundaries
3. Review **proof-sketches/** for informal security arguments

### For Cryptographers
1. Read UC framework introduction above
2. Review **coq/** for formal ideal functionalities
3. Read **composition-theorem.v** for the main result

### For Developers
1. Understand that UC proofs provide **protocol-level** security
2. Use **threat-model.md** to understand adversary model
3. Combine with other verification (constant-time, formal verification, TEE)

## References

### Foundational Papers
1. **Canetti, R.** (2001). "Universally Composable Security: A New Paradigm for Cryptographic Protocols." *FOCS 2001*.
2. **Canetti, R., Rabin, T.** (2003). "Universal Composition with Joint State." *CRYPTO 2003*.
3. **Patrignani, M., Künnemann, R., Cecchetti, E., Wahby, R.** (2024). "Universal Composability is Robust Compilation."

### Tutorial Resources
4. **Lindell, Y.** (2016). "How to Simulate It – A Tutorial on the Simulation Proof Technique." *IACR ePrint 2016/046*.
5. **Canetti, R.** (2020). "Universally Composable Security" (Updated version). *IACR ePrint 2000/067*.

### Formal Verification
6. **Coq Development Team** (2025). "The Coq Proof Assistant." https://coq.inria.fr/
7. **Barthe, G., et al.** (2019). "Formal Verification of Cryptographic Protocols with CryptoVerif."

## Contact

For questions about the UC proofs, see:
- Research foundation: Riad Wahby (CMU/Cubist)
- Formal methods: Andres Nötzli, Aleksandar Milicevic (Cubist)
- HSM implementation: See `docs/CLAUDE.md`
