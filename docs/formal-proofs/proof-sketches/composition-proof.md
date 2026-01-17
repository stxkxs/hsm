# Composition Theorem Proof Sketch

## Overview

This document provides an **informal proof sketch** of the main composition theorem for the HSM. It bridges the gap between the formal Coq proofs (`coq/composition-theorem.v`) and intuitive understanding.

**Target Audience**: Security engineers, cryptographers, auditors

---

## Main Theorem

**Theorem (HSM_UC_Security)**:

If each real HSM module UC-realizes its ideal functionality, then the composed real HSM UC-realizes the composed ideal HSM.

**Formal Statement**:
```
∀ π_auth π_keymgmt π_crypto π_audit,
  UCRealizes π_auth F_auth →
  UCRealizes π_keymgmt F_keymgmt →
  UCRealizes π_crypto F_crypto →
  UCRealizes π_audit F_audit →
  UCRealizes (π_auth ⊗ π_keymgmt ⊗ π_crypto ⊗ π_audit)
             (F_auth ∘ F_keymgmt ∘ F_crypto ∘ F_audit)
```

---

## Proof Strategy

The proof uses the **Universal Composition Theorem** from Canetti (2001):

```
If π₁ ≈ F₁ and π₂ ≈ F₂, then (π₁ ⊗ π₂) ≈ (F₁ ∘ F₂)
```

where `≈` denotes "UC-realizes".

We apply this theorem **three times** to compose the four modules:

```
Step 1: π_crypto ⊗ π_audit ≈ F_crypto ∘ F_audit
Step 2: π_keymgmt ⊗ (π_crypto ⊗ π_audit) ≈ F_keymgmt ∘ (F_crypto ∘ F_audit)
Step 3: π_auth ⊗ [...] ≈ F_auth ∘ F_keymgmt ∘ F_crypto ∘ F_audit
```

---

## Step-by-Step Proof

### Step 1: Compose Crypto and Audit

**Goal**: Show `(π_crypto ⊗ π_audit) ≈ (F_crypto ∘ F_audit)`

**Given**:
- `π_crypto ≈ F_crypto` (Assumption)
- `π_audit ≈ F_audit` (Assumption)

**Proof**:

1. **Expand UC-realizes definition**:
   - For `π_crypto ≈ F_crypto`:
     ```
     ∀ A, ∃ S₁ such that REAL_{π_crypto,A,Z} ≈ IDEAL_{F_crypto,S₁,Z}
     ```
   - For `π_audit ≈ F_audit`:
     ```
     ∀ A, ∃ S₂ such that REAL_{π_audit,A,Z} ≈ IDEAL_{F_audit,S₂,Z}
     ```

2. **Apply Universal Composition Theorem**:
   - By the UC theorem, we can compose:
     ```
     REAL_{π_crypto⊗π_audit,A,Z} ≈ IDEAL_{F_crypto∘F_audit,S₁∘S₂,Z}
     ```

3. **Interpret**:
   - Running `π_crypto` and `π_audit` together in the real world
   - Is indistinguishable from running `F_crypto` and `F_audit` in the ideal world
   - Even when an adversary A is attacking

**Why this works**: The UC framework guarantees that security is preserved under composition. The simulator `S₁ ∘ S₂` can simulate both protocols simultaneously.

---

### Step 2: Add Key Management

**Goal**: Show `(π_keymgmt ⊗ [π_crypto ⊗ π_audit]) ≈ (F_keymgmt ∘ [F_crypto ∘ F_audit])`

**Given**:
- `π_keymgmt ≈ F_keymgmt` (Assumption)
- `(π_crypto ⊗ π_audit) ≈ (F_crypto ∘ F_audit)` (From Step 1)

**Proof**:

1. **Treat `(π_crypto ⊗ π_audit)` as a single protocol**:
   - Let `π_CA = π_crypto ⊗ π_audit`
   - Let `F_CA = F_crypto ∘ F_audit`
   - We know: `π_CA ≈ F_CA` (from Step 1)

2. **Apply UC Composition again**:
   - We have: `π_keymgmt ≈ F_keymgmt` and `π_CA ≈ F_CA`
   - By UC theorem:
     ```
     (π_keymgmt ⊗ π_CA) ≈ (F_keymgmt ∘ F_CA)
     ```

3. **Expand**:
   ```
   (π_keymgmt ⊗ [π_crypto ⊗ π_audit]) ≈ (F_keymgmt ∘ [F_crypto ∘ F_audit])
   ```

**Intuition**: Key management operates on top of crypto+audit. The UC framework ensures that even though key management calls crypto operations, security is preserved.

---

### Step 3: Add Authentication

**Goal**: Show full HSM composition

**Given**:
- `π_auth ≈ F_auth` (Assumption)
- `(π_keymgmt ⊗ π_crypto ⊗ π_audit) ≈ (F_keymgmt ∘ F_crypto ∘ F_audit)` (From Step 2)

**Proof**:

1. **Treat previous composition as single protocol**:
   - Let `π_KCA = π_keymgmt ⊗ π_crypto ⊗ π_audit`
   - Let `F_KCA = F_keymgmt ∘ F_crypto ∘ F_audit`
   - We know: `π_KCA ≈ F_KCA` (from Step 2)

2. **Final composition**:
   - We have: `π_auth ≈ F_auth` and `π_KCA ≈ F_KCA`
   - By UC theorem:
     ```
     (π_auth ⊗ π_KCA) ≈ (F_auth ∘ F_KCA)
     ```

3. **Expand to full HSM**:
   ```
   HSM_real = π_auth ⊗ π_keymgmt ⊗ π_crypto ⊗ π_audit
   HSM_ideal = F_auth ∘ F_keymgmt ∘ F_crypto ∘ F_audit

   HSM_real ≈ HSM_ideal
   ```

**Result**: The real HSM is as secure as the ideal HSM. ∎

---

## Why This Proof is Powerful

### 1. Modular Security

We never had to reason about the entire HSM at once. Instead:
- Prove `π_auth ≈ F_auth` independently
- Prove `π_keymgmt ≈ F_keymgmt` independently
- Prove `π_crypto ≈ F_crypto` independently
- Prove `π_audit ≈ F_audit` independently
- **Composition is free** (via UC theorem)

### 2. Concurrent Security

The UC framework handles concurrent execution automatically. Even if:
- Multiple clients connect simultaneously
- Requests interleave arbitrarily
- Adversary adaptively chooses attacks

The security still holds. No need to re-prove for concurrent case.

### 3. Arbitrary Environments

The proof holds for **any** environment `Z`. This means:
- HSM can be used in any context (web service, IoT, blockchain)
- Can run alongside other protocols
- Security doesn't depend on usage pattern

---

## Proof of Individual Module Security

While the composition proof relies on the UC theorem, we still need to prove:
```
π_auth ≈ F_auth
π_keymgmt ≈ F_keymgmt
π_crypto ≈ F_crypto
π_audit ≈ F_audit
```

### Proof Sketch: π_crypto ≈ F_crypto

**Goal**: Show real crypto engine UC-realizes ideal crypto functionality

**Approach**: Construct a simulator `S_crypto`

**Simulator Construction**:
1. **Intercept ideal function calls**:
   - When environment calls `F_crypto.Sign(key_id, m)`
   - Simulator generates signature using real crypto library (ed25519-dalek)
   - Returns signature to environment

2. **Simulate adversary's view**:
   - Adversary sees real signatures (from ed25519-dalek)
   - These are indistinguishable from ideal signatures (by EUF-CMA security)

3. **Indistinguishability argument**:
   - In **real world**: `π_crypto` uses ed25519-dalek to sign
   - In **ideal world**: `F_crypto` uses random oracle to sign, `S_crypto` uses ed25519-dalek
   - Environment cannot distinguish because ed25519-dalek is EUF-CMA secure

**Why this works**: Ed25519 signatures are pseudorandom (look random to adversary). Ideal signatures are truly random. These are computationally indistinguishable.

---

### Proof Sketch: π_keymgmt ≈ F_keymgmt

**Goal**: Show real key manager UC-realizes ideal key management

**Key Challenge**: Namespace isolation

**Simulator Construction**:
1. **Maintain namespace mapping**:
   - For each namespace `ns`, simulator tracks keys in `ns`
   - On `GetKey(key_id, ns)`, simulator checks namespace isolation

2. **Simulate secure deletion**:
   - On `DeleteKey(key_id, ns)`, simulator removes from table
   - Later `GetKey(key_id, ns)` returns `None`

3. **Indistinguishability**:
   - In **real world**: `π_keymgmt` uses encrypted storage with namespace directories
   - In **ideal world**: `F_keymgmt` uses perfect isolation tables
   - Environment cannot distinguish because:
     - Encryption hides keys (IND-CCA2)
     - File system permissions enforce isolation

**Why this works**: Encryption provides computational hiding. Namespace isolation in filesystem mirrors ideal isolation.

---

### Proof Sketch: π_auth ≈ F_auth

**Goal**: Show real auth module UC-realizes ideal authentication

**Key Challenge**: Session integrity

**Simulator Construction**:
1. **Certificate validation**:
   - Simulator validates cert against CA (like real implementation)
   - Extracts identity (CN, OU → namespace)

2. **RBAC simulation**:
   - Simulator maintains permission matrix (Admin, Operator, User, Auditor)
   - Checks permissions exactly as `F_auth`

3. **Session integrity**:
   - Simulator binds session to IP address
   - Rejects session with different IP (prevents hijacking)

**Indistinguishability**:
- In **real world**: mTLS provides authentication, RBAC enforces authorization
- In **ideal world**: `F_auth` provides perfect authentication
- Environment cannot distinguish because:
  - mTLS signatures are unforgeable (SUF-CMA)
  - Session IDs are random (unpredictable)

**Why this works**: mTLS provides computational authentication. This is indistinguishable from perfect authentication.

---

### Proof Sketch: π_audit ≈ F_audit

**Goal**: Show real audit logger UC-realizes ideal tamper evidence

**Key Challenge**: Tamper evidence via hash chain

**Simulator Construction**:
1. **Log append**:
   - Simulator computes `hash(entry_n || prev_hash)`
   - Stores in append-only log

2. **Verification**:
   - Simulator recomputes hash chain
   - Detects tampering if hashes don't match

**Indistinguishability**:
- In **real world**: `π_audit` uses SHA-256 hash chain
- In **ideal world**: `F_audit` uses perfect tamper evidence
- Environment cannot distinguish because:
  - SHA-256 is collision-resistant
  - Cannot find `entry'` with `hash(entry') = hash(entry)`

**Why this works**: Collision resistance of SHA-256 provides computational tamper evidence. This is indistinguishable from perfect tamper evidence.

---

## End-to-End Security Properties

The composition theorem implies end-to-end security properties:

### Property 1: Authentication Implies Authorization

**Claim**:
```
Successful operation ⇒ Client was authenticated AND authorized
```

**Proof Sketch**:

1. **Request flow**:
   ```
   Request → F_auth.Authenticate → F_auth.Authorize → F_keymgmt.GetKey → F_crypto.Sign → F_audit.Log
   ```

2. **Each step is a barrier**:
   - `Authenticate` fails if cert invalid → request rejected
   - `Authorize` fails if no permission → request rejected
   - `GetKey` fails if wrong namespace → request rejected

3. **Only successful path**:
   - Request succeeds ⇔ All checks pass
   - By composition, same holds in real world

**Intuition**: Composition preserves security properties. If ideal world requires authentication+authorization, so does real world.

---

### Property 2: Namespace Isolation End-to-End

**Claim**:
```
identity.namespace ≠ key.namespace ⇒ GetKey fails ⇒ Crypto operation fails
```

**Proof Sketch**:

1. **Isolation at F_auth**:
   - `Authorize(identity, op, KeyResource(key_id, ns))` checks `identity.namespace == ns`
   - Fails if namespaces differ (Theorem `namespace_isolation_auth`)

2. **Isolation at F_keymgmt**:
   - `GetKey(key_id, ns)` checks requester's namespace
   - Returns key only if `requester.namespace == ns` (Theorem `namespace_isolation`)

3. **Composition**:
   - Request must pass both checks
   - Either check fails → request rejected
   - By UC composition, real world behaves identically

**Intuition**: Defense-in-depth. Multiple layers enforce namespace isolation.

---

### Property 3: Audit Completeness

**Claim**:
```
Operation succeeds ⇒ Operation is logged in F_audit
```

**Proof Sketch**:

1. **Request flow**:
   - Every operation ends with `F_audit.Log(event)`
   - By composition, `π_audit.log(event)` is called in real world

2. **Log append-only**:
   - `F_audit` never removes entries (Theorem `log_append_only`)
   - By UC, `π_audit` also append-only

3. **Tamper evidence**:
   - Any modification breaks hash chain (Theorem `tamper_evidence`)
   - By UC, real audit log also detects tampering

**Intuition**: Composition preserves completeness and integrity. All logged events remain logged.

---

## Handling Adaptive Adversaries

The UC framework automatically handles **adaptive adversaries**:

### What is an Adaptive Adversary?

An adversary that:
- Observes outputs of previous operations
- Chooses next attack based on observations
- Example: Chosen-ciphertext attack (CCA)

### Why UC Handles This

1. **Definition includes environment `Z`**:
   - Environment can run arbitrary protocols
   - Can adaptively choose messages based on outputs

2. **Simulator must work for all `Z`**:
   - Including adaptive environments
   - Simulator cannot "cheat" (doesn't know future queries)

3. **Indistinguishability**:
   - `REAL_{π,A,Z} ≈ IDEAL_{F,S,Z}` holds for adaptive `Z`
   - Therefore, security holds against adaptive attacks

**Example**: Chosen-Ciphertext Attack on F_crypto

1. **Adversary's strategy**:
   - Get ciphertext `c₁ = Encrypt(m₁)`
   - Modify to `c₂ = c₁ ⊕ delta`
   - Call `Decrypt(c₂)` to learn `m₂`

2. **Why it fails**:
   - `F_crypto` uses authenticated encryption (AES-GCM)
   - Modified ciphertext `c₂` fails authentication tag check
   - `Decrypt(c₂)` returns error
   - Adversary learns nothing

3. **UC proof**:
   - Simulator handles `Decrypt` queries
   - Returns error for invalid ciphertext (like real AES-GCM)
   - Environment cannot distinguish

---

## Composition with Concurrent Execution

### Sequential vs Parallel Composition

**Sequential** (`∘`):
```
F_auth ∘ F_keymgmt ∘ F_crypto ∘ F_audit
```
- Execution order: auth → keymgmt → crypto → audit
- One request at a time

**Parallel** (`||`):
```
(F_auth || F_keymgmt) || (F_crypto || F_audit)
```
- Multiple requests simultaneously
- Interleaved execution

### Theorem: Parallel Composition Also Secure

**Claim**: UC security holds for parallel composition

**Proof Sketch**:

1. **UC handles concurrency**:
   - Environment `Z` can run arbitrary concurrent protocols
   - UC security must hold even with interleaving

2. **Module independence**:
   - `F_auth`, `F_keymgmt`, `F_crypto`, `F_audit` are independent
   - No shared state (except keys, protected by locks)

3. **Real-world concurrency**:
   - `π_auth`, `π_keymgmt`, etc. use concurrent data structures (DashMap)
   - Thread-safe, no race conditions

4. **Indistinguishability**:
   - Concurrent real execution ≈ Concurrent ideal execution
   - By UC composition theorem (parallel version)

**Intuition**: UC framework was designed for concurrent execution. Security holds automatically.

---

## Summary

**Main Result**: `HSM_real ≈ HSM_ideal`

**Proof Method**:
1. Define ideal functionalities (F_auth, F_keymgmt, F_crypto, F_audit)
2. Prove each module UC-realizes its ideal functionality
3. Apply UC composition theorem 3 times
4. Result: Composed HSM is secure

**Key Insights**:
- **Modular**: Prove modules independently, compose for free
- **Concurrent**: Handles concurrent execution automatically
- **Adaptive**: Secure against adaptive adversaries
- **Universal**: Holds in any environment

**Next Steps**:
- Complete Coq mechanization (formalize proofs)
- Verify constant-time properties (Agent 2)
- Integrate with SMT verification (Agent 1)
- Deploy with TEE backing (Agent 3)

---

## References

1. **Canetti, R.** (2001). "Universally Composable Security: A New Paradigm for Cryptographic Protocols." *FOCS 2001*.
2. **Canetti, R.** (2020). "Universally Composable Security" (Updated). *IACR ePrint 2000/067*.
3. **Lindell, Y.** (2016). "How to Simulate It – A Tutorial on the Simulation Proof Technique." *IACR ePrint 2016/046*.
4. **Patrignani, M., et al.** (2024). "Universal Composability is Robust Compilation."
