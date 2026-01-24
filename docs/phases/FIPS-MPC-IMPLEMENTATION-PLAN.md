# FIPS Enhancement & MPC Custody Suite Implementation Plan

## Executive Summary

This plan adds **MPC (Multi-Party Computation) custody capabilities** and **enhances FIPS 140-3 compliance** for threshold cryptography. The implementation uses **8 parallel workstreams** that can be executed concurrently by multiple agents.

**Timeline**: 8 parallel workstreams, ~50 tasks total
**New Code**: ~8,000-10,000 lines of Rust
**Files Modified**: ~15 existing files
**Files Created**: ~20 new files

---

## Current State Analysis

### FIPS Module (Exists - 2,437 lines)
```
crates/crypto-engine/src/fips/
├── mod.rs           ✓ Complete
├── mode.rs          ✓ Complete (needs threshold extensions)
├── algorithms.rs    ✓ Complete (needs threshold algorithm registry)
├── self_test.rs     ✓ Complete (needs threshold KATs)
├── rng.rs           ✓ Complete
├── integrity.rs     ✓ Complete
└── audit.rs         ✓ Complete (needs threshold events)
```

### Threshold Module (Partial - FROST-Ed25519 only)
```
crates/crypto-engine/src/threshold/
├── mod.rs           ✓ Complete
├── types.rs         ✓ Complete (needs ECDSA/BLS types)
├── frost.rs         ✓ Complete (Ed25519 only)
├── participant.rs   ✓ Complete
├── coordinator.rs   ✓ Complete
├── dkg.rs           ✓ Complete (Ed25519 only)
├── ecdsa.rs         ✗ NEW - Threshold ECDSA
├── bls.rs           ✗ NEW - Threshold BLS
├── refresh.rs       ✗ NEW - Key refresh protocol
└── resharing.rs     ✗ NEW - Dynamic resharing
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        MPC Custody Suite Architecture                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │  FROST Ed25519  │  │ Threshold ECDSA │  │  Threshold BLS  │             │
│  │    (exists)     │  │     (NEW)       │  │     (NEW)       │             │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘             │
│           │                    │                    │                       │
│           ▼                    ▼                    ▼                       │
│  ┌─────────────────────────────────────────────────────────────┐           │
│  │                    Shared Infrastructure                     │           │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │           │
│  │  │    Types    │ │     DKG     │ │ Key Refresh │            │           │
│  │  │ (extended)  │ │ (per-scheme)│ │  (NEW)      │            │           │
│  │  └─────────────┘ └─────────────┘ └─────────────┘            │           │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │           │
│  │  │ Coordinator │ │ Participant │ │  Resharing  │            │           │
│  │  │ (extended)  │ │ (extended)  │ │    (NEW)    │            │           │
│  │  └─────────────┘ └─────────────┘ └─────────────┘            │           │
│  └─────────────────────────────────────────────────────────────┘           │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐           │
│  │                     FIPS Compliance Layer                    │           │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │           │
│  │  │  Algorithm  │ │  Self-Test  │ │    Audit    │            │           │
│  │  │  Registry   │ │    KATs     │ │   Events    │            │           │
│  │  │ (threshold) │ │ (threshold) │ │ (threshold) │            │           │
│  │  └─────────────┘ └─────────────┘ └─────────────┘            │           │
│  └─────────────────────────────────────────────────────────────┘           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Parallel Workstream Design

### Dependency Graph

```
                    ┌──────────────────┐
                    │   WS1: Types &   │
                    │   Infrastructure │
                    └────────┬─────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
   ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
   │  WS2: ECDSA    │ │  WS3: BLS      │ │  WS4: FIPS     │
   │  Engine        │ │  Engine        │ │  Extensions    │
   └────────┬───────┘ └────────┬───────┘ └────────┬───────┘
            │                  │                  │
            ▼                  ▼                  │
   ┌────────────────┐ ┌────────────────┐         │
   │  WS5: ECDSA    │ │  WS6: BLS      │         │
   │  DKG           │ │  DKG           │         │
   └────────┬───────┘ └────────┬───────┘         │
            │                  │                  │
            └────────┬─────────┘                  │
                     │                            │
                     ▼                            │
            ┌────────────────┐                    │
            │  WS7: Key      │                    │
            │  Refresh       │                    │
            └────────┬───────┘                    │
                     │                            │
                     └────────────┬───────────────┘
                                  │
                                  ▼
                         ┌────────────────┐
                         │  WS8: Tests &  │
                         │  Benchmarks    │
                         └────────────────┘
```

### Parallelism Opportunities

| Phase | Parallel Workstreams | Dependencies |
|-------|---------------------|--------------|
| **Phase 1** | WS1 (Types) | None |
| **Phase 2** | WS2 (ECDSA) + WS3 (BLS) + WS4 (FIPS) | WS1 |
| **Phase 3** | WS5 (ECDSA DKG) + WS6 (BLS DKG) | WS2, WS3 |
| **Phase 4** | WS7 (Key Refresh) | WS5, WS6 |
| **Phase 5** | WS8 (Tests/Benchmarks) | All |

---

## Workstream 1: Types & Infrastructure (Foundation)

**Owner**: Agent 1
**Estimated Tasks**: 6
**Dependencies**: None
**Parallel With**: None (must complete first)

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `threshold/types.rs` | Modify | Add ECDSA/BLS type variants |
| `threshold/scheme.rs` | Create | Scheme abstraction trait |
| `threshold/config.rs` | Create | Extended configuration |
| `threshold/session.rs` | Create | Session management |

### Tasks

#### Task 1.1: Extend ThresholdScheme Enum
```rust
// In threshold/types.rs
pub enum ThresholdScheme {
    FrostEd25519,           // Existing
    ThresholdEcdsaP256,     // NEW
    ThresholdEcdsaSecp256k1,// NEW
    ThresholdBls12381,      // NEW
}

pub enum KeyShareType {
    FrostEd25519(frost_ed25519::keys::KeyPackage),
    EcdsaP256(EcdsaKeyShare),
    EcdsaSecp256k1(EcdsaKeyShare),
    Bls12381(BlsKeyShare),
}
```

#### Task 1.2: Create Scheme Abstraction Trait
```rust
// NEW: threshold/scheme.rs
pub trait ThresholdScheme: Send + Sync {
    type PublicKey: Clone + Serialize;
    type SecretShare: Clone + Zeroize;
    type Signature: Clone + Serialize;
    type SigningCommitment: Clone;
    type SignatureShare: Clone;

    fn scheme_id(&self) -> &'static str;
    fn generate_key_shares(&self, config: &ThresholdConfig)
        -> Result<(Self::PublicKey, Vec<Self::SecretShare>)>;
    fn create_commitment(&self, share: &Self::SecretShare)
        -> Result<(SigningNonce, Self::SigningCommitment)>;
    fn create_signature_share(&self, ...) -> Result<Self::SignatureShare>;
    fn aggregate(&self, ...) -> Result<Self::Signature>;
    fn verify(&self, ...) -> Result<bool>;
}
```

#### Task 1.3: Create Extended Configuration
```rust
// NEW: threshold/config.rs
pub struct ThresholdSessionConfig {
    pub scheme: ThresholdScheme,
    pub threshold: u16,
    pub total_participants: u16,
    pub session_timeout: Duration,
    pub fips_mode: bool,
}

pub struct DkgConfig {
    pub scheme: ThresholdScheme,
    pub threshold: u16,
    pub participants: Vec<ParticipantId>,
    pub round_timeout: Duration,
}

pub struct KeyRefreshConfig {
    pub scheme: ThresholdScheme,
    pub old_threshold: u16,
    pub new_threshold: u16,
    pub participants_to_add: Vec<ParticipantId>,
    pub participants_to_remove: Vec<ParticipantId>,
}
```

#### Task 1.4: Create Session Management
```rust
// NEW: threshold/session.rs
pub struct ThresholdSession {
    pub id: SessionId,
    pub scheme: ThresholdScheme,
    pub config: ThresholdSessionConfig,
    pub state: SessionState,
    pub participants: HashMap<ParticipantId, ParticipantState>,
    pub commitments: HashMap<ParticipantId, SigningCommitment>,
    pub signature_shares: HashMap<ParticipantId, SignatureShare>,
    pub created_at: Instant,
}

pub enum SessionState {
    AwaitingCommitments,
    AwaitingSignatureShares,
    Aggregating,
    Complete,
    Failed(String),
}
```

#### Task 1.5: Add Error Types
```rust
// Extend threshold/types.rs ThresholdError
pub enum ThresholdError {
    // Existing...
    UnsupportedScheme(ThresholdScheme),
    DkgRoundTimeout { round: u8, timeout_ms: u64 },
    KeyRefreshFailed(String),
    ResharingFailed(String),
    FipsNotApproved(String),
    SessionExpired(SessionId),
    InvalidCommitment(ParticipantId),
}
```

#### Task 1.6: Update Module Exports
```rust
// threshold/mod.rs
pub mod scheme;
pub mod config;
pub mod session;
pub mod ecdsa;  // Will be created in WS2
pub mod bls;    // Will be created in WS3
pub mod refresh;// Will be created in WS7

pub use scheme::ThresholdScheme;
pub use config::{ThresholdSessionConfig, DkgConfig, KeyRefreshConfig};
pub use session::{ThresholdSession, SessionState};
```

### Success Criteria
- [ ] All new types compile
- [ ] Existing FROST tests still pass
- [ ] New types are `Send + Sync`
- [ ] All sensitive types implement `Zeroize`

---

## Workstream 2: Threshold ECDSA Engine

**Owner**: Agent 2
**Estimated Tasks**: 8
**Dependencies**: WS1 (Types)
**Parallel With**: WS3 (BLS), WS4 (FIPS)

### Files to Create

| File | Lines Est. | Description |
|------|------------|-------------|
| `threshold/ecdsa/mod.rs` | 50 | Module exports |
| `threshold/ecdsa/engine.rs` | 400 | Core ECDSA threshold engine |
| `threshold/ecdsa/types.rs` | 200 | ECDSA-specific types |
| `threshold/ecdsa/p256.rs` | 300 | P-256 curve implementation |
| `threshold/ecdsa/secp256k1.rs` | 300 | secp256k1 implementation |

### Tasks

#### Task 2.1: Create ECDSA Types
```rust
// threshold/ecdsa/types.rs
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaKeyShare {
    pub participant_id: ParticipantId,
    pub secret_share: Vec<u8>,  // Scalar share
    pub public_share: Vec<u8>,  // Point on curve
    pub group_public_key: Vec<u8>,
    pub curve: EcdsaCurve,
}

#[derive(Clone, Copy)]
pub enum EcdsaCurve {
    P256,
    Secp256k1,
}

pub struct EcdsaSigningCommitment {
    pub participant_id: ParticipantId,
    pub commitment_d: Vec<u8>,  // D_i commitment
    pub commitment_e: Vec<u8>,  // E_i commitment
}

pub struct EcdsaSignatureShare {
    pub participant_id: ParticipantId,
    pub share: Vec<u8>,  // s_i value
}

pub struct EcdsaPreSignature {
    pub r: Vec<u8>,      // R point x-coordinate
    pub k_share: Vec<u8>,// k share for this participant
}
```

#### Task 2.2: Create ECDSA Engine Interface
```rust
// threshold/ecdsa/engine.rs
pub struct ThresholdEcdsaEngine;

impl ThresholdEcdsaEngine {
    /// Trusted dealer key generation (for testing/bootstrap)
    pub fn trusted_dealer_keygen(
        config: ThresholdConfig,
        curve: EcdsaCurve,
    ) -> Result<(GroupPublicKey, Vec<EcdsaKeyShare>), ThresholdError>;

    /// Generate nonces and commitments for signing round 1
    pub fn generate_nonces(
        key_share: &EcdsaKeyShare,
    ) -> Result<(EcdsaSigningNonce, EcdsaSigningCommitment), ThresholdError>;

    /// Pre-signing phase (can be done before message is known)
    pub fn presign(
        key_share: &EcdsaKeyShare,
        commitments: &[EcdsaSigningCommitment],
        participants: &[ParticipantId],
    ) -> Result<EcdsaPreSignature, ThresholdError>;

    /// Generate signature share
    pub fn sign_share(
        key_share: &EcdsaKeyShare,
        presignature: &EcdsaPreSignature,
        message_hash: &[u8; 32],
    ) -> Result<EcdsaSignatureShare, ThresholdError>;

    /// Aggregate signature shares into final signature
    pub fn aggregate(
        group_public_key: &GroupPublicKey,
        presignature: &EcdsaPreSignature,
        signature_shares: &[EcdsaSignatureShare],
        message_hash: &[u8; 32],
    ) -> Result<ThresholdSignature, ThresholdError>;

    /// Verify a threshold ECDSA signature
    pub fn verify(
        public_key: &GroupPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
        curve: EcdsaCurve,
    ) -> Result<bool, ThresholdError>;
}
```

#### Task 2.3: Implement P-256 Threshold ECDSA
```rust
// threshold/ecdsa/p256.rs
use p256::{ecdsa::*, elliptic_curve::*, ProjectivePoint, Scalar};

pub struct P256ThresholdOps;

impl P256ThresholdOps {
    /// Shamir secret sharing over P-256 scalar field
    pub fn split_secret(
        secret: &Scalar,
        threshold: u16,
        total: u16,
    ) -> Result<Vec<Scalar>, ThresholdError>;

    /// Lagrange coefficient computation
    pub fn lagrange_coefficient(
        participant: ParticipantId,
        participants: &[ParticipantId],
    ) -> Scalar;

    /// Commitment generation (Pedersen)
    pub fn generate_commitment(
        nonce_d: &Scalar,
        nonce_e: &Scalar,
    ) -> (ProjectivePoint, ProjectivePoint);

    /// Signature share computation
    pub fn compute_signature_share(
        secret_share: &Scalar,
        k_share: &Scalar,
        r: &Scalar,
        message_hash: &Scalar,
        lagrange: &Scalar,
    ) -> Scalar;
}
```

#### Task 2.4: Implement secp256k1 Threshold ECDSA
```rust
// threshold/ecdsa/secp256k1.rs
use k256::{ecdsa::*, elliptic_curve::*, ProjectivePoint, Scalar};

pub struct Secp256k1ThresholdOps;

impl Secp256k1ThresholdOps {
    // Same interface as P256, different curve
    pub fn split_secret(...) -> Result<Vec<Scalar>, ThresholdError>;
    pub fn lagrange_coefficient(...) -> Scalar;
    pub fn generate_commitment(...) -> (ProjectivePoint, ProjectivePoint);
    pub fn compute_signature_share(...) -> Scalar;
}
```

#### Task 2.5: Implement Trusted Dealer Keygen
```rust
impl ThresholdEcdsaEngine {
    pub fn trusted_dealer_keygen(
        config: ThresholdConfig,
        curve: EcdsaCurve,
    ) -> Result<(GroupPublicKey, Vec<EcdsaKeyShare>), ThresholdError> {
        // 1. Generate random secret key
        let secret = generate_random_scalar(curve)?;

        // 2. Compute group public key
        let group_public = scalar_to_point(&secret, curve);

        // 3. Split secret using Shamir's Secret Sharing
        let shares = match curve {
            EcdsaCurve::P256 => P256ThresholdOps::split_secret(
                &secret, config.threshold, config.total_participants
            )?,
            EcdsaCurve::Secp256k1 => Secp256k1ThresholdOps::split_secret(
                &secret, config.threshold, config.total_participants
            )?,
        };

        // 4. Create key share structs
        let key_shares = shares.iter().enumerate().map(|(i, share)| {
            EcdsaKeyShare {
                participant_id: ParticipantId::new((i + 1) as u16)?,
                secret_share: share.to_bytes().to_vec(),
                public_share: scalar_to_point(share, curve).to_bytes().to_vec(),
                group_public_key: group_public.to_bytes().to_vec(),
                curve,
            }
        }).collect();

        Ok((GroupPublicKey::new(group_public.to_bytes().to_vec()), key_shares))
    }
}
```

#### Task 2.6: Implement Signing Protocol
```rust
impl ThresholdEcdsaEngine {
    pub fn sign_share(
        key_share: &EcdsaKeyShare,
        presignature: &EcdsaPreSignature,
        message_hash: &[u8; 32],
    ) -> Result<EcdsaSignatureShare, ThresholdError> {
        match key_share.curve {
            EcdsaCurve::P256 => {
                let secret = Scalar::from_bytes(key_share.secret_share.as_slice())?;
                let k = Scalar::from_bytes(presignature.k_share.as_slice())?;
                let r = Scalar::from_bytes(presignature.r.as_slice())?;
                let m = Scalar::from_bytes(message_hash)?;

                // s_i = k_i * (m + r * x_i) where x_i is secret share
                let share = P256ThresholdOps::compute_signature_share(
                    &secret, &k, &r, &m, &lagrange_coeff
                );

                Ok(EcdsaSignatureShare {
                    participant_id: key_share.participant_id,
                    share: share.to_bytes().to_vec(),
                })
            }
            EcdsaCurve::Secp256k1 => {
                // Similar for secp256k1
            }
        }
    }
}
```

#### Task 2.7: Implement Aggregation
```rust
impl ThresholdEcdsaEngine {
    pub fn aggregate(
        group_public_key: &GroupPublicKey,
        presignature: &EcdsaPreSignature,
        signature_shares: &[EcdsaSignatureShare],
        message_hash: &[u8; 32],
    ) -> Result<ThresholdSignature, ThresholdError> {
        // Sum signature shares: s = Σ s_i
        let s = signature_shares.iter()
            .map(|share| Scalar::from_bytes(&share.share))
            .try_fold(Scalar::ZERO, |acc, s| Ok(acc + s?))?;

        // Construct signature (r, s)
        let r = &presignature.r;
        let signature = encode_der_signature(r, &s.to_bytes())?;

        Ok(ThresholdSignature {
            bytes: signature,
            scheme: ThresholdScheme::ThresholdEcdsaP256,
        })
    }
}
```

#### Task 2.8: Add Unit Tests
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_ecdsa_2_of_3_p256() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
            config, EcdsaCurve::P256
        ).unwrap();

        // Generate nonces
        let (nonce1, commit1) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
        let (nonce2, commit2) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();

        // Presign
        let presig1 = ThresholdEcdsaEngine::presign(&shares[0], &[commit1, commit2], &[1, 2]).unwrap();
        let presig2 = ThresholdEcdsaEngine::presign(&shares[1], &[commit1, commit2], &[1, 2]).unwrap();

        // Sign
        let msg_hash = sha256(b"test message");
        let share1 = ThresholdEcdsaEngine::sign_share(&shares[0], &presig1, &msg_hash).unwrap();
        let share2 = ThresholdEcdsaEngine::sign_share(&shares[1], &presig2, &msg_hash).unwrap();

        // Aggregate
        let sig = ThresholdEcdsaEngine::aggregate(&group_key, &presig1, &[share1, share2], &msg_hash).unwrap();

        // Verify
        assert!(ThresholdEcdsaEngine::verify(&group_key, b"test message", &sig, EcdsaCurve::P256).unwrap());
    }

    #[test]
    fn test_ecdsa_3_of_5_secp256k1() {
        // Similar test for secp256k1
    }

    #[test]
    fn test_ecdsa_wrong_message_fails() {
        // Verify wrong message detection
    }

    #[test]
    fn test_ecdsa_insufficient_shares_fails() {
        // Verify threshold enforcement
    }
}
```

### Success Criteria
- [ ] 2-of-3 P-256 signing works
- [ ] 3-of-5 secp256k1 signing works
- [ ] Signatures verify with standard ECDSA verifier
- [ ] Wrong message verification fails
- [ ] Insufficient shares fail gracefully
- [ ] All key material zeroized on drop

---

## Workstream 3: Threshold BLS Engine

**Owner**: Agent 3
**Estimated Tasks**: 7
**Dependencies**: WS1 (Types)
**Parallel With**: WS2 (ECDSA), WS4 (FIPS)

### Files to Create

| File | Lines Est. | Description |
|------|------------|-------------|
| `threshold/bls/mod.rs` | 50 | Module exports |
| `threshold/bls/engine.rs` | 350 | Core BLS threshold engine |
| `threshold/bls/types.rs` | 150 | BLS-specific types |
| `threshold/bls/aggregation.rs` | 200 | BLS aggregation (native support) |

### Tasks

#### Task 3.1: Create BLS Types
```rust
// threshold/bls/types.rs
use blst::min_pk::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlsKeyShare {
    pub participant_id: ParticipantId,
    #[zeroize(skip)]  // blst SecretKey doesn't impl Zeroize, handle manually
    secret_share_bytes: Vec<u8>,
    pub public_share: Vec<u8>,  // 48 bytes compressed G1
    pub group_public_key: Vec<u8>,  // 48 bytes compressed G1
}

impl BlsKeyShare {
    pub fn secret_key(&self) -> Result<SecretKey, ThresholdError> {
        SecretKey::from_bytes(&self.secret_share_bytes)
            .map_err(|_| ThresholdError::InvalidKeyShare)
    }
}

impl Drop for BlsKeyShare {
    fn drop(&mut self) {
        self.secret_share_bytes.zeroize();
    }
}

pub struct BlsSignatureShare {
    pub participant_id: ParticipantId,
    pub share: Vec<u8>,  // 96 bytes compressed G2
}
```

#### Task 3.2: Create BLS Engine Interface
```rust
// threshold/bls/engine.rs
pub struct ThresholdBlsEngine;

impl ThresholdBlsEngine {
    /// Trusted dealer key generation
    pub fn trusted_dealer_keygen(
        config: ThresholdConfig,
    ) -> Result<(GroupPublicKey, Vec<BlsKeyShare>), ThresholdError>;

    /// Generate signature share (BLS is single-round!)
    pub fn sign_share(
        key_share: &BlsKeyShare,
        message: &[u8],
    ) -> Result<BlsSignatureShare, ThresholdError>;

    /// Aggregate signature shares (BLS native aggregation)
    pub fn aggregate(
        signature_shares: &[BlsSignatureShare],
        participants: &[ParticipantId],
    ) -> Result<ThresholdSignature, ThresholdError>;

    /// Verify threshold BLS signature
    pub fn verify(
        public_key: &GroupPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError>;

    /// Multi-signature aggregation (combine multiple signatures)
    pub fn aggregate_signatures(
        signatures: &[ThresholdSignature],
    ) -> Result<ThresholdSignature, ThresholdError>;

    /// Aggregate public keys (for multi-party verification)
    pub fn aggregate_public_keys(
        public_keys: &[GroupPublicKey],
    ) -> Result<GroupPublicKey, ThresholdError>;
}
```

#### Task 3.3: Implement Shamir Secret Sharing for BLS
```rust
// threshold/bls/engine.rs
use blst::blst_scalar;

impl ThresholdBlsEngine {
    fn split_secret_bls(
        secret: &SecretKey,
        threshold: u16,
        total: u16,
    ) -> Result<Vec<SecretKey>, ThresholdError> {
        // Generate random polynomial coefficients
        let mut coefficients = vec![secret.clone()];
        for _ in 1..threshold {
            coefficients.push(SecretKey::random(&mut OsRng));
        }

        // Evaluate polynomial at each participant's x-coordinate
        let shares: Vec<SecretKey> = (1..=total).map(|i| {
            let x = blst_scalar::from(i as u64);
            evaluate_polynomial(&coefficients, &x)
        }).collect();

        Ok(shares)
    }

    fn lagrange_coefficient_bls(
        participant: ParticipantId,
        participants: &[ParticipantId],
    ) -> blst_scalar {
        // λ_i = Π_{j≠i} (x_j / (x_j - x_i))
        let mut result = blst_scalar::one();
        let x_i = blst_scalar::from(participant.0 as u64);

        for &p in participants {
            if p != participant {
                let x_j = blst_scalar::from(p.0 as u64);
                let num = x_j;
                let denom = x_j - x_i;
                result = result * num * denom.inverse();
            }
        }
        result
    }
}
```

#### Task 3.4: Implement Trusted Dealer Keygen
```rust
impl ThresholdBlsEngine {
    pub fn trusted_dealer_keygen(
        config: ThresholdConfig,
    ) -> Result<(GroupPublicKey, Vec<BlsKeyShare>), ThresholdError> {
        // 1. Generate master secret key
        let master_sk = SecretKey::random(&mut OsRng);
        let master_pk = master_sk.sk_to_pk();

        // 2. Split into shares
        let secret_shares = Self::split_secret_bls(
            &master_sk, config.threshold, config.total_participants
        )?;

        // 3. Create key share objects
        let key_shares = secret_shares.iter().enumerate().map(|(i, sk)| {
            let pk = sk.sk_to_pk();
            BlsKeyShare {
                participant_id: ParticipantId::new((i + 1) as u16).unwrap(),
                secret_share_bytes: sk.to_bytes().to_vec(),
                public_share: pk.compress().to_vec(),
                group_public_key: master_pk.compress().to_vec(),
            }
        }).collect();

        // 4. Zeroize master secret
        drop(master_sk);  // SecretKey should zeroize on drop

        Ok((GroupPublicKey::new(master_pk.compress().to_vec()), key_shares))
    }
}
```

#### Task 3.5: Implement Single-Round Signing
```rust
impl ThresholdBlsEngine {
    pub fn sign_share(
        key_share: &BlsKeyShare,
        message: &[u8],
    ) -> Result<BlsSignatureShare, ThresholdError> {
        let sk = key_share.secret_key()?;

        // BLS sign: σ_i = sk_i * H(m)
        let sig = sk.sign(message, DST, &[]);

        Ok(BlsSignatureShare {
            participant_id: key_share.participant_id,
            share: sig.compress().to_vec(),
        })
    }

    pub fn aggregate(
        signature_shares: &[BlsSignatureShare],
        participants: &[ParticipantId],
    ) -> Result<ThresholdSignature, ThresholdError> {
        if signature_shares.len() < 2 {
            return Err(ThresholdError::InsufficientParticipants {
                required: 2,
                provided: signature_shares.len(),
            });
        }

        // Compute Lagrange coefficients and aggregate
        let mut agg_sig = Signature::default();

        for share in signature_shares {
            let sig = Signature::uncompress(&share.share)?;
            let lambda = Self::lagrange_coefficient_bls(share.participant_id, participants);

            // σ = Σ λ_i * σ_i
            agg_sig = agg_sig + sig.multiply(&lambda);
        }

        Ok(ThresholdSignature {
            bytes: agg_sig.compress().to_vec(),
            scheme: ThresholdScheme::ThresholdBls12381,
        })
    }
}
```

#### Task 3.6: Implement Verification
```rust
impl ThresholdBlsEngine {
    pub fn verify(
        public_key: &GroupPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        let pk = PublicKey::uncompress(&public_key.bytes)
            .map_err(|_| ThresholdError::InvalidPublicKey)?;
        let sig = Signature::uncompress(&signature.bytes)
            .map_err(|_| ThresholdError::InvalidSignature)?;

        // BLS verify: e(pk, H(m)) == e(G1, sig)
        let result = sig.verify(true, message, DST, &[], &pk, true);

        Ok(result == BLST_ERROR::BLST_SUCCESS)
    }
}
```

#### Task 3.7: Add Unit Tests
```rust
#[cfg(test)]
mod tests {
    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    #[test]
    fn test_bls_2_of_3() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

        let message = b"test message for BLS";

        // Sign with participants 1 and 2
        let share1 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
        let share2 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();

        // Aggregate
        let sig = ThresholdBlsEngine::aggregate(
            &[share1, share2],
            &[ParticipantId(1), ParticipantId(2)],
        ).unwrap();

        // Verify
        assert!(ThresholdBlsEngine::verify(&group_key, message, &sig).unwrap());
    }

    #[test]
    fn test_bls_3_of_5() {
        // Test with different threshold
    }

    #[test]
    fn test_bls_wrong_message() {
        // Verify wrong message fails
    }

    #[test]
    fn test_bls_signature_aggregation() {
        // Test multi-signature aggregation
    }
}
```

### Success Criteria
- [ ] 2-of-3 BLS signing works
- [ ] 3-of-5 BLS signing works
- [ ] Signatures verify with standard BLS verifier
- [ ] Multi-signature aggregation works
- [ ] Single-round protocol (no commitments needed)
- [ ] All key material zeroized on drop

---

## Workstream 4: FIPS Compliance Extensions

**Owner**: Agent 4
**Estimated Tasks**: 6
**Dependencies**: WS1 (Types)
**Parallel With**: WS2 (ECDSA), WS3 (BLS)

### Files to Modify

| File | Action | Description |
|------|--------|-------------|
| `fips/algorithms.rs` | Modify | Add threshold algorithm registry |
| `fips/self_test.rs` | Modify | Add threshold KATs |
| `fips/audit.rs` | Modify | Add threshold audit events |
| `fips/mode.rs` | Modify | Threshold operation enforcement |

### Tasks

#### Task 4.1: Register Threshold Algorithms
```rust
// fips/algorithms.rs - Add to ApprovedAlgorithms

impl ApprovedAlgorithms {
    fn init_threshold_algorithms(&mut self) {
        // NIST SP 800-186 approved threshold schemes

        // Threshold ECDSA (NIST curves only - not secp256k1!)
        self.approved.insert(Algorithm::ThresholdEcdsaP256);
        self.approved.insert(Algorithm::ThresholdEcdsaP384);

        // Note: secp256k1 is NOT FIPS approved
        self.non_approved.insert(Algorithm::ThresholdEcdsaSecp256k1);

        // BLS is under evaluation (not yet approved)
        self.under_evaluation.insert(Algorithm::ThresholdBls12381);

        // FROST Ed25519 - Ed25519 is FIPS approved
        self.approved.insert(Algorithm::FrostEd25519);
    }
}

pub enum Algorithm {
    // ... existing ...
    ThresholdEcdsaP256,
    ThresholdEcdsaP384,
    ThresholdEcdsaSecp256k1,  // Non-approved
    ThresholdBls12381,        // Under evaluation
    FrostEd25519,
}
```

#### Task 4.2: Add Threshold Self-Tests (KAT)
```rust
// fips/self_test.rs

impl SelfTestRunner {
    fn run_threshold_tests(&self) -> Vec<TestResult> {
        vec![
            self.test_frost_ed25519_kat(),
            self.test_threshold_ecdsa_p256_kat(),
            // BLS not included (not FIPS approved)
        ]
    }

    fn test_frost_ed25519_kat(&self) -> TestResult {
        // Known answer test for FROST Ed25519
        // Use pre-computed shares and expected signature
        let known_shares = [...];  // Pre-computed
        let known_message = b"FIPS KAT test message";
        let expected_signature = [...];  // Pre-computed

        let sig = FrostEngine::sign_with_shares(&known_shares, known_message)?;

        if sig.bytes == expected_signature {
            TestResult::passed("frost_ed25519_kat")
        } else {
            TestResult::failed("frost_ed25519_kat", "Signature mismatch")
        }
    }

    fn test_threshold_ecdsa_p256_kat(&self) -> TestResult {
        // Known answer test for Threshold ECDSA P-256
        let known_shares = [...];
        let known_message_hash = [...];
        let expected_signature = [...];

        let sig = ThresholdEcdsaEngine::sign_with_shares(
            &known_shares, &known_message_hash, EcdsaCurve::P256
        )?;

        // Verify DER encoding matches
        if verify_ecdsa_signature(&sig, &expected_signature) {
            TestResult::passed("threshold_ecdsa_p256_kat")
        } else {
            TestResult::failed("threshold_ecdsa_p256_kat", "Signature mismatch")
        }
    }
}
```

#### Task 4.3: Add Threshold Audit Events
```rust
// fips/audit.rs

pub enum FipsAuditEventType {
    // ... existing ...

    // Threshold operations
    ThresholdKeyGeneration,
    ThresholdDkgRound1,
    ThresholdDkgRound2,
    ThresholdDkgComplete,
    ThresholdSigningSessionStart,
    ThresholdCommitmentGenerated,
    ThresholdSignatureShareGenerated,
    ThresholdSignatureAggregated,
    ThresholdKeyRefresh,
    ThresholdResharing,

    // Threshold errors
    ThresholdInsufficientParticipants,
    ThresholdInvalidShare,
    ThresholdSessionTimeout,
    ThresholdNonApprovedScheme,
}

impl FipsAuditLog {
    pub fn log_threshold_keygen(
        &self,
        scheme: ThresholdScheme,
        threshold: u16,
        total: u16,
        success: bool,
    ) {
        self.log(FipsAuditEvent {
            timestamp: Utc::now(),
            event_type: FipsAuditEventType::ThresholdKeyGeneration,
            success,
            details: Some(format!(
                "scheme={:?}, threshold={}-of-{}",
                scheme, threshold, total
            )),
        });
    }

    pub fn log_threshold_signing(
        &self,
        scheme: ThresholdScheme,
        session_id: &SessionId,
        participants: &[ParticipantId],
        success: bool,
    ) {
        self.log(FipsAuditEvent {
            timestamp: Utc::now(),
            event_type: FipsAuditEventType::ThresholdSignatureAggregated,
            success,
            details: Some(format!(
                "scheme={:?}, session={}, participants={:?}",
                scheme, session_id, participants
            )),
        });
    }
}
```

#### Task 4.4: Add FIPS Mode Enforcement for Threshold
```rust
// fips/mode.rs

impl FipsMode {
    pub fn require_approved_threshold(
        scheme: ThresholdScheme,
    ) -> Result<(), FipsError> {
        if !Self::is_enabled() {
            return Ok(());
        }

        let algorithm = match scheme {
            ThresholdScheme::FrostEd25519 => Algorithm::FrostEd25519,
            ThresholdScheme::ThresholdEcdsaP256 => Algorithm::ThresholdEcdsaP256,
            ThresholdScheme::ThresholdEcdsaSecp256k1 => {
                // secp256k1 is NOT FIPS approved
                return Err(FipsError::AlgorithmNotApproved(
                    "ThresholdEcdsaSecp256k1 is not FIPS approved".into()
                ));
            }
            ThresholdScheme::ThresholdBls12381 => {
                // BLS is under evaluation
                return Err(FipsError::AlgorithmUnderEvaluation(
                    "ThresholdBls12381 is under NIST evaluation".into()
                ));
            }
        };

        Self::require_approved(algorithm)
    }

    pub fn validate_threshold_config(
        config: &ThresholdConfig,
    ) -> Result<(), FipsError> {
        // FIPS requires minimum threshold of 2
        if config.threshold < 2 {
            return Err(FipsError::InvalidParameter(
                "FIPS requires minimum threshold of 2".into()
            ));
        }

        // FIPS requires threshold <= total/2 + 1 for Byzantine tolerance
        if config.threshold > config.total_participants / 2 + 1 {
            // This is a warning, not an error
            log::warn!("Threshold {} of {} may not provide Byzantine fault tolerance",
                config.threshold, config.total_participants);
        }

        Ok(())
    }
}
```

#### Task 4.5: Add Conditional Self-Tests for Threshold
```rust
// fips/self_test.rs

impl SelfTestRunner {
    pub fn conditional_test_threshold(
        operation: ThresholdOperation,
    ) -> Result<(), FipsError> {
        if !FipsMode::is_enabled() {
            return Ok(());
        }

        match operation {
            ThresholdOperation::KeyGeneration(scheme) => {
                // Run keygen self-test
                Self::verify_keygen_integrity(scheme)?;
            }
            ThresholdOperation::Signing(scheme) => {
                // Run signing self-test
                Self::verify_signing_integrity(scheme)?;
            }
            ThresholdOperation::DkgRound(round) => {
                // Verify DKG round integrity
                Self::verify_dkg_round_integrity(round)?;
            }
        }

        Ok(())
    }

    fn verify_keygen_integrity(scheme: ThresholdScheme) -> Result<(), FipsError> {
        // Verify that generated shares reconstruct to original secret
        // This is a pairwise consistency test
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (pk, shares) = match scheme {
            ThresholdScheme::FrostEd25519 => {
                FrostEngine::trusted_dealer_keygen(config)?
            }
            ThresholdScheme::ThresholdEcdsaP256 => {
                ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256)?
            }
            _ => return Ok(()),  // Skip non-approved schemes
        };

        // Verify public key derivation is consistent
        // ... verification logic ...

        Ok(())
    }
}
```

#### Task 4.6: Add Threshold Tests
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_fips_threshold_algorithm_approval() {
        FipsMode::initialize().unwrap();

        // FROST Ed25519 should be approved
        assert!(FipsMode::is_approved(Algorithm::FrostEd25519));

        // Threshold ECDSA P-256 should be approved
        assert!(FipsMode::is_approved(Algorithm::ThresholdEcdsaP256));

        // secp256k1 should NOT be approved
        assert!(!FipsMode::is_approved(Algorithm::ThresholdEcdsaSecp256k1));

        // BLS should be under evaluation
        assert!(ApprovedAlgorithms::is_under_evaluation(Algorithm::ThresholdBls12381));
    }

    #[test]
    fn test_fips_threshold_self_tests() {
        let runner = SelfTestRunner::new();
        let results = runner.run_threshold_tests();

        assert!(results.iter().all(|r| r.status == SelfTestStatus::Passed));
    }
}
```

### Success Criteria
- [ ] P-256 threshold ECDSA is FIPS approved
- [ ] secp256k1 threshold ECDSA is blocked in FIPS mode
- [ ] BLS is marked "under evaluation"
- [ ] Threshold KATs pass during POST
- [ ] All threshold operations are audited
- [ ] Conditional self-tests run before operations

---

## Workstream 5: ECDSA Distributed Key Generation

**Owner**: Agent 5
**Estimated Tasks**: 6
**Dependencies**: WS2 (ECDSA Engine)
**Parallel With**: WS6 (BLS DKG)

### Files to Create

| File | Lines Est. | Description |
|------|------------|-------------|
| `threshold/ecdsa/dkg.rs` | 400 | ECDSA DKG protocol |
| `threshold/ecdsa/feldman.rs` | 200 | Feldman VSS for verification |

### Tasks

#### Task 5.1: Define DKG Types
```rust
// threshold/ecdsa/dkg.rs
pub struct EcdsaDkg {
    config: DkgConfig,
    participant_id: ParticipantId,
    curve: EcdsaCurve,
    state: EcdsaDkgState,

    // Round 1 data
    secret_polynomial: Option<Vec<Scalar>>,
    commitments: Option<Vec<ProjectivePoint>>,

    // Round 2 data
    received_shares: HashMap<ParticipantId, Scalar>,
    received_commitments: HashMap<ParticipantId, Vec<ProjectivePoint>>,

    // Result
    key_share: Option<EcdsaKeyShare>,
}

pub enum EcdsaDkgState {
    NotStarted,
    Round1Complete,
    Round2Complete,
    Complete,
    Failed(String),
}

pub struct EcdsaDkgRound1Package {
    pub sender: ParticipantId,
    pub commitments: Vec<Vec<u8>>,  // Feldman commitments (public)
}

pub struct EcdsaDkgRound2Package {
    pub sender: ParticipantId,
    pub receiver: ParticipantId,
    pub encrypted_share: Vec<u8>,  // Encrypted secret share
}
```

#### Task 5.2: Implement Feldman VSS
```rust
// threshold/ecdsa/feldman.rs
pub struct FeldmanVss;

impl FeldmanVss {
    /// Generate Feldman commitments for polynomial coefficients
    pub fn generate_commitments(
        coefficients: &[Scalar],
        curve: EcdsaCurve,
    ) -> Vec<ProjectivePoint> {
        // C_i = g^{a_i} for each coefficient a_i
        coefficients.iter().map(|coef| {
            match curve {
                EcdsaCurve::P256 => p256::ProjectivePoint::GENERATOR * coef,
                EcdsaCurve::Secp256k1 => k256::ProjectivePoint::GENERATOR * coef,
            }
        }).collect()
    }

    /// Verify a share against Feldman commitments
    pub fn verify_share(
        participant_id: ParticipantId,
        share: &Scalar,
        commitments: &[ProjectivePoint],
        curve: EcdsaCurve,
    ) -> bool {
        // Verify: g^{share} == Π C_i^{x^i} where x = participant_id
        let x = Scalar::from(participant_id.0 as u64);

        let mut expected = ProjectivePoint::IDENTITY;
        let mut x_power = Scalar::ONE;

        for commitment in commitments {
            expected = expected + commitment * x_power;
            x_power = x_power * x;
        }

        let actual = ProjectivePoint::GENERATOR * share;
        actual == expected
    }
}
```

#### Task 5.3: Implement Round 1
```rust
impl EcdsaDkg {
    pub fn new(config: DkgConfig, participant_id: ParticipantId, curve: EcdsaCurve) -> Self {
        Self {
            config,
            participant_id,
            curve,
            state: EcdsaDkgState::NotStarted,
            secret_polynomial: None,
            commitments: None,
            received_shares: HashMap::new(),
            received_commitments: HashMap::new(),
            key_share: None,
        }
    }

    pub fn round1(&mut self) -> Result<EcdsaDkgRound1Package, ThresholdError> {
        if self.state != EcdsaDkgState::NotStarted {
            return Err(ThresholdError::DkgInvalidState);
        }

        // Generate random polynomial of degree (threshold - 1)
        let mut coefficients = Vec::with_capacity(self.config.threshold as usize);
        for _ in 0..self.config.threshold {
            coefficients.push(Scalar::random(&mut OsRng));
        }

        // Generate Feldman commitments
        let commitments = FeldmanVss::generate_commitments(&coefficients, self.curve);

        self.secret_polynomial = Some(coefficients);
        self.commitments = Some(commitments.clone());
        self.state = EcdsaDkgState::Round1Complete;

        Ok(EcdsaDkgRound1Package {
            sender: self.participant_id,
            commitments: commitments.iter().map(|c| c.to_bytes().to_vec()).collect(),
        })
    }
}
```

#### Task 5.4: Implement Round 2
```rust
impl EcdsaDkg {
    pub fn round2(
        &mut self,
        round1_packages: Vec<EcdsaDkgRound1Package>,
    ) -> Result<Vec<EcdsaDkgRound2Package>, ThresholdError> {
        if self.state != EcdsaDkgState::Round1Complete {
            return Err(ThresholdError::DkgInvalidState);
        }

        // Store received commitments
        for package in &round1_packages {
            let commitments: Vec<ProjectivePoint> = package.commitments.iter()
                .map(|c| ProjectivePoint::from_bytes(c))
                .collect::<Result<_, _>>()?;
            self.received_commitments.insert(package.sender, commitments);
        }

        // Generate shares for each participant
        let polynomial = self.secret_polynomial.as_ref().unwrap();
        let mut packages = Vec::new();

        for &receiver in &self.config.participants {
            if receiver == self.participant_id {
                continue;  // Don't send to self
            }

            // Evaluate polynomial at receiver's x-coordinate
            let x = Scalar::from(receiver.0 as u64);
            let share = evaluate_polynomial(polynomial, &x);

            // Encrypt share for receiver (using receiver's DH public key)
            let encrypted_share = self.encrypt_share_for(&share, receiver)?;

            packages.push(EcdsaDkgRound2Package {
                sender: self.participant_id,
                receiver,
                encrypted_share,
            });
        }

        self.state = EcdsaDkgState::Round2Complete;
        Ok(packages)
    }
}
```

#### Task 5.5: Implement Finalization
```rust
impl EcdsaDkg {
    pub fn finalize(
        &mut self,
        round2_packages: Vec<EcdsaDkgRound2Package>,
    ) -> Result<(EcdsaKeyShare, GroupPublicKey), ThresholdError> {
        if self.state != EcdsaDkgState::Round2Complete {
            return Err(ThresholdError::DkgInvalidState);
        }

        // Decrypt and verify received shares
        for package in round2_packages {
            if package.receiver != self.participant_id {
                continue;
            }

            let share = self.decrypt_share(&package.encrypted_share)?;

            // Verify share against sender's commitments
            let sender_commitments = self.received_commitments.get(&package.sender)
                .ok_or(ThresholdError::DkgMissingCommitments)?;

            if !FeldmanVss::verify_share(self.participant_id, &share, sender_commitments, self.curve) {
                return Err(ThresholdError::DkgInvalidShare(package.sender));
            }

            self.received_shares.insert(package.sender, share);
        }

        // Compute final secret share: sum of all received shares
        let my_polynomial = self.secret_polynomial.as_ref().unwrap();
        let x = Scalar::from(self.participant_id.0 as u64);
        let my_share = evaluate_polynomial(my_polynomial, &x);

        let mut final_share = my_share;
        for share in self.received_shares.values() {
            final_share = final_share + share;
        }

        // Compute group public key: sum of all constant terms
        let mut group_public = self.commitments.as_ref().unwrap()[0];
        for commitments in self.received_commitments.values() {
            group_public = group_public + commitments[0];
        }

        let key_share = EcdsaKeyShare {
            participant_id: self.participant_id,
            secret_share: final_share.to_bytes().to_vec(),
            public_share: (ProjectivePoint::GENERATOR * final_share).to_bytes().to_vec(),
            group_public_key: group_public.to_bytes().to_vec(),
            curve: self.curve,
        };

        self.key_share = Some(key_share.clone());
        self.state = EcdsaDkgState::Complete;

        Ok((key_share, GroupPublicKey::new(group_public.to_bytes().to_vec())))
    }
}
```

#### Task 5.6: Add DKG Tests
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_ecdsa_dkg_2_of_3_p256() {
        let config = DkgConfig {
            scheme: ThresholdScheme::ThresholdEcdsaP256,
            threshold: 2,
            participants: vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)],
            round_timeout: Duration::from_secs(30),
        };

        // Create DKG instances
        let mut dkg1 = EcdsaDkg::new(config.clone(), ParticipantId(1), EcdsaCurve::P256);
        let mut dkg2 = EcdsaDkg::new(config.clone(), ParticipantId(2), EcdsaCurve::P256);
        let mut dkg3 = EcdsaDkg::new(config.clone(), ParticipantId(3), EcdsaCurve::P256);

        // Round 1
        let r1_pkg1 = dkg1.round1().unwrap();
        let r1_pkg2 = dkg2.round1().unwrap();
        let r1_pkg3 = dkg3.round1().unwrap();

        // Round 2
        let r2_pkgs1 = dkg1.round2(vec![r1_pkg1.clone(), r1_pkg2.clone(), r1_pkg3.clone()]).unwrap();
        let r2_pkgs2 = dkg2.round2(vec![r1_pkg1.clone(), r1_pkg2.clone(), r1_pkg3.clone()]).unwrap();
        let r2_pkgs3 = dkg3.round2(vec![r1_pkg1.clone(), r1_pkg2.clone(), r1_pkg3.clone()]).unwrap();

        // Combine round 2 packages
        let all_r2_pkgs: Vec<_> = r2_pkgs1.into_iter()
            .chain(r2_pkgs2)
            .chain(r2_pkgs3)
            .collect();

        // Finalize
        let (share1, pk1) = dkg1.finalize(all_r2_pkgs.clone()).unwrap();
        let (share2, pk2) = dkg2.finalize(all_r2_pkgs.clone()).unwrap();
        let (share3, pk3) = dkg3.finalize(all_r2_pkgs).unwrap();

        // All should have same group public key
        assert_eq!(pk1.bytes, pk2.bytes);
        assert_eq!(pk2.bytes, pk3.bytes);

        // Test signing with generated shares
        let msg = b"test message";
        let sig = ThresholdEcdsaEngine::sign_2_of_3(&[share1, share2], msg, EcdsaCurve::P256).unwrap();
        assert!(ThresholdEcdsaEngine::verify(&pk1, msg, &sig, EcdsaCurve::P256).unwrap());
    }
}
```

### Success Criteria
- [ ] 3-round DKG completes successfully
- [ ] Feldman VSS verification catches invalid shares
- [ ] Generated shares can sign valid signatures
- [ ] All participants derive same group public key
- [ ] Encrypted share transport is secure

---

## Workstream 6: BLS Distributed Key Generation

**Owner**: Agent 6
**Estimated Tasks**: 5
**Dependencies**: WS3 (BLS Engine)
**Parallel With**: WS5 (ECDSA DKG)

### Files to Create

| File | Lines Est. | Description |
|------|------------|-------------|
| `threshold/bls/dkg.rs` | 350 | BLS DKG protocol |

### Tasks

#### Task 6.1: Define BLS DKG Types
```rust
// threshold/bls/dkg.rs
use blst::min_pk::*;

pub struct BlsDkg {
    config: DkgConfig,
    participant_id: ParticipantId,
    state: BlsDkgState,

    // Round 1
    secret_polynomial: Option<Vec<blst_scalar>>,
    commitments: Option<Vec<PublicKey>>,  // g1^{a_i}

    // Round 2
    received_shares: HashMap<ParticipantId, blst_scalar>,
    received_commitments: HashMap<ParticipantId, Vec<PublicKey>>,

    // Result
    key_share: Option<BlsKeyShare>,
}

pub struct BlsDkgRound1Package {
    pub sender: ParticipantId,
    pub commitments: Vec<Vec<u8>>,  // Compressed G1 points
}

pub struct BlsDkgRound2Package {
    pub sender: ParticipantId,
    pub receiver: ParticipantId,
    pub encrypted_share: Vec<u8>,
}
```

#### Task 6.2: Implement Round 1
```rust
impl BlsDkg {
    pub fn round1(&mut self) -> Result<BlsDkgRound1Package, ThresholdError> {
        // Generate random polynomial
        let mut coefficients = Vec::new();
        for _ in 0..self.config.threshold {
            let sk = SecretKey::random(&mut OsRng);
            coefficients.push(sk.to_scalar());
        }

        // Generate commitments: C_i = g1^{a_i}
        let commitments: Vec<PublicKey> = coefficients.iter()
            .map(|c| PublicKey::from_scalar(c))
            .collect();

        self.secret_polynomial = Some(coefficients);
        self.commitments = Some(commitments.clone());
        self.state = BlsDkgState::Round1Complete;

        Ok(BlsDkgRound1Package {
            sender: self.participant_id,
            commitments: commitments.iter().map(|c| c.compress().to_vec()).collect(),
        })
    }
}
```

#### Task 6.3: Implement Round 2
```rust
impl BlsDkg {
    pub fn round2(
        &mut self,
        round1_packages: Vec<BlsDkgRound1Package>,
    ) -> Result<Vec<BlsDkgRound2Package>, ThresholdError> {
        // Store commitments
        for package in &round1_packages {
            let commitments: Vec<PublicKey> = package.commitments.iter()
                .map(|c| PublicKey::uncompress(c))
                .collect::<Result<_, _>>()?;
            self.received_commitments.insert(package.sender, commitments);
        }

        // Generate shares for each participant
        let polynomial = self.secret_polynomial.as_ref().unwrap();
        let mut packages = Vec::new();

        for &receiver in &self.config.participants {
            if receiver == self.participant_id {
                continue;
            }

            let x = blst_scalar::from(receiver.0 as u64);
            let share = evaluate_polynomial_bls(polynomial, &x);
            let encrypted = self.encrypt_share_for(&share, receiver)?;

            packages.push(BlsDkgRound2Package {
                sender: self.participant_id,
                receiver,
                encrypted_share: encrypted,
            });
        }

        self.state = BlsDkgState::Round2Complete;
        Ok(packages)
    }
}
```

#### Task 6.4: Implement Finalization
```rust
impl BlsDkg {
    pub fn finalize(
        &mut self,
        round2_packages: Vec<BlsDkgRound2Package>,
    ) -> Result<(BlsKeyShare, GroupPublicKey), ThresholdError> {
        // Decrypt and verify shares
        for package in round2_packages {
            if package.receiver != self.participant_id {
                continue;
            }

            let share = self.decrypt_share(&package.encrypted_share)?;

            // Verify against commitments
            let sender_commitments = self.received_commitments.get(&package.sender)
                .ok_or(ThresholdError::DkgMissingCommitments)?;

            if !self.verify_bls_share(&share, sender_commitments) {
                return Err(ThresholdError::DkgInvalidShare(package.sender));
            }

            self.received_shares.insert(package.sender, share);
        }

        // Sum all shares
        let polynomial = self.secret_polynomial.as_ref().unwrap();
        let x = blst_scalar::from(self.participant_id.0 as u64);
        let mut final_share = evaluate_polynomial_bls(polynomial, &x);

        for share in self.received_shares.values() {
            final_share = final_share + share;
        }

        // Compute group public key
        let mut group_public = self.commitments.as_ref().unwrap()[0];
        for commitments in self.received_commitments.values() {
            group_public = group_public + commitments[0];
        }

        let sk = SecretKey::from_scalar(&final_share);
        let key_share = BlsKeyShare {
            participant_id: self.participant_id,
            secret_share_bytes: sk.to_bytes().to_vec(),
            public_share: sk.sk_to_pk().compress().to_vec(),
            group_public_key: group_public.compress().to_vec(),
        };

        self.state = BlsDkgState::Complete;
        Ok((key_share, GroupPublicKey::new(group_public.compress().to_vec())))
    }
}
```

#### Task 6.5: Add BLS DKG Tests
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_bls_dkg_3_of_5() {
        let participants: Vec<ParticipantId> = (1..=5).map(|i| ParticipantId(i)).collect();
        let config = DkgConfig {
            scheme: ThresholdScheme::ThresholdBls12381,
            threshold: 3,
            participants: participants.clone(),
            round_timeout: Duration::from_secs(30),
        };

        // Create DKG instances
        let mut dkgs: Vec<BlsDkg> = participants.iter()
            .map(|&p| BlsDkg::new(config.clone(), p))
            .collect();

        // Round 1
        let r1_packages: Vec<_> = dkgs.iter_mut()
            .map(|dkg| dkg.round1().unwrap())
            .collect();

        // Round 2
        let mut all_r2_packages = Vec::new();
        for dkg in &mut dkgs {
            let pkgs = dkg.round2(r1_packages.clone()).unwrap();
            all_r2_packages.extend(pkgs);
        }

        // Finalize
        let results: Vec<_> = dkgs.iter_mut()
            .map(|dkg| dkg.finalize(all_r2_packages.clone()).unwrap())
            .collect();

        // Verify all have same group public key
        let group_pk = &results[0].1;
        for (_, pk) in &results {
            assert_eq!(pk.bytes, group_pk.bytes);
        }

        // Test signing
        let shares: Vec<_> = results.iter().map(|(s, _)| s.clone()).collect();
        let msg = b"BLS DKG test";

        let sig = ThresholdBlsEngine::sign_3_of_5(&shares[0..3], msg).unwrap();
        assert!(ThresholdBlsEngine::verify(group_pk, msg, &sig).unwrap());
    }
}
```

### Success Criteria
- [ ] 3-round DKG completes for BLS
- [ ] Share verification catches invalid shares
- [ ] All participants derive same group public key
- [ ] Generated shares produce valid BLS signatures
- [ ] Works for various threshold configurations

---

## Workstream 7: Key Refresh & Resharing

**Owner**: Agent 7
**Estimated Tasks**: 7
**Dependencies**: WS5 (ECDSA DKG), WS6 (BLS DKG)
**Parallel With**: None (depends on DKG)

### Files to Create

| File | Lines Est. | Description |
|------|------------|-------------|
| `threshold/refresh/mod.rs` | 50 | Module exports |
| `threshold/refresh/protocol.rs` | 400 | Key refresh protocol |
| `threshold/refresh/resharing.rs` | 350 | Dynamic resharing |

### Tasks

#### Task 7.1: Define Refresh Types
```rust
// threshold/refresh/mod.rs
pub struct KeyRefreshProtocol {
    config: KeyRefreshConfig,
    scheme: ThresholdScheme,
    state: RefreshState,

    // Participants contribute zero-sum shares
    refresh_shares: HashMap<ParticipantId, Vec<u8>>,
    commitments: HashMap<ParticipantId, Vec<Vec<u8>>>,
}

pub enum RefreshState {
    NotStarted,
    Round1Complete,
    Round2Complete,
    Complete,
    Failed(String),
}

pub struct RefreshRound1Package {
    pub sender: ParticipantId,
    pub commitments: Vec<Vec<u8>>,  // Commitments to zero polynomial
}

pub struct RefreshRound2Package {
    pub sender: ParticipantId,
    pub receiver: ParticipantId,
    pub refresh_share: Vec<u8>,
}
```

#### Task 7.2: Implement Key Refresh Protocol
```rust
// threshold/refresh/protocol.rs

impl KeyRefreshProtocol {
    /// Key refresh without changing public key
    ///
    /// Each participant generates a random polynomial with zero constant term
    /// and distributes shares to all participants. After aggregation,
    /// each participant's share is updated but the group key remains the same.
    pub fn new(config: KeyRefreshConfig, scheme: ThresholdScheme) -> Self {
        Self {
            config,
            scheme,
            state: RefreshState::NotStarted,
            refresh_shares: HashMap::new(),
            commitments: HashMap::new(),
        }
    }

    pub fn round1(&mut self, participant_id: ParticipantId) -> Result<RefreshRound1Package, ThresholdError> {
        // Generate polynomial with zero constant term: f(x) = a_1*x + a_2*x^2 + ...
        let mut coefficients = vec![Scalar::ZERO];  // a_0 = 0
        for _ in 1..self.config.new_threshold {
            coefficients.push(Scalar::random(&mut OsRng));
        }

        // Generate Feldman commitments
        let commitments = FeldmanVss::generate_commitments(&coefficients, self.scheme);

        // Verify first commitment is identity (since a_0 = 0)
        assert_eq!(commitments[0], ProjectivePoint::IDENTITY);

        self.state = RefreshState::Round1Complete;

        Ok(RefreshRound1Package {
            sender: participant_id,
            commitments: commitments.iter().map(|c| c.to_bytes().to_vec()).collect(),
        })
    }

    pub fn round2(
        &mut self,
        participant_id: ParticipantId,
        round1_packages: Vec<RefreshRound1Package>,
    ) -> Result<Vec<RefreshRound2Package>, ThresholdError> {
        // Verify all commitments have identity as first element
        for package in &round1_packages {
            let first_commitment = ProjectivePoint::from_bytes(&package.commitments[0])?;
            if first_commitment != ProjectivePoint::IDENTITY {
                return Err(ThresholdError::KeyRefreshInvalidCommitment(package.sender));
            }
            self.commitments.insert(package.sender, package.commitments.clone());
        }

        // Generate refresh shares for each participant
        let polynomial = &self.config.polynomial;  // Zero-constant polynomial
        let mut packages = Vec::new();

        for &receiver in &self.config.participants {
            if receiver == participant_id {
                continue;
            }

            let x = Scalar::from(receiver.0 as u64);
            let share = evaluate_polynomial(polynomial, &x);
            let encrypted = encrypt_share(&share, receiver)?;

            packages.push(RefreshRound2Package {
                sender: participant_id,
                receiver,
                refresh_share: encrypted,
            });
        }

        self.state = RefreshState::Round2Complete;
        Ok(packages)
    }

    pub fn finalize(
        &mut self,
        participant_id: ParticipantId,
        old_share: &KeyShare,
        round2_packages: Vec<RefreshRound2Package>,
    ) -> Result<KeyShare, ThresholdError> {
        // Collect refresh shares for this participant
        let mut total_refresh = Scalar::ZERO;

        for package in round2_packages {
            if package.receiver != participant_id {
                continue;
            }

            let refresh_share = decrypt_share(&package.refresh_share)?;

            // Verify against commitments
            let sender_commitments = self.commitments.get(&package.sender)
                .ok_or(ThresholdError::KeyRefreshMissingCommitments)?;

            if !FeldmanVss::verify_share(participant_id, &refresh_share, sender_commitments, self.scheme) {
                return Err(ThresholdError::KeyRefreshInvalidShare(package.sender));
            }

            total_refresh = total_refresh + refresh_share;
        }

        // Add own refresh share
        let x = Scalar::from(participant_id.0 as u64);
        let own_refresh = evaluate_polynomial(&self.config.polynomial, &x);
        total_refresh = total_refresh + own_refresh;

        // New share = old share + total refresh
        let old_scalar = Scalar::from_bytes(&old_share.secret_share)?;
        let new_scalar = old_scalar + total_refresh;

        self.state = RefreshState::Complete;

        Ok(KeyShare {
            participant_id,
            secret_share: new_scalar.to_bytes().to_vec(),
            public_share: (ProjectivePoint::GENERATOR * new_scalar).to_bytes().to_vec(),
            group_public_key: old_share.group_public_key.clone(),  // Unchanged!
            scheme: old_share.scheme,
        })
    }
}
```

#### Task 7.3: Implement Dynamic Resharing
```rust
// threshold/refresh/resharing.rs

pub struct Resharing {
    old_config: ThresholdConfig,
    new_config: ThresholdConfig,
    scheme: ThresholdScheme,
    state: ResharingState,
}

impl Resharing {
    /// Reshare to a new set of participants (can add/remove participants)
    ///
    /// Old participants (at least t of them) collaborate to generate
    /// new shares for the new participant set, potentially with a new threshold.
    pub fn new(
        old_config: ThresholdConfig,
        new_config: ThresholdConfig,
        scheme: ThresholdScheme,
    ) -> Result<Self, ThresholdError> {
        // Validate: need at least old_threshold participants from old set
        if old_config.threshold > new_config.total_participants {
            return Err(ThresholdError::ResharingInvalidConfig(
                "Not enough new participants for old threshold".into()
            ));
        }

        Ok(Self {
            old_config,
            new_config,
            scheme,
            state: ResharingState::NotStarted,
        })
    }

    /// Each old participant runs this to generate shares for new participants
    pub fn generate_new_shares(
        &self,
        old_share: &KeyShare,
        new_participants: &[ParticipantId],
    ) -> Result<Vec<ResharingPackage>, ThresholdError> {
        // Old participant's share becomes constant term of their polynomial
        let old_scalar = Scalar::from_bytes(&old_share.secret_share)?;

        // Generate polynomial with old_share as constant term
        let mut coefficients = vec![old_scalar];
        for _ in 1..self.new_config.threshold {
            coefficients.push(Scalar::random(&mut OsRng));
        }

        // Generate commitments
        let commitments = FeldmanVss::generate_commitments(&coefficients, self.scheme);

        // Evaluate for each new participant
        let packages: Vec<_> = new_participants.iter().map(|&receiver| {
            let x = Scalar::from(receiver.0 as u64);
            let share = evaluate_polynomial(&coefficients, &x);

            ResharingPackage {
                old_participant: old_share.participant_id,
                new_participant: receiver,
                share: encrypt_share(&share, receiver)?,
                commitments: commitments.iter().map(|c| c.to_bytes().to_vec()).collect(),
            }
        }).collect::<Result<_, _>>()?;

        Ok(packages)
    }

    /// New participant collects shares from old participants and combines
    pub fn receive_shares(
        &self,
        new_participant_id: ParticipantId,
        packages: Vec<ResharingPackage>,
        old_participants: &[ParticipantId],  // Which old participants contributed
    ) -> Result<KeyShare, ThresholdError> {
        if packages.len() < self.old_config.threshold as usize {
            return Err(ThresholdError::ResharingInsufficientShares {
                required: self.old_config.threshold as usize,
                provided: packages.len(),
            });
        }

        // Verify and collect shares
        let mut shares_with_ids = Vec::new();

        for package in packages {
            if package.new_participant != new_participant_id {
                continue;
            }

            let share = decrypt_share(&package.share)?;

            // Verify against commitments
            if !FeldmanVss::verify_share(new_participant_id, &share, &package.commitments, self.scheme) {
                return Err(ThresholdError::ResharingInvalidShare(package.old_participant));
            }

            shares_with_ids.push((package.old_participant, share));
        }

        // Interpolate to get new share
        // new_share(x) = Σ λ_i * share_i where λ_i is Lagrange coefficient for old participant i
        let mut new_share = Scalar::ZERO;
        let old_participant_ids: Vec<_> = shares_with_ids.iter().map(|(id, _)| *id).collect();

        for (old_id, share) in &shares_with_ids {
            let lambda = lagrange_coefficient(*old_id, &old_participant_ids);
            new_share = new_share + lambda * share;
        }

        // Compute group public key by interpolating commitments
        // (Should match the original group public key)
        let group_public_key = self.interpolate_group_public_key(&packages, &old_participant_ids)?;

        Ok(KeyShare {
            participant_id: new_participant_id,
            secret_share: new_share.to_bytes().to_vec(),
            public_share: (ProjectivePoint::GENERATOR * new_share).to_bytes().to_vec(),
            group_public_key: group_public_key.to_bytes().to_vec(),
            scheme: self.scheme,
        })
    }
}
```

#### Task 7.4: Add Integration with ECDSA
```rust
// threshold/ecdsa/mod.rs - Add refresh support

impl ThresholdEcdsaEngine {
    pub fn refresh_shares(
        old_shares: &[EcdsaKeyShare],
        config: KeyRefreshConfig,
    ) -> Result<Vec<EcdsaKeyShare>, ThresholdError> {
        let protocol = KeyRefreshProtocol::new(config, ThresholdScheme::ThresholdEcdsaP256);

        // Simulate multi-party refresh
        // In practice, this would be distributed
        let new_shares = protocol.execute_refresh(old_shares)?;

        // Verify: new shares should produce same public key
        let old_pk = &old_shares[0].group_public_key;
        for share in &new_shares {
            assert_eq!(&share.group_public_key, old_pk);
        }

        Ok(new_shares)
    }
}
```

#### Task 7.5: Add Integration with BLS
```rust
// threshold/bls/mod.rs - Add refresh support

impl ThresholdBlsEngine {
    pub fn refresh_shares(
        old_shares: &[BlsKeyShare],
        config: KeyRefreshConfig,
    ) -> Result<Vec<BlsKeyShare>, ThresholdError> {
        let protocol = KeyRefreshProtocol::new(config, ThresholdScheme::ThresholdBls12381);
        let new_shares = protocol.execute_refresh(old_shares)?;
        Ok(new_shares)
    }

    pub fn reshare(
        old_shares: &[BlsKeyShare],
        old_config: ThresholdConfig,
        new_config: ThresholdConfig,
        new_participants: &[ParticipantId],
    ) -> Result<Vec<BlsKeyShare>, ThresholdError> {
        let resharing = Resharing::new(old_config, new_config, ThresholdScheme::ThresholdBls12381)?;
        resharing.execute(old_shares, new_participants)
    }
}
```

#### Task 7.6: Add Refresh Tests
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_key_refresh_preserves_public_key() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (original_pk, original_shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
            config.clone(), EcdsaCurve::P256
        ).unwrap();

        // Refresh shares
        let refresh_config = KeyRefreshConfig {
            scheme: ThresholdScheme::ThresholdEcdsaP256,
            old_threshold: 2,
            new_threshold: 2,
            participants_to_add: vec![],
            participants_to_remove: vec![],
        };

        let new_shares = ThresholdEcdsaEngine::refresh_shares(&original_shares, refresh_config).unwrap();

        // Verify public key unchanged
        assert_eq!(new_shares[0].group_public_key, original_pk.bytes);

        // Verify new shares are different
        for i in 0..3 {
            assert_ne!(new_shares[i].secret_share, original_shares[i].secret_share);
        }

        // Verify signing still works
        let msg = b"test after refresh";
        let sig = ThresholdEcdsaEngine::sign_2_of_3(&new_shares[0..2], msg, EcdsaCurve::P256).unwrap();
        assert!(ThresholdEcdsaEngine::verify(&original_pk, msg, &sig, EcdsaCurve::P256).unwrap());
    }

    #[test]
    fn test_resharing_2_of_3_to_3_of_5() {
        let old_config = ThresholdConfig::new(2, 3).unwrap();
        let (original_pk, original_shares) = ThresholdBlsEngine::trusted_dealer_keygen(old_config.clone()).unwrap();

        let new_config = ThresholdConfig::new(3, 5).unwrap();
        let new_participants: Vec<_> = (1..=5).map(|i| ParticipantId(i)).collect();

        let new_shares = ThresholdBlsEngine::reshare(
            &original_shares,
            old_config,
            new_config,
            &new_participants,
        ).unwrap();

        // Verify same public key
        assert_eq!(new_shares[0].group_public_key, original_pk.bytes);

        // Verify 3-of-5 signing works
        let msg = b"reshared signature";
        let sig = ThresholdBlsEngine::sign_3_of_5(&new_shares[0..3], msg).unwrap();
        assert!(ThresholdBlsEngine::verify(&original_pk, msg, &sig).unwrap());
    }
}
```

#### Task 7.7: Add FIPS Audit for Refresh
```rust
// fips/audit.rs - Add refresh events

impl FipsAuditLog {
    pub fn log_key_refresh(
        &self,
        scheme: ThresholdScheme,
        participants: &[ParticipantId],
        success: bool,
    ) {
        self.log(FipsAuditEvent {
            timestamp: Utc::now(),
            event_type: FipsAuditEventType::ThresholdKeyRefresh,
            success,
            details: Some(format!(
                "scheme={:?}, participants={:?}",
                scheme, participants
            )),
        });
    }

    pub fn log_resharing(
        &self,
        scheme: ThresholdScheme,
        old_threshold: u16,
        new_threshold: u16,
        success: bool,
    ) {
        self.log(FipsAuditEvent {
            timestamp: Utc::now(),
            event_type: FipsAuditEventType::ThresholdResharing,
            success,
            details: Some(format!(
                "scheme={:?}, {}→{} threshold",
                scheme, old_threshold, new_threshold
            )),
        });
    }
}
```

### Success Criteria
- [ ] Key refresh preserves group public key
- [ ] New shares are different from old shares
- [ ] Refreshed shares can sign valid signatures
- [ ] Resharing changes threshold successfully
- [ ] Resharing can add/remove participants
- [ ] All operations audited in FIPS mode

---

## Workstream 8: Tests & Benchmarks

**Owner**: Agent 8
**Estimated Tasks**: 8
**Dependencies**: All previous workstreams
**Parallel With**: None (final integration)

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `tests/threshold_integration.rs` | Create | Full integration tests |
| `tests/threshold_security.rs` | Create | Security-focused tests |
| `benches/threshold_benches.rs` | Create | Criterion benchmarks |
| `fuzz/threshold_ecdsa.rs` | Create | Fuzz targets |
| `fuzz/threshold_bls.rs` | Create | Fuzz targets |

### Tasks

#### Task 8.1: Integration Tests
```rust
// tests/threshold_integration.rs

#[test]
fn test_full_ecdsa_mpc_flow() {
    // 1. DKG
    // 2. Multiple signing sessions
    // 3. Key refresh
    // 4. More signing
    // 5. Resharing
    // 6. Final signing
}

#[test]
fn test_mixed_threshold_operations() {
    // Test ECDSA and BLS operations interleaved
}

#[test]
fn test_concurrent_signing_sessions() {
    // Multiple signing sessions in parallel
}
```

#### Task 8.2: Security Tests
```rust
// tests/threshold_security.rs

#[test]
fn test_invalid_share_detection() {
    // Submit corrupted share, verify rejection
}

#[test]
fn test_replay_attack_prevention() {
    // Try to reuse old commitments/nonces
}

#[test]
fn test_rogue_key_attack_prevention() {
    // Malicious key contribution in DKG
}

#[test]
fn test_key_material_zeroization() {
    // Verify sensitive data is zeroed
}
```

#### Task 8.3: Criterion Benchmarks
```rust
// benches/threshold_benches.rs

fn bench_threshold_ecdsa_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("threshold_ecdsa");

    for (t, n) in [(2, 3), (3, 5), (5, 10)] {
        group.bench_function(format!("{}_of_{}_keygen", t, n), |b| {
            b.iter(|| {
                let config = ThresholdConfig::new(t, n).unwrap();
                ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256)
            });
        });
    }

    group.finish();
}

fn bench_threshold_ecdsa_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("threshold_ecdsa_sign");

    let config = ThresholdConfig::new(2, 3).unwrap();
    let (pk, shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
        config, EcdsaCurve::P256
    ).unwrap();
    let msg = b"benchmark message";

    group.throughput(Throughput::Elements(1));
    group.bench_function("2_of_3_full_sign", |b| {
        b.iter(|| {
            ThresholdEcdsaEngine::sign_2_of_3(black_box(&shares[0..2]), black_box(msg), EcdsaCurve::P256)
        });
    });

    group.finish();
}

fn bench_threshold_bls(c: &mut Criterion) {
    // Similar for BLS
}

fn bench_key_refresh(c: &mut Criterion) {
    // Benchmark refresh operations
}

fn bench_dkg(c: &mut Criterion) {
    // Benchmark DKG rounds
}

criterion_group!(
    benches,
    bench_threshold_ecdsa_keygen,
    bench_threshold_ecdsa_sign,
    bench_threshold_bls,
    bench_key_refresh,
    bench_dkg
);
criterion_main!(benches);
```

#### Task 8.4: Fuzz Testing - ECDSA
```rust
// fuzz/fuzz_targets/threshold_ecdsa.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 { return; }

    // Fuzz signing with arbitrary data
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (pk, shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
        config, EcdsaCurve::P256
    ).unwrap();

    // Try signing arbitrary message
    let _ = ThresholdEcdsaEngine::sign_2_of_3(&shares[0..2], data, EcdsaCurve::P256);
});
```

#### Task 8.5: Fuzz Testing - BLS
```rust
// fuzz/fuzz_targets/threshold_bls.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 { return; }

    let config = ThresholdConfig::new(2, 3).unwrap();
    let (pk, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

    let _ = ThresholdBlsEngine::sign_2_of_3(&shares[0..2], data);
});
```

#### Task 8.6: Property-Based Tests
```rust
// tests/threshold_property.rs
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_ecdsa_any_threshold_subset_signs(
        threshold in 2u16..5,
        total in 3u16..10,
        subset_offset in 0u16..5,
    ) {
        prop_assume!(threshold <= total);
        prop_assume!(subset_offset + threshold <= total);

        let config = ThresholdConfig::new(threshold, total).unwrap();
        let (pk, shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
            config, EcdsaCurve::P256
        ).unwrap();

        let msg = b"property test";
        let subset: Vec<_> = shares[subset_offset as usize..(subset_offset + threshold) as usize].to_vec();

        let sig = ThresholdEcdsaEngine::sign_with_shares(&subset, msg, EcdsaCurve::P256).unwrap();
        prop_assert!(ThresholdEcdsaEngine::verify(&pk, msg, &sig, EcdsaCurve::P256).unwrap());
    }
}
```

#### Task 8.7: Performance Targets Verification
```rust
// tests/threshold_performance.rs

#[test]
fn test_ecdsa_keygen_performance() {
    let start = Instant::now();
    let iterations = 100;

    for _ in 0..iterations {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let _ = ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    // Target: >100 keygens/sec
    assert!(ops_per_sec > 100.0, "Keygen too slow: {} ops/sec", ops_per_sec);
}

#[test]
fn test_ecdsa_sign_performance() {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (_, shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
        config, EcdsaCurve::P256
    ).unwrap();

    let start = Instant::now();
    let iterations = 1000;
    let msg = b"perf test";

    for _ in 0..iterations {
        let _ = ThresholdEcdsaEngine::sign_2_of_3(&shares[0..2], msg, EcdsaCurve::P256).unwrap();
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    // Target: >500 signs/sec
    assert!(ops_per_sec > 500.0, "Signing too slow: {} ops/sec", ops_per_sec);
}
```

#### Task 8.8: FIPS Compliance Verification Tests
```rust
// tests/threshold_fips.rs

#[test]
fn test_fips_mode_blocks_secp256k1() {
    FipsMode::initialize().unwrap();

    let config = ThresholdConfig::new(2, 3).unwrap();
    let result = ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::Secp256k1);

    assert!(matches!(result, Err(ThresholdError::FipsNotApproved(_))));
}

#[test]
fn test_fips_self_tests_include_threshold() {
    let runner = SelfTestRunner::new();
    let results = runner.run_all_tests();

    // Verify threshold KATs are included
    let threshold_tests: Vec<_> = results.iter()
        .filter(|r| r.name.starts_with("threshold_") || r.name.starts_with("frost_"))
        .collect();

    assert!(!threshold_tests.is_empty(), "No threshold self-tests found");
    assert!(threshold_tests.iter().all(|t| t.status == SelfTestStatus::Passed));
}

#[test]
fn test_fips_audit_logs_threshold_operations() {
    FipsMode::initialize().unwrap();
    let audit = FipsAuditLog::global();

    let config = ThresholdConfig::new(2, 3).unwrap();
    let (pk, shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
        config, EcdsaCurve::P256
    ).unwrap();

    let events = audit.export_json();
    assert!(events.contains("ThresholdKeyGeneration"));
}
```

### Success Criteria
- [ ] All integration tests pass
- [ ] Security tests verify attack resistance
- [ ] Benchmarks show acceptable performance
- [ ] Fuzz tests run without crashes
- [ ] Property tests verify correctness
- [ ] Performance targets met
- [ ] FIPS compliance verified

---

## Execution Plan

### Phase 1: Foundation (Day 1)
```
┌─────────────────────────────────────────┐
│         WS1: Types & Infrastructure      │
│         (Single agent, blocking)         │
└─────────────────────────────────────────┘
```

**Commands:**
```bash
# Agent 1
cd /Users/bs/codes/hsm/crates/crypto-engine
# Implement WS1 tasks 1.1-1.6
cargo check && cargo test
```

### Phase 2: Parallel Engines (Days 2-3)
```
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  WS2: ECDSA │ │  WS3: BLS   │ │  WS4: FIPS  │
│   (Agent 2) │ │  (Agent 3)  │ │  (Agent 4)  │
└─────────────┘ └─────────────┘ └─────────────┘
```

**Commands:**
```bash
# Agent 2 (ECDSA)
cd /Users/bs/codes/hsm/crates/crypto-engine/src/threshold
# Implement WS2 tasks 2.1-2.8
cargo test threshold::ecdsa

# Agent 3 (BLS) - PARALLEL
cd /Users/bs/codes/hsm/crates/crypto-engine/src/threshold
# Implement WS3 tasks 3.1-3.7
cargo test threshold::bls

# Agent 4 (FIPS) - PARALLEL
cd /Users/bs/codes/hsm/crates/crypto-engine/src/fips
# Implement WS4 tasks 4.1-4.6
cargo test fips
```

### Phase 3: Parallel DKG (Days 4-5)
```
┌─────────────────┐ ┌─────────────────┐
│  WS5: ECDSA DKG │ │  WS6: BLS DKG   │
│    (Agent 5)    │ │   (Agent 6)     │
└─────────────────┘ └─────────────────┘
```

**Commands:**
```bash
# Agent 5 (ECDSA DKG)
cd /Users/bs/codes/hsm/crates/crypto-engine/src/threshold/ecdsa
# Implement WS5 tasks 5.1-5.6
cargo test threshold::ecdsa::dkg

# Agent 6 (BLS DKG) - PARALLEL
cd /Users/bs/codes/hsm/crates/crypto-engine/src/threshold/bls
# Implement WS6 tasks 6.1-6.5
cargo test threshold::bls::dkg
```

### Phase 4: Key Refresh (Day 6)
```
┌─────────────────────────────────────────┐
│          WS7: Key Refresh               │
│            (Agent 7)                    │
└─────────────────────────────────────────┘
```

**Commands:**
```bash
# Agent 7
cd /Users/bs/codes/hsm/crates/crypto-engine/src/threshold
# Implement WS7 tasks 7.1-7.7
cargo test threshold::refresh
```

### Phase 5: Integration (Day 7)
```
┌─────────────────────────────────────────┐
│       WS8: Tests & Benchmarks           │
│            (Agent 8)                    │
└─────────────────────────────────────────┘
```

**Commands:**
```bash
# Agent 8
cd /Users/bs/codes/hsm/crates/crypto-engine

# Integration tests
cargo test --test threshold_integration

# Security tests
cargo test --test threshold_security

# Benchmarks
cargo bench --bench threshold_benches

# Fuzz tests
cargo fuzz run threshold_ecdsa -- -runs=100000
cargo fuzz run threshold_bls -- -runs=100000

# FIPS verification
cargo test --test threshold_fips
```

---

## Task Assignment for Parallel Execution

### Immediate Parallel Tasks (After WS1)

| Agent | Workstream | Tasks | Est. LOC |
|-------|------------|-------|----------|
| Agent 2 | WS2: ECDSA Engine | 2.1-2.8 | 1,250 |
| Agent 3 | WS3: BLS Engine | 3.1-3.7 | 750 |
| Agent 4 | WS4: FIPS Extensions | 4.1-4.6 | 400 |

### Secondary Parallel Tasks (After WS2/WS3)

| Agent | Workstream | Tasks | Est. LOC |
|-------|------------|-------|----------|
| Agent 5 | WS5: ECDSA DKG | 5.1-5.6 | 600 |
| Agent 6 | WS6: BLS DKG | 6.1-6.5 | 350 |

### Sequential Tasks

| Agent | Workstream | Tasks | Est. LOC |
|-------|------------|-------|----------|
| Agent 1 | WS1: Types | 1.1-1.6 | 500 |
| Agent 7 | WS7: Refresh | 7.1-7.7 | 750 |
| Agent 8 | WS8: Tests | 8.1-8.8 | 1,000 |

---

## Success Metrics

### Performance Targets

| Operation | Target | Measurement |
|-----------|--------|-------------|
| ECDSA 2-of-3 keygen | >100 ops/sec | Criterion benchmark |
| ECDSA 2-of-3 sign | >500 ops/sec | Criterion benchmark |
| BLS 2-of-3 sign | >1000 ops/sec | Criterion benchmark |
| DKG 3-round (3 parties) | <100ms | Integration test |
| Key refresh (3 parties) | <50ms | Integration test |

### Security Targets

| Requirement | Verification |
|-------------|--------------|
| All key material zeroized | Memory tests |
| Constant-time operations | Timing tests |
| FIPS P-256 approved | Self-test KAT |
| secp256k1 blocked in FIPS | Compliance test |
| Invalid shares rejected | Security tests |
| Rogue key attack prevented | Security tests |

### Test Coverage Targets

| Module | Target | Tool |
|--------|--------|------|
| threshold/ecdsa | >90% | tarpaulin |
| threshold/bls | >90% | tarpaulin |
| threshold/refresh | >85% | tarpaulin |
| fips (threshold) | >95% | tarpaulin |

---

## Files Summary

### New Files (20)

```
crates/crypto-engine/src/threshold/
├── scheme.rs           # NEW
├── config.rs           # NEW
├── session.rs          # NEW
├── ecdsa/
│   ├── mod.rs          # NEW
│   ├── engine.rs       # NEW
│   ├── types.rs        # NEW
│   ├── p256.rs         # NEW
│   ├── secp256k1.rs    # NEW
│   ├── dkg.rs          # NEW
│   └── feldman.rs      # NEW
├── bls/
│   ├── mod.rs          # NEW
│   ├── engine.rs       # NEW
│   ├── types.rs        # NEW
│   ├── aggregation.rs  # NEW
│   └── dkg.rs          # NEW
└── refresh/
    ├── mod.rs          # NEW
    ├── protocol.rs     # NEW
    └── resharing.rs    # NEW

tests/
├── threshold_integration.rs  # NEW
├── threshold_security.rs     # NEW
├── threshold_property.rs     # NEW
├── threshold_performance.rs  # NEW
└── threshold_fips.rs         # NEW

benches/
└── threshold_benches.rs      # NEW

fuzz/fuzz_targets/
├── threshold_ecdsa.rs        # NEW
└── threshold_bls.rs          # NEW
```

### Modified Files (8)

```
crates/crypto-engine/src/
├── threshold/
│   ├── mod.rs          # MODIFY (exports)
│   └── types.rs        # MODIFY (new types)
└── fips/
    ├── algorithms.rs   # MODIFY (threshold algorithms)
    ├── self_test.rs    # MODIFY (threshold KATs)
    ├── audit.rs        # MODIFY (threshold events)
    └── mode.rs         # MODIFY (threshold enforcement)

crates/crypto-engine/
├── Cargo.toml          # MODIFY (dependencies if needed)
└── benches/crypto_benches.rs  # MODIFY (add threshold benchmarks)
```

---

## Dependencies

### Existing (Already in Cargo.toml)
- `frost-ed25519 = "2.2"` ✓
- `p256 = "0.13"` ✓
- `k256 = "0.13"` ✓
- `blst = "0.3"` ✓
- `zeroize = "1.8"` ✓
- `criterion = "0.5"` ✓

### May Need to Add
```toml
# For threshold ECDSA (check if needed)
frost-secp256k1 = "2.2"  # If available and suitable
vsss-rs = "4.0"          # Verifiable Secret Sharing (alternative)
```

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Threshold ECDSA complexity | Use well-tested library (frost-secp256k1) if available |
| Performance regression | Benchmark early and often |
| Security vulnerabilities | Fuzz testing, property tests, security review |
| FIPS certification delay | Clear separation of approved/non-approved |
| Integration issues | Comprehensive integration tests |

---

## Quick Start Commands

```bash
# Clone and setup
cd /Users/bs/codes/hsm

# Phase 1: Foundation (WS1)
# Single agent implements types
claude "Read docs/phases/FIPS-MPC-IMPLEMENTATION-PLAN.md and implement Workstream 1 (Types & Infrastructure)"

# Phase 2: Parallel Engines (WS2 + WS3 + WS4)
# Launch 3 agents in parallel
claude "Implement Workstream 2 (Threshold ECDSA Engine) from the plan" &
claude "Implement Workstream 3 (Threshold BLS Engine) from the plan" &
claude "Implement Workstream 4 (FIPS Extensions) from the plan" &
wait

# Phase 3: Parallel DKG (WS5 + WS6)
claude "Implement Workstream 5 (ECDSA DKG) from the plan" &
claude "Implement Workstream 6 (BLS DKG) from the plan" &
wait

# Phase 4: Key Refresh (WS7)
claude "Implement Workstream 7 (Key Refresh) from the plan"

# Phase 5: Tests (WS8)
claude "Implement Workstream 8 (Tests & Benchmarks) from the plan"

# Final verification
cargo test --all
cargo bench --all
cargo clippy --all -- -D warnings
```

---

## Appendix: Algorithm Reference

### Threshold ECDSA Protocol
1. **Keygen**: Shamir's Secret Sharing of private key
2. **Round 1**: Generate nonces, broadcast commitments
3. **Round 2**: Pre-signing phase (can be done before message)
4. **Round 3**: Sign shares with message hash
5. **Aggregation**: Combine shares into (r, s) signature

### Threshold BLS Protocol (Simpler!)
1. **Keygen**: Shamir's Secret Sharing of private key
2. **Sign**: Each party signs directly (single round!)
3. **Aggregation**: Lagrange interpolation of signature shares

### Key Refresh Protocol
1. **Round 1**: Each party generates zero-polynomial, broadcasts commitments
2. **Round 2**: Distribute encrypted shares
3. **Finalize**: Add refresh shares to existing shares

### Resharing Protocol
1. **Setup**: Old parties agree on new configuration
2. **Distribution**: Old parties generate shares for new parties
3. **Collection**: New parties collect and verify shares
4. **Interpolation**: New parties compute their final shares

---

**Plan Version**: 1.0
**Created**: 2026-01-23
**Author**: Claude (Opus 4.5)
**Status**: Ready for Implementation
