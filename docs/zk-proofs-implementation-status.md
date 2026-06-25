# ZK Proofs Implementation Status

> ## ⚠️ NOT PRODUCTION-READY — NO SOUNDNESS GUARANTEE
>
> The `hsm-zk-proofs` crate is a **structural scaffold**, not a working
> zero-knowledge proof system. Its lookup-argument verifier is an explicit
> placeholder: it does **not** verify anything and **accepts proofs
> unconditionally** (see `crates/zk-proofs/src/lasso.rs`, which states it
> "provides no soundness guarantee whatsoever and must never be used to make
> security decisions"). It is **not wired into the running HSM server** and must
> not be used for compliance, attestation, or any security-relevant decision.
>
> This document tracks intended design and remaining work. Every "designed" or
> "scaffolded" item below is interface/structure only unless explicitly stated to
> be functional.

## Executive Summary

Privacy-preserving audit verification using ZK-SNARKs and Lasso optimization is
**scaffolded at the interface/structure level only**. The crate compiles and is a
workspace member, but the proof generation and verification paths are placeholders
with no cryptographic soundness. Substantial cryptographic implementation work
remains before any of this is usable.

## What actually exists

### Module structure (scaffold)

`crates/zk-proofs/` contains five modules whose **types and interfaces** are
defined but whose proving/verifying internals are placeholders:

- **`lasso.rs`** — `LookupTable`, `LookupArgument`, `HashLookupTable`. The
  verifier is a placeholder that does not check the lookup relation (no real
  sumcheck). **No soundness.**
- **`merkle_proof.rs`** — `MerkleProofCircuit` / `MerkleProofSystem` types and
  R1CS constraint scaffolding. Hash constraints are not fully implemented.
- **`event_proof.rs`** — `EventExistenceCircuit` and the public/private field
  split (`PublicEventData`). Circuit constraints are incomplete.
- **`proof_system.rs`** — `ProofSystem` / `BatchProver` / `ProofMetrics`
  interface surface over the above.
- **`circuits.rs`** — field-element and constraint helpers.

### Integration points (defined, not active)

- `crates/audit/src/zk_integration.rs` defines a `ZkAuditLogger` trait and
  request/response types. It is **not** wired into the running server.
- `crates/grpc-api/proto/hsm.proto` declares ZK RPCs
  (`GenerateZkAuditProof`, `VerifyZkAuditProof`, `GetMerkleRoot`). The gRPC
  service itself is not registered by the default `hsm-server` binary.

### Benchmarks and docs

- `crates/zk-proofs/benches/zk_benchmarks.rs` exists but measures the placeholder
  paths, so its numbers do **not** reflect a sound proof system.
- `docs/zk-audit-proofs.md` describes the *intended* design; treat its security
  claims as design goals, not delivered guarantees.

## Remaining work (to make this real)

This is genuine cryptographic engineering, not "API compatibility cleanup":

1. **Lasso lookup argument** — implement the real sumcheck protocol and a sound
   verifier (the current one accepts everything).
2. **Hash constraints** — implement SHA-256 (and any commitment hash) as circuit
   constraints.
3. **Merkle / event circuits** — complete the R1CS constraints and witness
   generation.
4. **Groth16 wiring** — real trusted setup, prove, and verify against BN254.
5. **Audit field mapping** — map real `AuditEvent` fields into circuit inputs.
6. **Integration** — register the gRPC service and wire `ZkAuditLogger` into the
   audit path.
7. **Security review** — independent review and test vectors before any
   security-relevant use.

## Status by phase

### Phase 1 (Minimum Viable) — NOT started (scaffold only)
- [ ] Sound Merkle proof generation + verification
- [ ] Sound event-existence proof
- [ ] Tests that assert real soundness (reject forged/invalid proofs)

### Phase 2 (Performance) — NOT started
- [ ] Lasso sumcheck implemented and benchmarked honestly
- [ ] Batch proving

### Phase 3 (Production) — NOT started
- [ ] Trusted setup ceremony documented + executed
- [ ] Independent security audit
- [ ] gRPC service registered and integrated
- [ ] Performance validated against targets

## Intended design references

- **Primary paper**: "Unlocking the Lookup Singularity with Lasso"
  (Setty, Thaler, Wahby, 2024) — the lookup-argument approach this crate aims to
  implement.
- **Intended primitives**: BN254 curve, Groth16 SNARK, SHA-256 Merkle hashing,
  KZG polynomial commitments.
- **Intended privacy model**: a proof would reveal only public inputs
  (sequence, event type, timestamp, Merkle root) while hiding client id, key id,
  and operation details. This is the *goal*; it is not delivered by the current
  placeholder.

---

**Status**: Scaffold/interface only; verifier is a non-sound placeholder.
**Not** wired into the running server. Do not use for security decisions.
**Last updated**: 2026-06 (corrected to reflect actual implementation state).
