# Phase 3: Advanced Features

This phase adds advanced cryptographic capabilities and integration points to bring the HSM to feature parity with commercial solutions.

## Feature Plans

| Plan | Feature | Complexity | Dependencies |
|------|---------|------------|--------------|
| 3.1 | [Post-Quantum Cryptography](./plan-3.1-post-quantum.md) | Medium | pqcrypto |
| 3.2 | [Threshold Cryptography](./plan-3.2-threshold.md) | High | frost-core |
| 3.3 | [Blind Signatures](./plan-3.3-blind-signatures.md) | Medium | None (implement from primitives) |
| 3.4 | [PKCS#11 Bridge](./plan-3.4-pkcs11-bridge.md) | High | cryptoki, libloading |
| 3.5 | [KMIP Protocol](./plan-3.5-kmip.md) | High | Custom implementation |
| 3.6 | [Secrets Manager](./plan-3.6-secrets-manager.md) | Medium | Existing crates |

## Parallel Execution

These plans are designed for parallel execution by independent agents:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Cryptographic Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │ Post-Quantum │  │  Threshold   │  │    Blind     │           │
│  │   (3.1)      │  │    (3.2)     │  │ Signatures   │           │
│  │              │  │              │  │    (3.3)     │           │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
│         │                 │                 │                    │
│         └─────────────────┼─────────────────┘                    │
│                           ▼                                      │
│                   crypto-engine crate                            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     Integration Layer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   PKCS#11    │  │    KMIP      │  │   Secrets    │           │
│  │   (3.4)      │  │    (3.5)     │  │   Manager    │           │
│  │              │  │              │  │    (3.6)     │           │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
│         │                 │                 │                    │
│         └─────────────────┼─────────────────┘                    │
│                           ▼                                      │
│                    grpc-api / rest-api                           │
└─────────────────────────────────────────────────────────────────┘
```

## Agent Instructions

Each agent should:

1. Read their assigned plan completely
2. Check dependencies in workspace Cargo.toml
3. Create the new crate or modify existing crate
4. Implement following the plan structure
5. Add comprehensive tests
6. Add benchmarks where applicable
7. Update workspace Cargo.toml if creating new crate
8. Run `cargo check --workspace` before finishing

## Coordination Points

While agents work in parallel, some coordination is needed:

- **crypto-engine modifications**: Plans 3.1, 3.2, 3.3 all modify crypto-engine
  - Each should add to separate submodules to avoid conflicts
  - 3.1 → `src/pqc/`
  - 3.2 → `src/threshold/`
  - 3.3 → `src/blind/`

- **Proto file additions**: Plans 3.4, 3.5, 3.6 may add gRPC endpoints
  - Each should add to separate .proto files
  - Or coordinate additions to hsm.proto

- **Key types**: All plans may add new KeyAlgorithm variants
  - Coordinate additions to avoid enum conflicts
