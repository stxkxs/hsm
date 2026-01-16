# Claude Development Guide for HSM Project

This document captures the development approach, workflows, and extensibility patterns for the HSM (Hardware Security Module) project. It serves as a guide for Claude agents working on this codebase.

---

## Project Overview

**HSM** is a production-grade, software-based Hardware Security Module implemented in Rust for Kubernetes environments. It provides cryptographic operations, key management, authentication, audit logging, and backup/recovery capabilities.

### Architecture: 9-Module Design

The project follows a **modular architecture** with 9 independent crates:

| Module | Crate           | Purpose                                                  |
|--------|-----------------|----------------------------------------------------------|
| 1      | `crypto-engine` | Core cryptographic primitives (RSA, ECDSA, Ed25519, AES) |
| 2      | `key-manager`   | Key lifecycle management and storage coordination        |
| 3      | `auth`          | mTLS authentication and RBAC authorization               |
| 4      | `grpc-api`      | gRPC API server with Protocol Buffers                    |
| 5      | `audit`         | Tamper-evident audit logging with hash chains            |
| 6      | `metrics`       | Prometheus metrics and monitoring                        |
| 7      | `storage`       | Encrypted persistent storage backend                     |
| 8      | `backup`        | Backup/recovery with Shamir's Secret Sharing             |
| 9      | `config`        | Configuration management and validation                  |

**Design Principle**: Each module is independent with well-defined interfaces, enabling parallel development and isolated testing.

---

## Development Approach

### Phase-Based Development

The project follows a **two-phase development lifecycle**:

#### Phase 1: Initial Implementation
- **Goal**: Get each module working with core functionality
- **Focus**: Correctness, completeness, compilation
- **Deliverable**: Functional code that passes basic tests
- **Plans**: Located in `docs/phases/phase-1-plans/`

#### Phase 2: Performance & Security Enhancements
- **Goal**: Optimize for production deployment
- **Focus**: Performance, security hardening, comprehensive testing
- **Deliverable**: Production-grade code meeting all success metrics
- **Plans**: Located in `docs/phases/phase-2-plans/`

### Development Workflow

Work directly with Claude on any module:

```bash
# Navigate to module
cd crates/<module-name>

# View implementation plan
cat ../docs/phases/phase-1-plans/module-N-*.md

# View enhancement plan
cat ../docs/phases/phase-2-plans/module-N-*-ENHANCE.md

# Run tests
cargo test

# Run benchmarks
cargo bench
```

#### Phase 1 Workflow
```bash
cd crates/crypto-engine

# Read the plan
cat ../docs/phases/phase-1-plans/module-1-crypto-engine.md

# Ask Claude to implement
"Read ../docs/phases/phase-1-plans/module-1-crypto-engine.md and implement it"

# Claude will:
# 1. Read the implementation plan
# 2. Create file structure
# 3. Implement all code
# 4. Write tests
# 5. Update Cargo.toml with dependencies
# 6. Run cargo check and cargo test
```

#### Phase 2 Workflow
```bash
cd crates/crypto-engine

# Read the enhancement plan
cat ../docs/phases/phase-2-plans/module-1-crypto-ENHANCE.md

# Ask Claude to apply enhancements
"Read ../docs/phases/phase-2-plans/module-1-crypto-ENHANCE.md and implement all enhancements"

# Claude will:
# 1. Read the enhancement plan
# 2. Run existing tests (baseline)
# 3. Implement performance optimizations
# 4. Implement security enhancements
# 5. Add benchmarks, fuzz tests, property tests
# 6. Verify success metrics
# 7. Run cargo check, test, bench
```

---

## Key Technical Patterns

### 1. Performance Optimization

**Lock-Free Concurrency**:
```rust
use dashmap::DashMap;

pub struct KeyStore {
    keys: Arc<DashMap<KeyId, Arc<Key>>>,  // Lock-free concurrent access
}
```

**LRU Caching**:
```rust
use lru::LruCache;

pub struct CachedStorage {
    cache: Arc<Mutex<LruCache<KeyId, Arc<EncryptedKey>>>>,
    backend: Box<dyn StorageBackend>,
}
```

**SIMD Acceleration**:
```rust
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

// Use AES-NI, AVX2, AVX512 when available
```

**Async I/O**:
```rust
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn read_key(&self, key_id: &KeyId) -> Result<Vec<u8>> {
    let mut file = File::open(path).await?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await?;
    Ok(buffer)
}
```

### 2. Security Hardening

**Constant-Time Operations**:
```rust
use subtle::ConstantTimeEq;

pub fn verify_signature(&self, sig: &[u8], expected: &[u8]) -> bool {
    sig.ct_eq(expected).into()
}
```

**Memory Zeroization**:
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    bytes: Vec<u8>,
}
```

**Secret Redaction**:
```rust
use secrecy::{Secret, ExposeSecret};

pub struct Config {
    #[serde(deserialize_with = "deserialize_secret")]
    pub master_key: Secret<Vec<u8>>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("master_key", &"<redacted>")
            .finish()
    }
}
```

### 3. Testing Strategies

**Benchmarking with Criterion**:
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_sign(c: &mut Criterion) {
    let engine = CryptoEngine::new();
    let key = engine.generate_ed25519_keypair();
    let message = b"test message";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| engine.sign(black_box(&key), black_box(message)))
    });
}

criterion_group!(benches, bench_sign);
criterion_main!(benches);
```

**Fuzz Testing**:
```rust
// fuzz/fuzz_targets/crypto_operations.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 { return; }
    let engine = CryptoEngine::new();
    let _ = engine.hash_sha256(data);
});
```

**Property-Based Testing**:
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_encrypt_decrypt_roundtrip(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let engine = CryptoEngine::new();
        let key = engine.generate_aes_key(256);
        let encrypted = engine.encrypt(&key, &data)?;
        let decrypted = engine.decrypt(&key, &encrypted)?;
        prop_assert_eq!(data, decrypted);
    }
}
```

---

## Extensibility: Skills, Agents, and Hooks

### Claude Code Skills

**Recommended Skills to Create**:

1. **`/hsm-module`** - Quick module development helper
   ```bash
   # Usage: /hsm-module <number> [phase]
   # Automatically reads plan and implements module
   ```
   - Reads appropriate plan file
   - Sets working directory to crate
   - Follows phase-specific workflow
   - Runs verification commands

2. **`/hsm-bench`** - Benchmark runner and analyzer
   ```bash
   # Usage: /hsm-bench [module-number]
   # Runs benchmarks and analyzes performance
   ```
   - Runs `cargo bench` for specified module(s)
   - Parses criterion output
   - Compares against success metrics
   - Reports pass/fail for performance targets

3. **`/hsm-security-audit`** - Security verification
   ```bash
   # Usage: /hsm-security-audit [module-number]
   # Comprehensive security checks
   ```
   - Runs `cargo audit`
   - Runs `cargo clippy -- -D warnings`
   - Checks for constant-time operations
   - Verifies zeroization of sensitive data
   - Scans for secret logging

4. **`/hsm-test-coverage`** - Test coverage analyzer
   ```bash
   # Usage: /hsm-test-coverage [module-number]
   # Analyzes test coverage
   ```
   - Runs `cargo tarpaulin`
   - Reports coverage per module
   - Identifies untested code paths
   - Suggests additional test cases

5. **`/hsm-fuzz`** - Fuzz testing orchestrator
   ```bash
   # Usage: /hsm-fuzz <module-number> [iterations]
   # Runs fuzz tests
   ```
   - Lists available fuzz targets
   - Runs specified number of iterations
   - Reports crashes/hangs
   - Analyzes corpus coverage

### Claude Code Hooks

**Recommended Hooks to Configure**:

1. **Pre-Commit Hook** - Code quality gate
   ```json
   {
     "hooks": {
       "pre-commit": {
         "command": "cargo fmt --check && cargo clippy -- -D warnings",
         "description": "Format check and lint before committing"
       }
     }
   }
   ```

2. **Post-Edit Hook** - Incremental verification
   ```json
   {
     "hooks": {
       "post-edit": {
         "command": "cargo check --all",
         "description": "Verify compilation after edits"
       }
     }
   }
   ```

3. **Pre-Benchmark Hook** - Clean before benchmarking
   ```json
   {
     "hooks": {
       "pre-benchmark": {
         "command": "cargo clean && cargo build --release",
         "description": "Clean build before benchmarks"
       }
     }
   }
   ```

### Specialized Agents

**Agent Types for This Project**:

1. **Security Agent** - Focus on security enhancements
   - Prompt: "Review module X for security vulnerabilities, implement constant-time operations, add zeroization"
   - Tools: Read, Edit, Bash (for cargo audit/clippy)
   - Context: Security guidelines from enhancement plans

2. **Performance Agent** - Focus on optimization
   - Prompt: "Optimize module X for performance, implement caching, add SIMD, benchmark improvements"
   - Tools: Read, Edit, Bash (for cargo bench)
   - Context: Performance targets from enhancement plans

3. **Testing Agent** - Focus on test coverage
   - Prompt: "Add comprehensive tests to module X: unit tests, property tests, fuzz tests, benchmarks"
   - Tools: Read, Write, Bash (for cargo test/bench/fuzz)
   - Context: Success metrics requiring >90% coverage

---

## Best Practices for Claude Agents

### 1. Always Read Before Writing
```bash
# ❌ Bad: Edit without reading
claude "Add caching to key-manager"

# ✅ Good: Read, understand, then edit
claude "Read key-manager/src/lib.rs, understand the current implementation, then add LRU caching following the pattern in the enhancement plan"
```

### 2. Follow the Plans
Each module has detailed implementation and enhancement plans. **Always read and follow them**:
```bash
cd crates/crypto-engine
claude "Read and implement ../docs/phases/phase-2-plans/module-1-crypto-ENHANCE.md step by step"
```

### 3. Verify After Changes
After implementing changes, always verify:
```bash
cargo check      # Fast compilation check
cargo test       # Run all tests
cargo clippy     # Lint for issues
cargo bench      # Performance verification (Phase 2)
```

### 4. Use Success Metrics
Each enhancement plan includes quantifiable success metrics. Verify them:
```
Performance:
✓ Ed25519 signing: 1,200 ops/sec (target: >1,000)
✓ P99 latency: 0.8ms (target: <1ms)
✓ Cache hit rate: 94% (target: >90%)

Security:
✓ All operations use constant-time comparisons
✓ All sensitive data zeroized on drop
✓ cargo audit: 0 vulnerabilities
```

### 5. Document Deviations
If you deviate from the plan, document why:
```rust
// NOTE: Using ChaCha20-Poly1305 instead of AES-256-GCM
// because it provides better performance on non-AES-NI hardware
// and constant-time guarantees across all platforms.
// See enhancement plan section 3.2 for discussion.
```

---

## Common Development Patterns

### Adding a New Cryptographic Algorithm

1. **Update crypto-engine/src/algorithms/** with new algorithm
2. **Add tests** in corresponding test file
3. **Add benchmarks** in benches/crypto_ops.rs
4. **Update Key enum** in key-manager to support new key type
5. **Add gRPC endpoint** in grpc-api proto and implementation
6. **Update docs** with algorithm specifications

### Adding a New Module

1. **Create plan** in `docs/phases/phase-1-plans/module-N-name.md`
2. **Add to Cargo.toml** workspace members
3. **Initialize crate**: `cd crates && cargo new --lib new-module`
4. **Implement following plan**: Ask Claude to read and implement the plan
5. **Create enhancement plan** for Phase 2
6. **Update integration tests** in root

### Optimizing Performance

1. **Establish baseline**: Run `cargo bench` before changes
2. **Implement optimization**: Follow enhancement plan priorities
3. **Verify improvement**: Run `cargo bench` after changes
4. **Check regression**: Ensure other benchmarks aren't slower
5. **Document results**: Update BENCHMARK_RESULTS.md

---

## File Organization Reference

```
hsm/
├── CLAUDE.md                          # This file - Guide for Claude agents
├── README.md                          # Project overview
├── Cargo.toml                         # Workspace configuration
│
├── crates/                            # All module implementations
│   ├── crypto-engine/                 # Module 1
│   ├── key-manager/                   # Module 2
│   ├── auth/                          # Module 3
│   ├── grpc-api/                      # Module 4
│   ├── audit/                         # Module 5
│   ├── metrics/                       # Module 6
│   ├── storage/                       # Module 7
│   ├── backup/                        # Module 8
│   └── config/                        # Module 9
│
├── docs/                              # Documentation
│   ├── architecture/
│   │   └── spec.md                    # Full specification
│   ├── development/
│   │   └── getting-started.md         # New developer guide
│   └── phases/
│       ├── phase-1-plans/             # Initial implementation plans
│       │   ├── module-1-crypto-engine.md
│       │   ├── module-2-key-management.md
│       │   └── ...
│       ├── phase-2-plans/             # Enhancement plans
│       │   ├── module-1-crypto-ENHANCE.md
│       │   ├── module-2-key-manager-ENHANCE.md
│       │   └── ...
│       └── phase-2-summary.md         # Enhancement overview
│
├── scripts/                           # Utility scripts
│   ├── init-workspace.sh              # Initial project setup
│   └── archive/                       # Old/deprecated scripts
│
└── test-data/                         # Test fixtures and data
```

---

## Quick Reference Commands

### Development
```bash
# Work on a specific module
cd crates/<module-name>

# Build all modules
cargo build --all

# Test all modules
cargo test --all

# Benchmark all modules
cargo bench --all

# Security audit
cargo audit && cargo clippy --all -- -D warnings

# Test coverage
cargo tarpaulin --all --out Lcov
```

### Module-Specific
```bash
# Work on specific module
cd crates/<module-name>

# Fast compilation check
cargo check

# Run module tests
cargo test

# Run module benchmarks
cargo bench

# Run fuzz tests
cargo fuzz list
cargo fuzz run <target> -- -runs=1000000
```

---

## Success Metrics by Module

| Module | Performance Target | Security Target |
|--------|-------------------|-----------------|
| Crypto Engine | >1000 Ed25519 ops/sec, >500 ECDSA ops/sec | Constant-time ops, memory zeroization |
| Key Manager | <1ms key lookup p99, >1000 concurrent ops/sec | Namespace isolation, secure deletion |
| Auth | <5ms cert validation p99, <100μs permission checks | mTLS hardening, rate limiting |
| gRPC API | >10k connections, >5000 req/sec | Input validation, error sanitization |
| Audit | <5ms audit write p99, >10k events/sec | Tamper evidence, log signing |
| Metrics | <10μs metric overhead, <1% CPU | N/A |
| Storage | <100μs cached reads, >90% cache hit | Envelope encryption, integrity checks |
| Backup | <5min full backup (100k keys), <1min incremental | SSS validation, backup encryption |
| Config | <1μs config reads, hot reload | Secret management, validation |

---

## When to Use What

### Work directly with Claude when:
- Implementing features from plans
- Making targeted fixes or improvements
- Reviewing code and understanding architecture
- Running verification commands
- Working on any module

### Use specialized agents when:
- Focusing on one aspect (security, performance, testing)
- Large refactoring with clear scope
- Systematic improvements across all modules

---

## Project Status

### Phase 1: Complete ✅
- All 9 modules implemented
- Total: 14,223 lines of code
- All modules compile successfully
- Basic tests passing

### Phase 2: Complete ✅
- All modules enhanced for performance and security
- Benchmarks added and targets met
- Comprehensive test coverage (>90%)
- Production-ready code

### Next Steps
- Integration testing across modules
- End-to-end deployment testing in Kubernetes
- Performance testing under load
- Security penetration testing
- Documentation completion

---

## Troubleshooting

### Common Issues

**Issue**: `cargo check` fails with dependency errors
```bash
# Solution: Update Cargo.lock
cargo update
cargo check
```

**Issue**: Benchmarks show performance regression
```bash
# Solution: Check for debug mode, rebuild release
cargo clean
cargo build --release
cargo bench
```

**Issue**: Fuzz tests find crashes
```bash
# Solution: Minimize the crashing input
cargo fuzz cmin <target>  # Minimize corpus
cargo fuzz tmin <target> <crash-file>  # Minimize crash input
# Then investigate and fix the bug
```

**Issue**: Tests pass locally but fail in CI
```bash
# Solution: Check for timing-dependent tests or concurrency issues
# Use --test-threads=1 to isolate
cargo test -- --test-threads=1
```

---

## Contributing Guidelines for Claude Agents

1. **Read the plan first** - Always consult the implementation or enhancement plan
2. **Follow the patterns** - Use established patterns from other modules
3. **Verify your work** - Run check, test, clippy, bench after changes
4. **Document changes** - Add comments for non-obvious code
5. **Update metrics** - If adding features, update success metrics
6. **Security first** - Never compromise security for performance
7. **Test thoroughly** - Aim for >90% code coverage
8. **Benchmark performance** - Verify against targets in enhancement plans

---

## Additional Resources

- **Full Specification**: `docs/architecture/spec.md`
- **Phase 2 Summary**: `docs/phases/phase-2-summary.md`
- **Getting Started**: `docs/development/getting-started.md`
- **Rust Crypto Libraries**:
  - `ring` - Fast, safe crypto
  - `RustCrypto` - Pure Rust implementations
  - `subtle` - Constant-time operations
  - `zeroize` - Memory zeroization
  - `secrecy` - Secret management

---

**Last Updated**: Phase 2 completion (January 2026)
**Maintained By**: Claude agents working on HSM project
