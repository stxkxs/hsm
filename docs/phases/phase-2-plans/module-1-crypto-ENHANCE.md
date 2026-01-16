# Module 1: Crypto Engine - Phase 2 Enhancements

## Current Status
- ✅ 1,101 lines of code
- ✅ Compiles successfully
- ✅ Basic implementations of RSA, ECDSA, Ed25519, AES

## Performance Enhancements

### 1. Benchmark Infrastructure (Priority: CRITICAL)
**Goal**: Establish baseline and measure improvements

```bash
# Add to benches/crypto_benches.rs
```

**Tasks**:
- [ ] Create comprehensive benchmark suite for all operations
- [ ] Measure current performance (baseline)
- [ ] Add criterion benchmarks with HTML reports
- [ ] Benchmark groups for each algorithm
- [ ] Add comparison benchmarks between algorithms

**Expected baseline targets**:
- Ed25519 sign: > 1000 ops/sec
- Ed25519 verify: > 500 ops/sec
- ECDSA-P256 sign: > 500 ops/sec
- RSA-2048 sign: > 300 ops/sec
- AES-256-GCM encrypt: > 5000 ops/sec

### 2. SIMD Optimizations (Priority: HIGH)
**Goal**: Use hardware acceleration where available

**Tasks**:
- [ ] Enable SIMD features in dependencies (portable-simd, packed_simd)
- [ ] Use hardware AES-NI instructions for AES operations
- [ ] Enable AVX2/AVX512 for applicable operations
- [ ] Add runtime CPU feature detection
- [ ] Benchmark SIMD vs scalar implementations

**Code changes**:
```rust
// Enable hardware features
#[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
use aes::cipher::crypto_common::hazmat::cipher::BlockCipher;

// Runtime detection
if is_x86_feature_detected!("aes") {
    // Use hardware AES
} else {
    // Fall back to software
}
```

### 3. Memory Pool for Hot Path (Priority: HIGH)
**Goal**: Reduce allocations in critical paths

**Tasks**:
- [ ] Implement buffer pool for crypto operations
- [ ] Use stack allocation for small buffers (< 4KB)
- [ ] Pre-allocate signature/ciphertext buffers
- [ ] Reuse nonce generation buffers
- [ ] Profile allocations with heaptrack

**Performance gain**: 20-30% reduction in latency

### 4. Parallel Batch Operations (Priority: MEDIUM)
**Goal**: Support batch signing/verification

**Tasks**:
- [ ] Add `batch_sign()` and `batch_verify()` methods
- [ ] Use rayon for parallel processing
- [ ] Optimize for Ed25519 batch verification
- [ ] Add batch benchmarks
- [ ] Document batch API usage

**Expected speedup**: 3-4x for batch operations

### 5. Constant-Time Operations (Priority: CRITICAL - SECURITY)
**Goal**: Prevent timing attacks

**Tasks**:
- [ ] Audit all comparison operations for constant-time
- [ ] Use `subtle` crate for constant-time comparisons
- [ ] Replace `==` with `ct_eq()` for sensitive data
- [ ] Add timing attack tests
- [ ] Document constant-time guarantees

**Critical code review**:
```rust
// BEFORE (vulnerable)
if signature == expected_signature {
    return Ok(true);
}

// AFTER (constant-time)
use subtle::ConstantTimeEq;
if signature.ct_eq(&expected_signature).into() {
    return Ok(true);
}
```

## Security Enhancements

### 1. Memory Zeroization Audit (Priority: CRITICAL)
**Goal**: Ensure all sensitive data is zeroized

**Tasks**:
- [ ] Audit all `KeyMaterial` usage for proper zeroization
- [ ] Add `#[zeroize(drop)]` to all sensitive structs
- [ ] Use `SecretVec` from `secrecy` crate for buffers
- [ ] Add tests to verify zeroization (use valgrind/miri)
- [ ] Document zeroization guarantees

**Critical structs to check**:
- `KeyMaterial`
- Intermediate buffers in signing/encryption
- Nonces and IVs
- HMAC keys

### 2. Input Validation (Priority: HIGH)
**Goal**: Validate all inputs at API boundaries

**Tasks**:
- [ ] Validate key sizes for all algorithms
- [ ] Check plaintext/ciphertext length limits
- [ ] Validate algorithm parameters
- [ ] Add fuzz testing for all public APIs
- [ ] Return specific errors for invalid inputs

**Add validation**:
```rust
pub fn sign(&self, key: &KeyMaterial, data: &[u8]) -> Result<Vec<u8>> {
    // Validate key size
    if key.as_bytes().len() != 32 {
        return Err(CryptoError::InvalidKeySize(key.as_bytes().len()));
    }

    // Validate data size
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(CryptoError::MessageTooLarge(data.len()));
    }

    // ... proceed with signing
}
```

### 3. Secure Random Number Generation (Priority: CRITICAL)
**Goal**: Use cryptographically secure RNG everywhere

**Tasks**:
- [ ] Audit all uses of randomness
- [ ] Replace any `rand::thread_rng()` with `OsRng`
- [ ] Verify nonce generation is cryptographically secure
- [ ] Add entropy health checks
- [ ] Document RNG usage

### 4. Side-Channel Resistance (Priority: HIGH)
**Goal**: Mitigate cache timing attacks

**Tasks**:
- [ ] Use constant-time select operations
- [ ] Avoid data-dependent branching in crypto code
- [ ] Use constant-time lookups (no array indexing with secret data)
- [ ] Add valgrind cache-grind analysis
- [ ] Document side-channel mitigations

### 5. Dependency Security Audit (Priority: HIGH)
**Goal**: Ensure all dependencies are secure

**Tasks**:
- [ ] Run `cargo audit` and fix all vulnerabilities
- [ ] Pin dependency versions
- [ ] Review security advisories for crypto crates
- [ ] Consider using audited crates only
- [ ] Document dependency security posture

## Code Quality Enhancements

### 1. Error Handling (Priority: HIGH)
**Goal**: Never leak sensitive information in errors

**Tasks**:
- [ ] Audit all error messages
- [ ] Remove key material from error strings
- [ ] Add error context without sensitive data
- [ ] Use opaque errors at API boundary
- [ ] Add error handling tests

**Pattern**:
```rust
// BAD - leaks key
return Err(CryptoError::SigningFailed(format!("Key: {:?}", key)));

// GOOD - opaque
return Err(CryptoError::SigningFailed("Invalid key format".into()));
```

### 2. Testing Enhancements (Priority: HIGH)
**Goal**: Comprehensive test coverage

**Tasks**:
- [ ] Add Known Answer Tests (KAT) from NIST
- [ ] Add negative test cases
- [ ] Add fuzzing with cargo-fuzz
- [ ] Add property-based tests with proptest
- [ ] Target > 90% code coverage

**Add KAT tests**:
```rust
#[test]
fn test_ed25519_rfc8032_vectors() {
    // Use official test vectors
    let vectors = load_rfc8032_vectors();
    for v in vectors {
        let sig = sign(&v.key, &v.message).unwrap();
        assert_eq!(sig, v.expected_signature);
    }
}
```

### 3. Documentation (Priority: MEDIUM)
**Goal**: Complete API documentation

**Tasks**:
- [ ] Add rustdoc for all public APIs
- [ ] Document security properties
- [ ] Add usage examples
- [ ] Document performance characteristics
- [ ] Add security considerations section

## Implementation Checklist

### Phase 2A: Performance (Week 1)
- [ ] Set up comprehensive benchmarks
- [ ] Measure baseline performance
- [ ] Implement memory pooling
- [ ] Add SIMD optimizations
- [ ] Verify performance targets met

### Phase 2B: Security (Week 1-2)
- [ ] Complete memory zeroization audit
- [ ] Add constant-time operations
- [ ] Implement input validation
- [ ] Add fuzz testing
- [ ] Run cargo-audit

### Phase 2C: Testing & Documentation (Week 2)
- [ ] Add KAT tests
- [ ] Add property-based tests
- [ ] Achieve > 90% coverage
- [ ] Complete documentation
- [ ] Security review

## Success Metrics

**Performance**:
- ✅ Ed25519 sign: > 1000 ops/sec
- ✅ ECDSA-P256 sign: > 500 ops/sec
- ✅ RSA-2048 sign: > 300 ops/sec
- ✅ AES-256-GCM: > 5000 ops/sec
- ✅ Memory allocations < 10 per operation

**Security**:
- ✅ 100% zeroization of sensitive data
- ✅ All comparisons constant-time
- ✅ Zero cargo-audit warnings
- ✅ Fuzz testing passes 1M iterations
- ✅ No timing attack vulnerabilities

**Quality**:
- ✅ Code coverage > 90%
- ✅ All KAT tests pass
- ✅ Documentation complete
- ✅ Zero clippy warnings

## Claude Agent Instructions

When relaunched, the agent should:

1. Read this enhancement plan completely
2. Run benchmarks to establish baseline
3. Implement each enhancement in order of priority
4. Test after each change
5. Verify performance targets are met
6. Run security audit (cargo-audit, clippy)
7. Achieve all success metrics

Focus on **production-grade quality** - this code will handle cryptographic keys in production.
