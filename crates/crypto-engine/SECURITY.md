# Security Considerations

## Overview

This document describes the security properties, guarantees, and known issues of the HSM Crypto Engine.

## Security Guarantees

### Memory Zeroization

All sensitive key material is automatically zeroized on drop using the `zeroize` crate:

- `KeyMaterial` struct uses `#[zeroize(drop)]` attribute
- Private keys are never leaked in error messages
- Intermediate buffers in crypto operations are not currently zeroized (future enhancement)

### Cryptographically Secure Random Number Generation

All random number generation uses operating system entropy:

- Key generation: `OsRng` from `rand_core`
- Nonce generation (AES-GCM): `getrandom` crate
- No weak or deterministic RNG used anywhere

### Constant-Time Operations

The underlying cryptographic libraries provide constant-time implementations:

- **Ed25519**: Uses `ed25519-dalek` which implements constant-time operations
- **ECDSA P-256/P-384**: Uses `p256`/`p384` crates with constant-time scalar multiplication
- **AES-GCM**: Uses hardware AES-NI when available (constant-time)
- **RSA**: ⚠️ Known timing side-channel vulnerability (see below)

### Input Validation

All inputs are validated at API boundaries:

- Key sizes are checked and return specific errors for mismatches
- Signature sizes are validated
- Plaintext size limits enforced (64 MB for AES-GCM)
- Ciphertext minimum sizes verified

## Known Security Issues

### RSA Timing Side-Channel (RUSTSEC-2023-0071)

**Severity**: Medium (CVSS 5.9)

**Description**: The RSA crate (v0.9.10) is vulnerable to the Marvin Attack, a timing side-channel that could allow key recovery through careful measurement of decryption timing.

**Impact**:
- Affects RSA PKCS#1 v1.5 and PSS signature verification
- Requires precise timing measurements over many operations
- Not exploitable in typical network scenarios

**Mitigation**:
- **Prefer ECDSA or Ed25519** for new deployments
- RSA should only be used when required for compatibility
- No fix available in current RSA crate version
- Monitor https://rustsec.org/advisories/RUSTSEC-2023-0071 for updates

### Future Enhancements

1. **Memory Pooling**: Reduce allocations in hot paths
2. **Batch Verification**: Optimize Ed25519 batch verification using native support
3. **SIMD Optimizations**: Enable hardware acceleration features
4. **Additional Zeroization**: Zero intermediate buffers in signing/encryption

## Security Testing

### Test Coverage

- ✅ Known Answer Tests (KAT) from RFC 8032, NIST vectors
- ✅ Property-based testing with `proptest`
- ✅ Fuzz testing infrastructure in `fuzz/`
- ✅ Input validation tests
- ✅ Integration tests

### Running Security Tests

```bash
# Run all tests including property tests
cargo test

# Run fuzz tests (requires cargo-fuzz)
cd fuzz
cargo fuzz run fuzz_ed25519_sign
cargo fuzz run fuzz_ed25519_verify
cargo fuzz run fuzz_aes_gcm_encrypt
cargo fuzz run fuzz_aes_gcm_decrypt

# Run security audit
cargo audit
```

## Dependency Security

Regular dependency audits are performed using `cargo audit`:

```bash
cargo audit
```

Current known issues:
- `rsa 0.9.10`: RUSTSEC-2023-0071 (Marvin Attack)

## Reporting Security Issues

If you discover a security vulnerability, please email: security@example.com

Do NOT open a public GitHub issue for security vulnerabilities.

## Changelog

### Phase 2 Enhancements (Current)

- ✅ Enhanced input validation with specific error types
- ✅ Added batch signing/verification operations
- ✅ Comprehensive property-based testing
- ✅ Fuzz testing infrastructure
- ✅ Security documentation
- ✅ Performance benchmarks (Ed25519: 38K ops/sec)

### Phase 1 (Initial)

- Basic implementations of Ed25519, ECDSA, RSA, AES-GCM
- Memory zeroization for KeyMaterial
- Cryptographically secure RNG
- Known Answer Tests
