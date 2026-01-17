# Constant-Time Guarantees and Timing Side-Channel Mitigation

This document describes the constant-time properties of the HSM crypto-engine and the measures taken to prevent timing side-channel attacks.

## Table of Contents

1. [Overview](#overview)
2. [Threat Model](#threat-model)
3. [Constant-Time Operations](#constant-time-operations)
4. [Library Dependencies](#library-dependencies)
5. [Verification Methods](#verification-methods)
6. [Known Limitations](#known-limitations)
7. [Best Practices](#best-practices)
8. [References](#references)

---

## Overview

Timing side-channel attacks exploit variations in execution time to infer information about secret data (keys, plaintexts, internal state). The HSM crypto-engine implements multiple defenses against these attacks:

- **Constant-time comparison functions** using the `subtle` crate
- **Verified constant-time libraries** for cryptographic primitives
- **Statistical timing tests** using dudect
- **Cache-timing analysis** using Valgrind cache-grind
- **Explicit annotations** (`#[inline(never)]`) to prevent compiler optimizations

---

## Threat Model

### Attacker Capabilities

We defend against attackers who can:

1. **Measure execution time** of cryptographic operations
2. **Choose inputs** to cryptographic functions (chosen-plaintext, chosen-ciphertext)
3. **Observe cache behavior** via shared CPU cache (same machine, different processes)
4. **Observe branch prediction** via speculative execution side channels
5. **Make repeated measurements** to reduce noise via statistical averaging

### Out of Scope

The following are outside our threat model:

- **Physical attacks** (power analysis, electromagnetic emissions, fault injection)
- **Privileged attackers** with kernel or hypervisor access
- **Hardware backdoors** in CPU or crypto accelerators
- **Rowhammer** and other DRAM attacks

---

## Constant-Time Operations

The `hsm_crypto_engine::constant_time` module provides verified constant-time implementations of timing-critical operations.

### Core Functions

#### 1. `ct_compare(a: &[u8], b: &[u8]) -> bool`

Compares two byte slices in constant time.

**Guarantees:**
- Execution time depends only on slice length
- No early return on first difference
- No secret-dependent branches
- Uses `subtle::ConstantTimeEq` internally

**Use cases:**
- Comparing authentication tags (AES-GCM, HMAC)
- Verifying message authentication codes
- Checking password hashes

**Example:**
```rust
use hsm_crypto_engine::constant_time::ct_compare;

let expected_tag = &[0x12, 0x34, 0x56, 0x78];
let received_tag = &[0x12, 0x34, 0x56, 0x78];

if ct_compare(expected_tag, received_tag) {
    println!("Tag verified");
} else {
    println!("Tag mismatch");
}
```

---

#### 2. `ct_verify_tag(expected: &[u8], received: &[u8]) -> bool`

Verifies authentication tags in constant time (alias for `ct_compare`).

**Security properties:**
- Timing independent of tag content
- Timing independent of position of first difference
- Prevents tag oracle attacks
- Mitigates Bleichenbacher-style padding oracles

---

#### 3. `ct_select(condition: bool, a: &[u8], b: &[u8]) -> Vec<u8>`

Selects between two byte slices in constant time.

**Guarantees:**
- Time independent of condition value
- Time independent of buffer content
- No conditional branches on secret data
- Prevents branch prediction attacks

**Use cases:**
- Conditional key selection without leaking which key is chosen
- Implementing constant-time conditional logic
- Masking operations in white-box cryptography

**Example:**
```rust
use hsm_crypto_engine::constant_time::ct_select;

let key_a = b"production_key_1";
let key_b = b"production_key_2";
let use_key_a = true; // Condition from secret data

let selected = ct_select(use_key_a, key_a, key_b);
// Timing reveals nothing about which key was selected
```

---

#### 4. `ct_zero(data: &mut [u8])`

Zeros memory in a way that won't be optimized away.

**Guarantees:**
- Guaranteed not to be optimized away by compiler
- Uses compiler memory fences
- Ensures sensitive data is cleared from memory

**Use cases:**
- Clearing key material after use
- Ensuring secrets don't remain in memory dumps
- Preventing memory disclosure attacks

---

## Library Dependencies

The HSM relies on several external cryptographic libraries. Below we document their constant-time properties and known vulnerabilities.

### Ed25519: `ed25519-dalek` (v2.2)

**Constant-time claims:** ✅ **YES**

- Ed25519 signature generation and verification are designed to be constant-time
- Uses constant-time field arithmetic from `curve25519-dalek`
- No secret-dependent branches in critical paths

**Verification:**
- Library maintainers claim constant-time implementation
- Extensively tested by the crypto community
- Used in production by Signal, Tor, and other security-critical systems

**Known issues:** None

---

### ECDSA: `p256` (v0.13) and `p384` (v0.13)

**Constant-time claims:** ✅ **PARTIAL**

- Signature generation uses constant-time scalar multiplication
- Signature verification aims for constant-time but may have variable-time optimizations
- Nonce generation is constant-time (critical for ECDSA security)

**Verification:**
- RustCrypto team claims constant-time scalar multiplication
- Uses constant-time field arithmetic
- Final signature comparison should use our `ct_compare` wrapper

**Known issues:**
- Some optimizations may introduce timing variations in verification
- **Recommendation:** Use Ed25519 for new deployments (faster and provably constant-time)

---

### RSA: `rsa` (v0.9)

**Constant-time claims:** ❌ **NO** - **VULNERABLE**

**RUSTSEC-2023-0071: Marvin Attack**

The `rsa` crate is vulnerable to the Marvin Attack, a timing side-channel that can leak private key information during RSA decryption with PKCS#1 v1.5 padding.

**Vulnerability details:**
- Padding verification has timing variations
- Attacker can distinguish valid from invalid padding
- Enables Bleichenbacher's million-message attack
- Can recover plaintext or private key with enough queries

**Mitigation:**
- ⚠️  **DO NOT USE RSA** for new deployments
- Prefer Ed25519 or ECDSA instead
- If RSA is required, use RSA-PSS padding (less vulnerable than PKCS#1 v1.5)
- Implement additional blinding or delay randomization (not currently implemented)

**Status:**
- No fix available in `rsa` crate v0.9
- Upstream work in progress to implement constant-time RSA
- Expected fix timeline: Unknown

**References:**
- [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
- ["The Marvin Attack" (Hubert Kario, 2023)](https://people.redhat.com/~hkario/marvin/)

---

### AES-GCM: `aes-gcm` (v0.10)

**Constant-time claims:** ✅ **YES**

- AES encryption uses hardware AES-NI instructions when available (constant-time)
- GCM authentication uses constant-time GHASH implementation
- Tag comparison uses constant-time equality check
- Decryption time independent of tag validity

**Verification:**
- RustCrypto implementation extensively reviewed
- Uses `subtle::ConstantTimeEq` for tag verification
- Hardware AES-NI is constant-time by design

**Caveats:**
- Software AES fallback (when AES-NI not available) may have timing variations
- **Recommendation:** Deploy on hardware with AES-NI support

---

### Hash Functions: `sha2` (v0.10) and `sha3` (v0.10)

**Constant-time claims:** ✅ **YES**

- SHA-2 and SHA-3 implementations are constant-time
- No secret-dependent branches
- No table lookups with secret indices

**Note:** Hash functions don't typically need constant-time guarantees since they operate on public data. However, constant-time implementations prevent timing attacks when hashing secret data (e.g., in HMAC or password hashing).

---

## Verification Methods

We employ multiple verification techniques to ensure constant-time properties:

### 1. Statistical Timing Tests (dudect)

**Tool:** `dudect-bencher`

**Methodology:**
- Compare execution time of operations on two input classes
- Use Welch's t-test to detect timing differences
- Measure t-statistic and p-value
- Threshold: t-statistic < 4.5, p-value > 0.05

**Location:** `tests/timing_tests.rs`

**Run tests:**
```bash
cd crates/crypto-engine
cargo test --release --test timing_tests
```

**Interpretation:**
- **PASS (p > 0.05):** No statistically significant timing difference detected
- **FAIL (p ≤ 0.05):** Timing leak detected, investigate immediately

**Example output:**
```
test test_ct_compare_tags ... ok (t = 0.42, p = 0.67) ✅
test test_aes_gcm_tag_verification ... ok (t = 1.23, p = 0.22) ✅
```

---

### 2. Cache-Grind Analysis

**Tool:** Valgrind with cache-grind

**Methodology:**
- Simulate CPU cache behavior
- Track cache hits and misses
- Identify secret-dependent memory access patterns
- Detect data-dependent branch prediction

**Location:** `scripts/cache_analysis.sh`

**Run analysis:**
```bash
./scripts/cache_analysis.sh
```

**What to look for:**
- ❌ **Secret-dependent cache misses:** Table lookups with secret indices
- ❌ **Branch mispredictions on secret data:** Conditional branches on keys/plaintexts
- ✅ **Uniform cache behavior:** Cache misses independent of secret values

---

### 3. Manual Code Review

**Guidelines:**

1. **No secret-dependent branches:**
   ```rust
   // ❌ BAD: Timing depends on secret_key[0]
   if secret_key[0] == 0x42 {
       // fast path
   } else {
       // slow path
   }

   // ✅ GOOD: Constant-time selection
   let value = ct_select(condition, &option_a, &option_b);
   ```

2. **No secret-dependent array indexing:**
   ```rust
   // ❌ BAD: Lookup time depends on secret_index
   let value = lookup_table[secret_index];

   // ✅ GOOD: Constant-time access or use AES S-box with AES-NI
   ```

3. **Use constant-time comparison:**
   ```rust
   // ❌ BAD: Early return leaks position of mismatch
   for i in 0..a.len() {
       if a[i] != b[i] {
           return false;
       }
   }

   // ✅ GOOD: Constant-time comparison
   ct_compare(a, b)
   ```

4. **Mark functions as `#[inline(never)]`:**
   ```rust
   #[inline(never)] // Prevent inlining to avoid speculation
   pub fn verify_tag(expected: &[u8], received: &[u8]) -> bool {
       ct_compare(expected, received)
   }
   ```

---

### 4. Automated CI Checks

**GitHub Actions Workflow:** `.github/workflows/timing-tests.yml`

Automatically runs on every PR:
- Dudect timing tests
- Cache-grind analysis
- Clippy checks for timing vulnerabilities
- Cargo audit for known vulnerabilities

**Fails CI if:**
- Dudect tests detect timing leaks (p ≤ 0.05)
- Cache-grind finds secret-dependent cache misses
- Known timing vulnerabilities in dependencies

---

## Known Limitations

### 1. Compiler Optimizations

**Issue:** Compilers may optimize away constant-time code.

**Mitigation:**
- Use `#[inline(never)]` on timing-critical functions
- Use `subtle::ConstantTimeEq` which uses compiler barriers
- Use `zeroize` crate which prevents dead store elimination

**Verification:** Review generated assembly to ensure optimizations don't break constant-time guarantees.

---

### 2. CPU Microarchitecture

**Issue:** Speculative execution, out-of-order execution, and branch prediction can leak timing information.

**Examples:**
- **Spectre:** Speculative execution leaks data via cache
- **Meltdown:** Out-of-order execution bypasses privilege checks

**Mitigation:**
- `#[inline(never)]` reduces speculation
- Memory fences after security-critical operations
- Rely on operating system Spectre/Meltdown mitigations

**Limitation:** Cannot fully prevent microarchitectural attacks in software alone.

---

### 3. RSA Marvin Attack (RUSTSEC-2023-0071)

**Status:** ❌ **UNRESOLVED**

**Impact:** RSA with PKCS#1 v1.5 padding is vulnerable to timing attacks.

**Workaround:**
- **Avoid RSA** - Use Ed25519 or ECDSA instead
- If RSA required, use RSA-PSS (less vulnerable)
- Deploy RSA only in contexts where timing attacks are not feasible

**Long-term fix:** Awaiting constant-time RSA implementation in `rsa` crate.

---

### 4. Software AES (no AES-NI)

**Issue:** Software AES implementations may have timing variations due to table lookups.

**Mitigation:**
- Deploy on hardware with AES-NI support
- AES-NI instructions are constant-time by design

**Detection:** Check CPU flags for AES-NI support:
```bash
# Linux
grep aes /proc/cpuinfo

# macOS
sysctl machdep.cpu.features | grep AES
```

---

## Best Practices

### For HSM Operators

1. **Deploy on hardware with AES-NI** - Ensures constant-time AES
2. **Avoid RSA** - Use Ed25519 or ECDSA instead
3. **Monitor timing tests in CI** - Catch regressions early
4. **Run cache-grind periodically** - Verify constant-time properties
5. **Keep dependencies updated** - Get constant-time fixes from upstream

---

### For HSM Developers

1. **Use `ct_compare` for all secret comparisons**
2. **Use `ct_select` for conditional logic on secrets**
3. **Mark timing-critical functions `#[inline(never)]`**
4. **Use `zeroize` for all key material**
5. **Add dudect tests for new crypto operations**
6. **Review generated assembly for constant-time violations**
7. **Document constant-time assumptions and limitations**

---

### For Security Auditors

1. **Run dudect timing tests** - Verify statistical constant-time
2. **Run cache-grind analysis** - Detect cache-timing leaks
3. **Review dependencies** - Check for known timing vulnerabilities
4. **Test on target hardware** - Verify constant-time on deployment platform
5. **Review assembly output** - Ensure compiler doesn't break constant-time
6. **Test with realistic threat models** - Account for noise and measurement error

---

## References

### Academic Papers

1. **"FaCT: A DSL for Timing-Sensitive Computation"**
   Cauligi, Renner, Brown, Stefan, et al. (PLDI 2019)
   https://cseweb.ucsd.edu/~dstefan/pubs/cauligi:2017:fact.pdf

2. **"CT-Wasm: Type-Driven Secure Cryptography for WebAssembly"**
   Watt, Renner, Stefan, et al. (2018)
   https://arxiv.org/abs/1808.01348

3. **"Cache-Timing Attacks on AES"**
   Daniel J. Bernstein (2005)
   https://cr.yp.to/antiforgery/cachetiming-20050414.pdf

4. **"Dude, is my code constant time?"**
   Reparaz, Balasch, Verbauwhede (2017)
   https://eprint.iacr.org/2016/1123

5. **"The Marvin Attack"**
   Hubert Kario (2023)
   https://people.redhat.com/~hkario/marvin/

6. **"Spectre Attacks: Exploiting Speculative Execution"**
   Kocher et al. (2018)
   https://spectreattack.com/spectre.pdf

---

### Tools and Libraries

- **dudect-bencher:** https://github.com/rozbb/rust-dudect-bencher
- **subtle crate:** https://docs.rs/subtle/
- **zeroize crate:** https://docs.rs/zeroize/
- **Valgrind:** https://valgrind.org/
- **RustCrypto:** https://github.com/RustCrypto

---

### Security Advisories

- **RUSTSEC-2023-0071:** https://rustsec.org/advisories/RUSTSEC-2023-0071.html
- **RustSec Advisory Database:** https://rustsec.org/

---

## Changelog

- **2026-01-16:** Initial documentation
  - Documented constant-time functions in `constant_time` module
  - Documented library dependencies and their constant-time properties
  - Added verification methods (dudect, cache-grind)
  - Documented RSA Marvin Attack (RUSTSEC-2023-0071)
  - Added best practices for operators, developers, and auditors

---

## Contact

For security issues related to timing side-channels, please report to:
- Email: security@hsm-project.example (REPLACE WITH ACTUAL CONTACT)
- Issue tracker: https://github.com/your-org/hsm/issues (REPLACE WITH ACTUAL REPO)

For questions about constant-time implementation, contact the development team.
