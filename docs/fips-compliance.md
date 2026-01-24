# FIPS 140-3 Compliance

HSM includes a FIPS 140-3 validation-ready cryptographic module for regulated environments.

## Overview

FIPS 140-3 is the U.S. government standard for cryptographic modules. When FIPS mode is enabled:

- Only NIST-approved algorithms are available
- Power-on self-tests (POST) run at startup
- Continuous RNG health monitoring is active
- All cryptographic operations are audit logged

## Enabling FIPS Mode

### Environment Variable

```bash
HSM_FIPS_MODE=true hsm-server
```

### Configuration File

```toml
[fips]
enabled = true
```

### Programmatic

```rust
use hsm_crypto_engine::fips::FipsMode;

let fips = FipsMode::initialize()?;
assert!(fips.is_enabled());
assert!(fips.self_test_passed());
```

## Approved Algorithms

### Symmetric Encryption

| Algorithm | Key Sizes | Standard |
|-----------|-----------|----------|
| AES-GCM | 128, 192, 256 | SP 800-38D |
| AES-CBC | 128, 192, 256 | SP 800-38A |
| AES-CTR | 128, 192, 256 | SP 800-38A |

### Hash Functions

| Algorithm | Output Size | Standard |
|-----------|-------------|----------|
| SHA-256 | 256 bits | FIPS 180-4 |
| SHA-384 | 384 bits | FIPS 180-4 |
| SHA-512 | 512 bits | FIPS 180-4 |
| SHA-512/256 | 256 bits | FIPS 180-4 |
| SHA3-256 | 256 bits | FIPS 202 |
| SHA3-384 | 384 bits | FIPS 202 |
| SHA3-512 | 512 bits | FIPS 202 |
| SHAKE128 | variable | FIPS 202 |
| SHAKE256 | variable | FIPS 202 |

### Digital Signatures

| Algorithm | Key Sizes | Standard |
|-----------|-----------|----------|
| RSA | 2048, 3072, 4096 | FIPS 186-5 |
| ECDSA P-256 | 256 bits | FIPS 186-5 |
| ECDSA P-384 | 384 bits | FIPS 186-5 |
| ECDSA P-521 | 521 bits | FIPS 186-5 |
| Ed25519 | 256 bits | FIPS 186-5 |
| Ed448 | 448 bits | FIPS 186-5 |

### Message Authentication

| Algorithm | Standard |
|-----------|----------|
| HMAC-SHA256 | FIPS 198-1 |
| HMAC-SHA384 | FIPS 198-1 |
| HMAC-SHA512 | FIPS 198-1 |
| CMAC-AES | SP 800-38B |

### Key Derivation

| Algorithm | Standard |
|-----------|----------|
| HKDF | SP 800-56C |
| PBKDF2 | SP 800-132 |
| SP800-108 KDF | SP 800-108 |

### Key Agreement

| Algorithm | Standard |
|-----------|----------|
| ECDH P-256 | SP 800-56A |
| ECDH P-384 | SP 800-56A |
| ECDH P-521 | SP 800-56A |
| X25519 | SP 800-186 |
| X448 | SP 800-186 |
| DH | SP 800-56A |

### Random Number Generation

| Algorithm | Standard |
|-----------|----------|
| HMAC_DRBG | SP 800-90A |
| CTR_DRBG | SP 800-90A |
| Hash_DRBG | SP 800-90A |

## Non-Approved Algorithms

These algorithms are **not available** in FIPS mode:

- ChaCha20 / ChaCha20-Poly1305
- BLAKE2 / BLAKE3
- secp256k1 (Bitcoin/Ethereum curve)
- BLS12-381
- Argon2 / scrypt
- SHA-1 (except signature verification)

## Verification-Only Algorithms

SHA-1 is approved only for signature verification (legacy compatibility):

```rust
// allowed - verifying old signatures
fips.require_for_operation(Algorithm::Sha1, true)?;  // for_verification = true

// rejected - creating new signatures
fips.require_for_operation(Algorithm::Sha1, false)?; // error!
```

## Self-Tests

### Power-On Self-Tests (POST)

Run automatically at startup:

| Test | Description |
|------|-------------|
| AES-256-GCM KAT | encrypt/decrypt round-trip |
| SHA-256 KAT | known answer test |
| SHA-384 KAT | known answer test |
| SHA-512 KAT | known answer test |
| HMAC-SHA256 KAT | mac generation and verification |
| DRBG health | continuous output test |

### Conditional Self-Tests

Triggered on-demand or after errors:

```rust
fips.run_conditional_test()?;
```

### Continuous RNG Testing

The DRBG performs continuous health checks:

- Consecutive outputs must differ
- Automatic reseeding at 2^20 requests
- Health check failure enters error state

## Module Integrity

On startup, the module verifies its own integrity:

```rust
use hsm_crypto_engine::fips::IntegrityChecker;

let checker = IntegrityChecker::new();
let result = checker.verify()?;
assert!(result.passed);
```

For production FIPS validation, embed the expected HMAC at build time:

```rust
let checker = IntegrityChecker::new()
    .with_expected_hmac(EMBEDDED_HMAC);
```

## Audit Logging

All cryptographic operations are logged in FIPS mode:

```rust
use hsm_crypto_engine::fips::{FipsAuditLog, FipsAuditEventType};

let log = FipsAuditLog::new();

// events are logged automatically, or manually:
log.log_success(FipsAuditEventType::KeyGeneration, Some("AES-256"));
log.log_failure(FipsAuditEventType::AlgorithmNotApproved, "ChaCha20 rejected");

// export for compliance
let json = log.export_json()?;
```

### Event Types

| Category | Events |
|----------|--------|
| Module Lifecycle | init start/complete/failed, shutdown |
| Self-Tests | start, passed, failed, conditional |
| Integrity | check start/passed/failed |
| DRBG | instantiate, reseed, generate, health failed |
| Crypto Operations | key gen/destroy/import/export, encrypt/decrypt, sign/verify |
| Security | algorithm rejected, key length rejected, access denied, error state |

### Security-Critical Events

These events indicate potential security issues:

- `SelfTestFailed`
- `IntegrityCheckFailed`
- `DrbgHealthFailed`
- `AlgorithmNotApproved`
- `AuthenticationFailure`
- `ErrorStateEntered`

## Error Handling

When FIPS mode detects a problem, it enters an error state:

```rust
// check status
match fips.status() {
    FipsStatus::Operational => { /* normal */ }
    FipsStatus::SelfTestFailed => { /* POST failed */ }
    FipsStatus::Error => {
        let msg = fips.error_message();
        // module is non-operational
    }
}
```

Recovery requires reinitialization:

```rust
let fips = FipsMode::initialize()?; // runs POST again
```

## API Usage

### Check Algorithm Approval

```rust
use hsm_crypto_engine::fips::{FipsMode, Algorithm};

let fips = FipsMode::initialize()?;

// check if approved
if fips.is_approved(Algorithm::Aes256) {
    // use it
}

// or require it (returns error if not approved)
fips.require_approved(Algorithm::Aes256)?;

// check for specific operation
fips.require_for_operation(Algorithm::Sha1, true)?; // verification only
```

### Validate Key Length

```rust
// ensure key meets FIPS requirements
fips.validate_key_length(Algorithm::Rsa2048, 2048)?; // ok
fips.validate_key_length(Algorithm::Rsa2048, 1024)?; // error!
```

### Generate Random Numbers

```rust
// use FIPS DRBG
let mut random_bytes = [0u8; 32];
fips.generate_random(&mut random_bytes)?;
```

## Certification Status

This module is designed to be **FIPS 140-3 validation-ready**. Formal CMVP certification requires:

1. Submission to accredited testing laboratory
2. Cryptographic algorithm validation (CAVP)
3. Module validation testing
4. CMVP review and certificate issuance

Current status: **not yet submitted for validation**

For environments requiring certified modules today, consider using HSM with a hardware backend that has existing FIPS certification.

## References

- [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final)
- [SP 800-140C: CMVP Approved Security Functions](https://csrc.nist.gov/publications/detail/sp/800-140c/final)
- [CAVP Algorithm Validation](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
- [CMVP Validated Modules](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules)
