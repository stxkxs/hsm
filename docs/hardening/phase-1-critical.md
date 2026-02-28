# Phase 1: Critical Security Fixes (Block Production Deploy)

## Overview
8 critical fixes that must be resolved before any production deployment.

---

## Fix 1: Implement JWT Signature Verification
**File:** `crates/auth/src/oidc/jwt.rs`
**Lines:** 153-178

Replace the two stub methods `verify_rsa_signature` and `verify_ec_signature` that currently return `Ok(())` unconditionally.

**Implementation:**
- Use `rsa` crate (already in workspace) for RS256/RS384/RS512
- Use `p256`/`p384` crates (already in workspace) for ES256/ES384
- Parse JWK `n`/`e` (RSA) or `x`/`y` (EC) parameters from the JWK JSON
- Verify actual cryptographic signatures against the parsed public key
- Add proper error handling for malformed JWK parameters

**Dependencies available:** `rsa = "0.9"`, `p256 = "0.13"`, `p384 = "0.13"`, `sha2 = "0.10"`, `base64 = "0.22"`

---

## Fix 2: Implement mTLS Certificate Signature Verification
**File:** `crates/auth/src/mtls/cert_validator.rs`
**Lines:** 271-282 (verify_signature method)

Currently only checks `client_issuer != ca_subject` (name match) but doesn't verify the actual cryptographic signature.

**Implementation:**
- Use `ring` crate (already in workspace) or `x509-parser`'s built-in verification
- Extract the signature algorithm OID from the certificate
- Extract the CA's public key from the CA certificate
- Verify the client certificate's signature using the CA's public key
- Support RSA (PKCS1v15, PSS) and ECDSA (P-256, P-384) signature algorithms

**Dependencies available:** `ring = "0.17"`, `x509-parser` (already used for parsing)

---

## Fix 3: Implement PKCS#11 PIN Validation
**File:** `crates/pkcs11-bridge/src/session.rs`
**Lines:** 157-184

Currently `_pin` parameter is ignored and a hardcoded `"placeholder_token"` is used.

**Implementation:**
- Accept PIN as `&[u8]`, hash it with SHA-256 for comparison
- Store expected PIN hash in the session's `TokenInfo` or via the HSM client
- Validate PIN against expected hash using constant-time comparison (`subtle::ConstantTimeEq`)
- Implement PIN retry limiting (max 3 attempts, then lock)
- Track failed attempts and return `CKR_PIN_INCORRECT` on failure
- Return `CKR_PIN_LOCKED` after max attempts exceeded
- Add a `pin_attempts_remaining` field to the session struct

---

## Fix 4: Guard Dev Mode Auth Bypass
**File:** `crates/grpc-api/src/middleware/auth.rs`
**Lines:** 48-58

Dev mode returns hardcoded `Role::Admin` identity when `auth_service` is `None`.

**Implementation:**
- Wrap the dev mode code path in `#[cfg(debug_assertions)]`
- In release mode, return `ApiError::AuthenticationFailed("Auth service not configured")` when `auth_service` is `None`
- Apply same treatment to `authorize()` (line 91-95) and `authorize_key_access()` (line 109)
- Log a CRITICAL-level warning at startup if auth is disabled

---

## Fix 5: Guard REST API Dev Login Endpoint
**File:** `crates/rest-api/src/routes.rs`
**Line:** 20

The `/auth/dev-login` route is mounted unconditionally in production.

**Implementation:**
- Wrap the dev-login route registration in `#[cfg(debug_assertions)]`
- In release builds, this endpoint will simply not exist (404)
- Alternative: check a runtime config flag `enable_dev_login: bool` and only mount if true

---

## Fix 6: Fix Ethereum Transaction Hash Bug
**File:** `crates/blockchain/src/ethereum/transaction.rs`
**Line:** 102

`Keccak256::digest(&items).into()` hashes the wrong buffer.

**Fix:**
Change `Keccak256::digest(&items).into()` to `Keccak256::digest(&buf).into()`

The `buf` variable contains the RLP-encoded list; `items` contains only the individual field encodings.

---

## Fix 7: Propagate Validator DB Write Errors
**File:** `crates/validator/src/slashing_db.rs`
**Lines:** 493, 619

`let _ = self.update_validator_data(&validator_data);` silently discards errors.

**Fix:**
- Replace `let _ =` with proper error propagation using `?`
- At line 493: `self.update_validator_data(&validator_data).map_err(|e| SlashingError::DatabaseError(format!("Failed to persist validator data: {}", e)))?;`
- At line 619: Same fix
- This ensures that if the DB write fails, the operation returns an error instead of silently proceeding

---

## Fix 8: Set Restrictive File Permissions on Storage Files
**File:** `crates/storage/src/encrypted_fs.rs`
**Lines:** 310-312 and 319-321

`File::create()` uses default umask, potentially creating world-readable files.

**Implementation:**
- Add `#[cfg(unix)]` block using `std::os::unix::fs::OpenOptionsExt`
- Replace `File::create(&key_path)` with:
  ```rust
  OpenOptions::new()
      .create(true)
      .write(true)
      .truncate(true)
      .mode(0o600)
      .open(&key_path)?
  ```
- Apply same fix to metadata file creation (line 319)
- For non-Unix platforms, fall back to `File::create()` with a warning log

---

## Verification
After implementing all fixes:
```bash
cargo check --all
cargo test --all
cargo clippy --all -- -D warnings
```
