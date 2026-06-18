# Phase 2: Pre-Release Security Fixes

> **STATUS: ✅ RESOLVED.** All 8 fixes below are implemented. Retained as a
> historical hardening record, not an open work list. Verified 2026-06-17:
>
> | Fix | Implemented in |
> | --- | --- |
> | 1. RBAC roles from cert extensions | `crates/auth/src/mtls/authenticator.rs:277` — `extract_roles` reads OID `1.3.6.1.4.1.99999.1`, CN only as logged fallback |
> | 2. Webhook anti-SSRF URL validation | `crates/webhooks/src/config.rs:112` — `validate_url` requires https; `is_private_ip` (144) rejects loopback/link-local/private ranges |
> | 3. RSA blind-signature constant-time compare | `crates/crypto-engine/src/blind/rsa_blind.rs:252` — `ct_eq` over key-size-padded bytes |
> | 4. Secure file deletion | `crates/storage/src/encrypted_fs.rs:387` — overwrite with random bytes + `sync`, then remove |
> | 5. Backup password strength | `crates/backup/src/export.rs:70` — rejects `< 16` bytes with `WeakPassword` |
> | 6. Redacted `SecretValue` Debug | `crates/secrets/src/secret.rs:275` — manual `Debug` prints `<redacted>` |
> | 7. Reject wildcard CORS | `crates/grpc-api/src/grpc_web.rs:103` — `validate` errors on `*` origin |
> | 8. KMIP error sanitization | `crates/kmip-server/src/server.rs:165` — generic "Invalid message format"; detail only in `warn!` |

## Overview
8 high-severity fixes that were resolved before public release.

---

## Fix 1: Move RBAC Roles from CN to Certificate Extensions
**File:** `crates/auth/src/mtls/authenticator.rs`
**Lines:** 268-293 (extract_roles function)

Currently uses `common_name.contains("admin")` string matching. Attacker can request cert with CN "admin-user" and get admin role.

**Implementation:**
- Check for a custom X.509 extension OID (e.g., `1.3.6.1.4.1.99999.1` for roles)
- Parse the extension value as a comma-separated list of role names
- Fall back to `Role::User` if no extension is present
- Remove all CN-based string matching
- Add the X.509 extension parsing using `x509-parser`'s extension iteration API
- Log a warning if a certificate has no role extension

---

## Fix 2: Add Webhook URL Validation (Anti-SSRF)
**File:** `crates/webhooks/src/config.rs`
**Lines:** Add validation in the `WebhookConfig` validate method

Currently no URL validation — accepts HTTP, private IPs, metadata endpoints.

**Implementation:**
- Add a `validate_url()` method to `WebhookConfig`
- Require HTTPS scheme (reject `http://`)
- Parse the URL hostname and resolve to IP
- Reject private IP ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Reject loopback: `127.0.0.0/8`, `::1`
- Reject link-local: `169.254.0.0/16` (cloud metadata services)
- Reject `0.0.0.0`
- Use the `url` crate (add to Cargo.toml) for URL parsing
- Call validation in webhook registration

---

## Fix 3: Fix RSA Blind Signature Timing Vulnerability
**File:** `crates/crypto-engine/src/blind/rsa_blind.rs`
**Line:** 252

`Ok(m_recovered == m_expected_int)` uses non-constant-time BigUint comparison.

**Implementation:**
- Convert both `BigUint` values to fixed-length byte arrays (padded to key size)
- Use `subtle::ConstantTimeEq` for comparison:
  ```rust
  let recovered_bytes = m_recovered.to_bytes_be();
  let expected_bytes = m_expected_int.to_bytes_be();
  // Pad to same length
  let max_len = std::cmp::max(recovered_bytes.len(), expected_bytes.len());
  let mut a = vec![0u8; max_len];
  let mut b = vec![0u8; max_len];
  a[max_len - recovered_bytes.len()..].copy_from_slice(&recovered_bytes);
  b[max_len - expected_bytes.len()..].copy_from_slice(&expected_bytes);
  Ok(a.ct_eq(&b).into())
  ```

---

## Fix 4: Implement Secure File Deletion
**File:** `crates/storage/src/encrypted_fs.rs`
**Lines:** 327-340 (delete_key_impl)

Currently uses `fs::remove_file()` — data recoverable from disk.

**Implementation:**
- Add a `secure_delete()` helper function:
  1. Open the file for writing
  2. Get file size from metadata
  3. Overwrite with random bytes (1 pass is sufficient for modern drives)
  4. `sync_all()` to flush to disk
  5. Then `fs::remove_file()`
- Apply to both key file and metadata file paths
- Handle errors gracefully (if overwrite fails, still try to remove)

---

## Fix 5: Strengthen Backup Password Validation
**File:** `crates/backup/src/export.rs`
**Lines:** 68-71

Only checks `password.is_empty()`. A single character is accepted.

**Implementation:**
- Require minimum 16 bytes (128 bits of entropy)
- Add descriptive error message: "Password must be at least 16 bytes"
- Consider adding optional entropy estimation
- Update `BackupError::WeakPassword` to include a message field if needed

---

## Fix 6: Redact SecretValue Debug Output
**File:** `crates/secrets/src/secret.rs`
**Line:** 264

`#[derive(Debug, ...)]` on `SecretValue` exposes secret contents via `{:?}` formatting.

**Implementation:**
- Remove `Debug` from the derive macro
- Add manual `fmt::Debug` implementation:
  ```rust
  impl fmt::Debug for SecretValue {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
          match self {
              SecretValue::String(_) => f.write_str("SecretValue::String(<redacted>)"),
              SecretValue::Binary(_) => f.write_str("SecretValue::Binary(<redacted>)"),
              SecretValue::Json(_) => f.write_str("SecretValue::Json(<redacted>)"),
          }
      }
  }
  ```

---

## Fix 7: Reject Wildcard CORS in Production
**File:** `crates/grpc-api/src/grpc_web.rs`
**Lines:** 102-107 (validate method)

Currently allows wildcard CORS origins with only a warning.

**Implementation:**
- Change the validation to return an error for wildcard origins when TLS is configured (production indicator)
- Or add a `allow_wildcard_cors: bool` config option that defaults to `false`
- Return `Err("Wildcard CORS origins not allowed in production".to_string())` when wildcards detected and not explicitly allowed

---

## Fix 8: KMIP Error Message Sanitization
**File:** `crates/kmip-server/src/server.rs`
**Lines:** 160-171

Error response includes internal decoder details: `format!("TTLV decode error: {}", e)`

**Implementation:**
- Replace detailed error message with generic: `"Invalid message format"`
- Keep the detailed error in the `warn!()` log (internal only)
- Apply same pattern to all error responses in the KMIP handler

---

## Verification
```bash
cargo check --all
cargo test --all
cargo clippy --all -- -D warnings
```
