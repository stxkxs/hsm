# Phase 3: Production Hardening

> **STATUS: ✅ RESOLVED.** All 7 fixes below are implemented. Retained as a
> historical hardening record, not an open work list. Verified 2026-06-17:
>
> | Fix | Implemented in |
> | --- | --- |
> | 1. Webhook circuit breaker | `crates/webhooks/src/delivery.rs:67` — `CircuitState` + `is_circuit_open` (130), threshold 5 |
> | 2. Composite rate-limit key | `crates/auth/src/rate_limit.rs:90` — keyed on `common_name:serial_number` |
> | 3. Token-bound session validation | `crates/auth/src/session/manager.rs:583` — `validate_session` `#[deprecated]`; `validate_session_with_token` (609); `generate_session_id` uses `getrandom` (`session_data.rs:259`) |
> | 4. Journal stores ciphertext only | `crates/storage/src/journal.rs:125,135` — `StoreKey.data` documented + enforced as pre-encrypted |
> | 5. Path-traversal protection | `crates/storage/src/encrypted_fs.rs:301` — `validate_path_component` rejects `/`,`\`,`..`,NUL on namespace + key id |
> | 6. Atomic key deletion | `crates/key-manager/src/lib.rs:443` — store delete first, then mark destroyed |
> | 7. Namespace check on cache hit | `crates/key-manager/src/store.rs:64` — hot-cache hit re-verifies namespace, errors `NamespaceViolation` |

## Overview
7 medium-severity fixes that were resolved for production-grade resilience.

---

## Fix 1: Add Circuit Breaker to Webhook Retries
**File:** `crates/webhooks/src/delivery.rs`
**Lines:** 146-187

No circuit breaker — failing endpoints get infinite retries.

**Implementation:**
- Add a `CircuitBreaker` using `DashMap<String, CircuitState>` to track per-URL failure counts
- `CircuitState` struct: `{ consecutive_failures: u32, last_failure: DateTime<Utc>, state: Open|Closed|HalfOpen }`
- Before delivering, check if circuit is open for the URL:
  - If open and cooldown period hasn't elapsed: return `DeliveryStatus::CircuitOpen` immediately
  - If open and cooldown elapsed: transition to half-open, allow one attempt
  - On success: reset to closed
  - On failure: increment counter, open circuit after threshold (e.g., 5 consecutive failures)
- Add `circuit_breaker_threshold: u32` and `circuit_breaker_cooldown: Duration` to delivery config
- Store the breaker in `DeliveryManager` struct

---

## Fix 2: Enhance Rate Limiting with IP + Certificate Serial
**File:** `crates/auth/src/rate_limit.rs`
**Lines:** 88-92

Only uses `identity.common_name` as rate limit key.

**Implementation:**
- Create a composite rate limit key: `format!("{}:{}", identity.common_name, identity.serial_number)`
- This ensures different certificates with the same CN are rate-limited separately
- Add an optional IP-based rate limiter as a separate layer (if `peer_addr` is available in identity)
- Keep the existing global and per-namespace limiters unchanged

---

## Fix 3: Deprecate Token-less Session Validation
**File:** `crates/auth/src/session.rs`
**Lines:** 1302-1316

`validate_session(session_id)` doesn't verify the session token — session fixation risk.

**Implementation:**
- Add `#[deprecated(note = "Use validate_session_with_token for security")]` to `validate_session`
- In the method body, log a warning: `warn!("validate_session called without token verification")`
- Update all callers in the codebase to use `validate_session_with_token` instead
- Search for callers in: `grpc-api/src/middleware/auth.rs`, `rest-api/src/middleware.rs`

Also fix `generate_session_id()` (line 690-699):
- Replace `rand::thread_rng()` with `rand::rngs::OsRng`
- This provides guaranteed OS-level entropy

---

## Fix 4: Encrypt Journal Entries
**File:** `crates/storage/src/journal.rs`
**Lines:** 122-136

`JournalOp::StoreKey` contains plaintext `data: Vec<u8>`.

**Implementation:**
- The data stored in journal entries should already be encrypted before reaching the journal
- Verify that `store_key_impl` encrypts data BEFORE passing to the journal
- If not, add encryption in the journal write path:
  - Accept `MasterKeyManager` reference in `WriteAheadJournal`
  - Encrypt the `data` field when writing `StoreKey` ops
  - Decrypt when replaying the journal on recovery
- Add a comment documenting that journal data is encrypted

---

## Fix 5: Add Path Traversal Protection
**File:** `crates/storage/src/encrypted_fs.rs`
**Lines:** 284-287

`get_key_file_path` uses `key_id` directly in path construction without sanitization.

**Implementation:**
- Add validation to reject key IDs containing path separators or parent directory references:
  ```rust
  fn validate_path_component(s: &str) -> StorageResult<()> {
      if s.contains('/') || s.contains('\\') || s.contains("..") || s.contains('\0') {
          return Err(StorageError::InvalidPath(
              "Path component contains invalid characters".to_string(),
          ));
      }
      Ok(())
  }
  ```
- Call validation in `get_key_file_path` for both `namespace` and `key_id`
- Also apply to `get_meta_file_path`, `get_namespace_path`

---

## Fix 6: Make Key Deletion Atomic
**File:** `crates/key-manager/src/lib.rs`
**Lines:** 442-451

State update and store deletion are separate operations — partial failure leaves inconsistent state.

**Implementation:**
- Reverse the order: delete from store first, then update state
- Or better: use the journal/WAL for atomicity:
  1. Write a delete intent to the journal
  2. Delete from store
  3. Mark state as destroyed
  4. Commit journal entry
- If any step fails after journal write, the journal replay will complete the operation
- Add error handling that rolls back if the second operation fails

---

## Fix 7: Add Namespace Verification on Cache Hits
**File:** `crates/key-manager/src/store.rs`
**Lines:** 58-63

Hot cache returns keys without re-verifying namespace ownership.

**Implementation:**
- After getting from hot cache, verify the namespace field matches:
  ```rust
  if let Some(key) = cache.get(&composite_key) {
      if key.namespace != namespace {
          return Err(crate::Error::NamespaceViolation {
              expected: namespace.to_string(),
              actual: key.namespace.clone(),
          });
      }
      return Ok(key.clone());
  }
  ```
- This adds a trivial check that prevents cached keys from crossing namespace boundaries

---

## Verification
```bash
cargo check --all
cargo test --all
cargo clippy --all -- -D warnings
```
