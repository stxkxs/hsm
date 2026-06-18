# Phase 4: Code Quality & Continuous Improvement

> **STATUS: ✅ RESOLVED (7/7).** Verified 2026-06-17:
>
> | Fix | Status | Evidence |
> | --- | --- | --- |
> | 1. Remove production `println!` | ✅ | `crates/verification/src/shamir.rs` — 0 `println!`, uses `tracing` |
> | 2. Graceful server shutdown | ✅ | `crates/hsm-server/src/main.rs:147,187` — `CancellationToken` + `tokio::select!` + `shutdown_signal()` |
> | 3. StarkNet string truncation | ✅ | `crates/blockchain/src/starknet/signing.rs:294` — `felt_from_short_string` returns `Result`, errors `> 31` bytes |
> | 4. Remove blanket clippy suppressions | ✅ | All crate-root `#![allow(dead_code/unused_imports/unused_variables)]` removed (`auth`, `cluster`, `validator`, `bridge-monitor`). Rather than prune the scaffolding, the underlying features were completed: `validator` builder now honors `enable_babylon` (`service.rs`); `bridge-monitor` time-lock queue + release + config-driven maintenance loop (`policy/mod.rs`, `lib.rs`); `cluster` Raft replicated state machine in `apply_command` + `voted_for` vote-safety in `handle_request_vote` (`node.rs`). `#![deny(unsafe_code)]` retained everywhere; only stale leftover imports removed. |
> | 5. WASM allocation + fuel safety | ✅ | `crates/wasm-policy/src/engine.rs:300-333` checked `HEAP_MAX`; fuel exhaustion detected via typed `Trap::OutOfFuel` (289), regression-tested |
> | 6. Upgrade Wasmtime | ✅ | `crates/wasm-policy/Cargo.toml:11` — `wasmtime = "45"` |
> | 7. Mnemonic zeroization | ✅ | `crates/blockchain/src/bip/bip39.rs:25,151` — `Zeroize`/`ZeroizeOnDrop` + manual `Drop for Mnemonic` |

## Overview
7 quality improvements for long-term maintainability and safety.

---

## Fix 1: Remove Production println! Statements
**File:** `crates/verification/src/shamir.rs`
**Lines:** ~104-360 (29 println! statements in non-test code)

**Implementation:**
- Replace all `println!()` calls with `tracing::debug!()` or `tracing::info!()`
- Add `use tracing::{debug, info};` import if not present
- Add `tracing` to `crates/verification/Cargo.toml` if not already a dependency
- Ensure the verification functions use structured logging

---

## Fix 2: Fix Graceful Server Shutdown
**File:** `crates/hsm-server/src/main.rs`
**Lines:** 94-102 (unwraps), 110-112 (abort)

**Implementation:**
- Replace `.unwrap()` on `TcpListener::bind()` with proper error handling using `?` or `expect` with descriptive message
- Replace `.abort()` calls with graceful shutdown using `tokio::signal`:
  ```rust
  tokio::select! {
      result = &mut rest_server => { /* handle */ },
      result = &mut metrics_server => { /* handle */ },
      _ = tokio::signal::ctrl_c() => {
          info!("Shutdown signal received, draining connections...");
          rest_server.abort();  // Last resort after graceful
          metrics_server.abort();
      }
  }
  ```
- Add a graceful shutdown token using `tokio_util::sync::CancellationToken` or `tokio::sync::watch`

---

## Fix 3: Fix StarkNet String Truncation
**File:** `crates/blockchain/src/starknet/signing.rs`
**Lines:** 291-297

`felt_from_short_string` silently truncates strings >31 bytes.

**Implementation:**
- Change return type to `Result<Felt, BlockchainError>`
- Return an error for strings >31 bytes instead of silently truncating:
  ```rust
  if bytes.len() > 31 {
      return Err(BlockchainError::InvalidInput(
          format!("String exceeds maximum felt length of 31 bytes: {} bytes", bytes.len())
      ));
  }
  ```
- Update all callers to handle the Result

---

## Fix 4: Remove Blanket Clippy Suppressions
**File:** `crates/auth/src/lib.rs` (14 suppressions) and 6 other crates

**Implementation:**
- Remove all `#![allow(...)]` attributes from the top of lib.rs files
- Run `cargo clippy --all -- -D warnings` to see actual warnings
- Fix each clippy warning properly rather than suppressing
- Only add back targeted `#[allow(...)]` on specific items where justified with a comment
- Priority crates (most aggressive suppressions):
  1. `crates/auth/src/lib.rs` (14 suppressions)
  2. `crates/cluster/src/lib.rs` (4 suppressions including `clippy::all`)
  3. `crates/validator/src/lib.rs` (4 suppressions)
  4. `crates/bridge-monitor/src/lib.rs` (4 suppressions)

---

## Fix 5: Add WASM Memory Allocation Safety
**File:** `crates/wasm-policy/src/engine.rs`
**Lines:** 307-327

`alloc_pos` incremented without overflow protection.

**Implementation:**
- Use checked arithmetic: `ptr.checked_add(len).ok_or(PolicyError::MemoryLimitExceeded { ... })?`
- Add a `HEAP_MAX` constant (e.g., 16MB) and validate against it
- Validate `data.len()` fits in `i32` before casting
- Add unit test for large allocation that would overflow i32

Also fix fuel detection (line ~284):
- Replace string-based error detection `e.to_string().contains("fuel")` with proper wasmtime fuel API:
  ```rust
  let remaining = store.get_fuel().unwrap_or(0);
  if remaining == 0 {
      return Err(PolicyError::GasLimitExceeded { ... });
  }
  ```

---

## Fix 6: Upgrade Wasmtime
**File:** `crates/wasm-policy/Cargo.toml`

Current version: `wasmtime = "27"` — has RUSTSEC-2026-0020 and RUSTSEC-2026-0021.

**Implementation:**
- Upgrade to latest patched wasmtime version
- Check `cargo audit` for the exact minimum safe version
- Update any API changes required by the new version
- Run wasm-policy tests to verify compatibility

---

## Fix 7: Add Mnemonic Zeroization
**File:** `crates/blockchain/src/bip/bip39.rs`
**Lines:** 137-140

Mnemonic struct derives `Clone` but not `ZeroizeOnDrop`.

**Implementation:**
- Add `Zeroize` and `ZeroizeOnDrop` derives (note: `SecretString` already handles its own zeroization, but the struct wrapper should also be explicit)
- If `Zeroize` can't be derived due to `SecretString`/`Language` types, implement it manually:
  ```rust
  impl Drop for Mnemonic {
      fn drop(&mut self) {
          self.word_count = 0;
          // SecretString handles its own zeroization
      }
  }
  ```
- Consider removing the `Clone` derive to prevent unnecessary copies of mnemonic data

---

## Verification
```bash
cargo check --all
cargo test --all
cargo clippy --all -- -D warnings
cargo audit
```
