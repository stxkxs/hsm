---
name: hsm-module
description: Orient on one HSM crate — what it does, what depends on it, its recent history and health — then explore, implement, test or benchmark it.
---

# HSM module helper

```
/hsm-module <crate>
```

`crate` is a directory name under `crates/`; `ls crates` lists them. Package names are in each crate's `Cargo.toml` (`grep -h '^name' crates/*/Cargo.toml`). The module descriptions in `docs/architecture/spec.md` ("Module Breakdown") describe the core crates; the crate's own `README.md` and `src/lib.rs` doc comment describe the rest.

## Orient

1. **Purpose:** the crate's `README.md` (if present) and the `//!` doc comment in `src/lib.rs`.
2. **Position in the graph:**
   - what it depends on: `cargo tree -p <package> --depth 1 -e normal`
   - what depends on it: `cargo tree -i <package> --depth 1 -e normal`
3. **Recent history:** `git log -10 --oneline -- crates/<crate>`
4. **Health:** `cargo clippy -p <package> --all-targets -- -D warnings` and `cargo test -p <package>`.
5. **Features:** the `[features]` table in its `Cargo.toml`. Non-default features are not built by `cargo test --all`; name the ones relevant to the task.
6. **Unsafe policy:** every crate carries `#![deny(unsafe_code)]` except those listed in `CLAUDE.md`; keep it that way.

Then offer: explain the code, implement a change, run tests, run benchmarks (`/hsm-bench <crate>`), coverage (`/hsm-coverage <crate>`), fuzzing (`/hsm-fuzz <crate>` where a `fuzz/` directory exists), or a security pass (`/hsm-security <crate>`).

## Working in a crate

- Finish with `/verify`; it runs the feature-gated builds a single-crate test misses.
- A change to a public type or function: check the reverse dependencies from step 2 still build.
