---
name: hsm-coverage
description: Measure test coverage with cargo-llvm-cov for one crate or the workspace and turn uncovered security-relevant paths into concrete test suggestions.
---

# HSM test coverage

```
/hsm-coverage [crate]
```

`crate` is a directory name under `crates/`. With no argument, measure the workspace.

## Steps

1. **Tooling.** `cargo llvm-cov --version`; if missing, `cargo install cargo-llvm-cov` and `rustup component add llvm-tools-preview`.

2. **Run.** Use the same slow-test skips as `/verify`:
   ```bash
   SKIPS="--skip performance --skip throughput --skip stress --skip high_concurrency --skip large_chain --skip batch_operations --skip workload"
   # one crate
   cargo llvm-cov --manifest-path crates/<crate>/Cargo.toml --summary-only -- $SKIPS
   # workspace
   cargo llvm-cov --workspace --summary-only -- $SKIPS
   ```
   For line-level gaps, rerun with `--text --output-path target/llvm-cov.txt` (or `--html`) and read the uncovered lines for the files that matter.

3. **Target.** The spec's testing strategy (`docs/architecture/spec.md`) sets >80% coverage per module. Report each crate's line and region coverage against it.

4. **Prioritise gaps.** A percentage is not the finding; uncovered behaviour is. Rank uncovered code by risk:
   - error and rejection paths in crypto, auth, key lifecycle and storage (invalid keys, bad signatures, tampered ciphertext, expired or revoked credentials)
   - namespace and RBAC denial branches
   - zeroization and redaction paths
   - parsing of untrusted input

   Shape-only tests (constructs a value, asserts it exists) count toward the percentage while proving nothing. Suggested tests assert behaviour: known-answer vectors for crypto, an explicit rejection for every denial path.

5. **Report.** Per crate: coverage vs target, then the ranked uncovered paths as `file:line` with a named test that would cover each.
