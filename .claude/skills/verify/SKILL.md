---
name: verify
description: Run full verification suite — compile check, clippy, tests (skipping slow ones), and doc warnings. Use after making changes to confirm everything is clean.
---

Run the following commands in sequence, stopping on first failure:

1. `cargo check --all`
2. `cargo clippy --all -- -D warnings`
3. `cargo test --all -- --skip performance --skip throughput --skip stress --skip high_concurrency --skip large_chain --skip batch_operations --skip workload`
4. `cargo doc --no-deps --all 2>&1 | grep "^warning"` (should produce no output)

Report results as pass/fail for each step. If any step fails, diagnose the issue and suggest a fix.
