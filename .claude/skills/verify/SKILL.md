---
name: verify
description: Run the same checks CI runs — fmt, clippy (including feature-gated builds), tests (skipping slow ones), docs, plus the UI and SDK suites for any surface the change touches. Use after making changes and before every commit.
---

Run the steps in order and stop on the first failure. Report pass/fail per step; on failure, diagnose the cause and propose a fix.

## Rust workspace (always)

System dependencies: `protobuf-compiler`, `z3`, `libclang`.

1. `cargo fmt --all -- --check`
2. `cargo clippy --all --all-targets -- -D warnings`
3. Feature-gated builds CI runs:
   ```bash
   cargo clippy -p hsm-blockchain --features experimental-chains --all-targets -- -D warnings
   cargo test -p hsm-blockchain --features experimental-chains
   cargo clippy -p hsm-key-manager --features hardware --all-targets -- -D warnings
   cargo test -p hsm-key-manager --features hardware
   ```
4. Feature CI does not build. Run it when the change touches `crates/hardware-backend` or any dependency it uses:
   `cargo clippy -p hsm-hardware-backend --features aws-nitro -- -D warnings`
5. `cargo test --all -- --skip performance --skip throughput --skip stress --skip high_concurrency --skip large_chain --skip batch_operations --skip workload`
6. `RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --all`

## Other surfaces (when the change touches them)

Each block mirrors its CI job in `.github/workflows/ci.yml`. Run from the directory shown.

| Directory | Commands |
|---|---|
| `ui` | `npm ci && npm run lint && npm run type-check && npm run build`, plus `npx tsc --noEmit -p cypress/tsconfig.json` when `cypress/` or the cypress version changes |
| `sdks/typescript` | `npm ci && npm run lint && npm run typecheck && npm run build && npm test` |
| `sdks/rust` | `cargo clippy --all-targets -- -D warnings && cargo test && cargo fmt --check` |
| `sdks/go` | `go build ./... && go vet ./... && test -z "$(gofmt -l .)" && go test -race ./...` |
| `sdks/python` | `ruff check . && ruff format --check hsm_client tests && mypy . && pytest -q` |

`sdks/rust` is excluded from the root workspace, so the Rust steps above do not cover it.

UI lint warnings from `react-hooks/set-state-in-effect` are configured as warnings, not errors. Cypress e2e (`npm run test:e2e`) needs a browser and a running app and is not part of this check; say so when a change touches `ui/cypress`.
