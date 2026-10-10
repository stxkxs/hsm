# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Production-grade software HSM in Rust for Kubernetes. 23 crates in `crates/`, one workspace.

## Build requirements

System dependencies: `protobuf-compiler`, `libz3-dev`, `libclang-dev`. MSRV is Rust 1.97 (pinned in `rust-toolchain.toml`, the CI `msrv` job, and the `Dockerfile` builder image; required by the aws-sdk-* stack and wasmtime 47).

## Commands

```bash
cargo check --all                                  # fast compile check
cargo test --all -- --skip performance --skip throughput --skip stress --skip high_concurrency --skip large_chain --skip batch_operations --skip workload  # tests (skip slow ones)
cargo clippy --all -- -D warnings                  # lint (warnings are errors)
cargo fmt --all                                    # format
cargo doc --no-deps --all                          # docs (should produce zero warnings)
cargo audit --deny unsound                         # security audit, CI policy (ignores: .cargo/audit.toml + ci.yml)
cargo bench --all                                  # benchmarks (Criterion)
```

## Code conventions

- Every crate root carries `#![deny(unsafe_code)]` except `crypto-engine`, `pkcs11-bridge` and `hardware-backend`.
- Commit messages use conventional prefixes: `fix:`, `feat:`, `security:`, `style:`, `docs:`, etc.
- Security first: constant-time operations (`subtle`), memory zeroization (`zeroize`), secret redaction (`secrecy`). Never log key material.

## Architecture references

- Full specification: @docs/architecture/spec.md

## Module-specific CLAUDE.md

Subdirectory CLAUDE.md files can be added under any `crates/<module>/` for module-specific instructions — they load automatically when working in that directory.
