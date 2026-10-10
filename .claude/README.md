# Claude Code configuration

Project skills and settings for Claude Code in this repository.

## Skills

Each skill lives in `skills/<name>/SKILL.md` and runs as `/<name>`.

| Skill | Use it to |
|---|---|
| `/verify` | Run the checks CI runs (fmt, clippy including feature-gated builds, tests, docs, and the UI/SDK suites a change touches). Run before every commit. |
| `/hsm-module <crate>` | Orient on one crate under `crates/`: purpose, dependents, history, health. |
| `/hsm-bench [crate]` | Run Criterion benchmarks and compare against the performance targets in `docs/architecture/spec.md`. |
| `/hsm-coverage [crate]` | Measure coverage with cargo-llvm-cov and turn uncovered security-relevant paths into test suggestions. |
| `/hsm-fuzz <crate> [runs]` | Run cargo-fuzz targets (nightly) for a crate with a `fuzz/` workspace and triage crashes. |
| `/hsm-security [crate]` | Audit advisories on every dependency surface under the CI policy, then check constant-time comparison, zeroization, redaction, unsafe usage and input validation. |
| `/hsm-deps` | Dependency maintenance pass: triage Dependabot PRs and alerts, update and audit every surface, keep `.github/dependabot.yml` and MSRV references consistent, land one PR. |

`<crate>` is always a directory name under `crates/`.

## Hooks

`settings.json` runs `cargo fmt` on any `.rs` file after Claude writes or edits it.
