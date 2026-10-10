---
name: hsm-security
description: Security verification for the HSM — advisories on every dependency surface under the repo's CI policy, then code checks for constant-time comparison, zeroization, secret redaction, unsafe usage and input validation. Optionally scoped to one crate.
---

# HSM security audit

```
/hsm-security [crate]
```

With a `crate` (directory under `crates/`), part 1 still runs workspace-wide (advisories are per lockfile) and part 2 is scoped to that crate.

## Part 1 — dependency advisories

**Policy (the CI `security` job):** `cargo audit --deny unsound` with the `--ignore` flags in `.github/workflows/ci.yml`, plus the ignores in `.cargo/audit.toml`. Vulnerabilities and unsound advisories fail; unmaintained and yanked notices are reported, not failed. Every ignore carries a reason; an ignore whose crate has left `Cargo.lock` is removed, not kept.

Run each surface and collect findings:

| Surface | Command |
|---|---|
| root workspace | `cargo audit --deny unsound` (reads `.cargo/audit.toml`; add the CI `--ignore` flags to match CI exactly) |
| `sdks/rust` (lockfile gitignored, as for a library) | `cargo update && cargo audit` in `sdks/rust` |
| `crates/*/fuzz` (lockfile not committed) | `cargo generate-lockfile && cargo audit` in each `fuzz/` directory, then delete the generated `Cargo.lock`; advisories accepted in `.cargo/audit.toml` apply here too |
| `ui`, `sdks/typescript` | `npm audit` |
| `sdks/go` | `govulncheck ./...` |
| `sdks/python` | `pip-audit` (`pip install pip-audit`) in an environment built with `pip install -e '.[dev]'` |
| GitHub | `gh api 'repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100' --jq '.[] \| "\(.security_advisory.severity) \(.dependency.package.name) \(.dependency.manifest_path) fix>=\(.security_vulnerability.first_patched_version.identifier)"'` |

For every Rust advisory, establish reachability before choosing a fix:

```bash
cargo tree -i <crate>@<version> --all-features -e normal --target all
```

`cargo audit` scans `Cargo.lock`, which also records crates reachable only through optional features. The fix order is: upgrade into the patched range; remove the path (often a default feature on an intermediate crate, e.g. a legacy TLS client); only then ignore, with a comment naming the path and why it is not exploitable here. Fixing dependencies is `/hsm-deps` territory — this skill reports and recommends.

For npm, a "fix" that `npm audit` offers as a semver-major downgrade of a direct dependency is not a fix; report the advisory as unpatched. An `overrides` pin below the patched version is itself a vulnerability source — check `overrides` in each `package.json` against current advisories.

## Part 2 — code checks

Use Grep across `crates/` (or the one crate). Report each finding as `file:line` with severity.

1. **Lints:** `cargo clippy --all --all-targets -- -D warnings`.
2. **Unsafe:** every crate root carries `#![deny(unsafe_code)]` except the crates `CLAUDE.md` lists. In the exempt crates, every `unsafe` block has a `// SAFETY:` comment that states the invariant.
3. **Constant-time comparison:** MACs, signatures, tokens, password hashes and key material compare with `subtle::ConstantTimeEq` (`ct_eq`), never `==` on byte slices or `Vec<u8>`.
4. **Zeroization:** types holding private keys, seeds, mnemonics, passwords or session secrets derive or implement `Zeroize`/`ZeroizeOnDrop`, or wrap the value in `secrecy::SecretBox`/`SecretString`. Temporary buffers holding key bytes are zeroized before drop.
5. **Redaction:** no secret-bearing type derives `Debug` or `Serialize` without redaction; no `tracing`/`log` call formats key material, seeds, tokens or passwords.
6. **Input validation:** gRPC, REST, KMIP and PKCS#11 entry points bound sizes and lengths before allocating, validate key and algorithm identifiers against an allowlist, and fail closed on unknown values.

## Report

Group by severity (Critical / High / Medium / Low). Each finding: location, what is wrong, why it matters here, and the fix. End with the advisory table per surface: count, ignored-with-reason, unpatched.
