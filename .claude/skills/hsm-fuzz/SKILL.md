---
name: hsm-fuzz
description: Run cargo-fuzz targets for a crate that has a fuzz workspace, triage any crash into a minimized reproducer, and turn it into a regression test.
---

# HSM fuzzing

```
/hsm-fuzz <crate> [runs]
```

`crate` is a directory under `crates/` that contains a `fuzz/` directory; `find crates -maxdepth 2 -name fuzz -type d` lists them. Default `runs`: 1,000,000 per target.

## Tooling

cargo-fuzz needs a nightly toolchain, and `rust-toolchain.toml` pins a stable one, so every command uses `+nightly`.

```bash
rustup toolchain install nightly   # if `rustup toolchain list` lacks it
cargo install cargo-fuzz           # if `cargo fuzz` is missing
```

Each `fuzz/` directory is its own Cargo workspace (it is not a member of the root workspace) with its own `Cargo.lock`, which is not committed.

## Steps

Run from `crates/<crate>`:

1. **List targets:** `cargo +nightly fuzz list`
2. **Run each target:** `cargo +nightly fuzz run <target> -- -runs=<runs>`
   For a time box instead of a run count: `-- -max_total_time=<seconds>`.
3. **On a crash**, libFuzzer writes the input to `fuzz/artifacts/<target>/crash-<hash>`.
   - Reproduce: `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>`
   - Minimize: `cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>`
   - Fix the bug in the crate, then add a unit test that feeds the minimized bytes through the same API the target calls, so the case stays covered without nightly.
4. **Corpus upkeep (optional):** `cargo +nightly fuzz cmin <target>` shrinks `fuzz/corpus/<target>` to the inputs that add coverage.

## Report

Per target: runs completed, crashes, timeouts/OOMs, and the final `cov:` / `ft:` counters from libFuzzer's last status line. For each crash: the artifact path, the panic message, the root cause, and the regression test added.

## Adding targets

When a crate parses untrusted input and has no fuzz workspace, `cargo +nightly fuzz init` inside the crate creates one; add a `package-ecosystem: cargo` entry for the new `fuzz/` directory to `.github/dependabot.yml`, since the root entry cannot reach a nested workspace.
