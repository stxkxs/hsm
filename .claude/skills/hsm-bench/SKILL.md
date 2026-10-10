---
name: hsm-bench
description: Run Criterion benchmarks for one crate or the workspace and compare results against the performance targets in the architecture spec.
---

# HSM benchmarks

```
/hsm-bench [crate]
```

`crate` is a directory name under `crates/` (for example `crypto-engine`). With no argument, run every crate that has benches.

## Steps

1. **Find bench targets.** `grep -l '\[\[bench\]\]' crates/*/Cargo.toml` lists the crates with Criterion benches; each `[[bench]]` entry names a file under that crate's `benches/`.

2. **Run.**
   - One crate: `cargo bench --manifest-path crates/<crate>/Cargo.toml`
   - All: `cargo bench --all`
   - One bench group: append `-- <filter>` (Criterion name filter).

   Benchmarks run in release mode and take minutes per crate. Run them on an otherwise idle machine; numbers from a loaded laptop are not comparable run to run.

3. **Read results.** Criterion prints `time: [low mean high]` per benchmark and stores detail under `target/criterion/<group>/<bench>/new/estimates.json`. Throughput in ops/sec is `1 / mean`. Criterion does not report a p99; compare the latency target against the `high` bound of the confidence interval and say that is what was compared.

4. **Compare against targets.** The target table is the "Performance Targets" section of `docs/architecture/spec.md`. Most rows map to `crates/crypto-engine/benches/crypto_benches.rs`. Benchmarks with no row in that table are reported without a verdict.

5. **Report.** One line per benchmark: measured value, target, verdict. Flag any result that regressed against Criterion's stored baseline (`change: ... Performance has regressed`).

Throughput tests inside the test suite (the names `--skip performance`/`throughput`/`stress` filters out in `/verify`) are separate from Criterion benches; run them with `cargo test --all --release -- performance throughput stress` when asked for them.
