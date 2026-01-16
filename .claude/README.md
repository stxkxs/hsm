# Claude Code Configuration

This directory contains Claude Code configuration for the HSM project.

## Skills

Custom skills for HSM development:

### `/hsm-module <number>`
Work on any HSM module - explore, implement, test, benchmark.

**Examples:**
```
/hsm-module 1           # Work on crypto-engine
/hsm-module 2           # Work on key-manager
```

### `/hsm-bench [module]`
Run benchmarks and analyze performance against targets.

**Examples:**
```
/hsm-bench          # Benchmark all modules
/hsm-bench 1        # Benchmark crypto-engine only
```

### `/hsm-security [module]`
Comprehensive security audit - dependencies, lints, constant-time ops, zeroization.

**Examples:**
```
/hsm-security       # Audit all modules
/hsm-security 1     # Audit crypto-engine only
```

### `/hsm-coverage [module]`
Test coverage analysis and gap identification.

**Examples:**
```
/hsm-coverage       # Coverage for all modules
/hsm-coverage 1     # Coverage for crypto-engine only
```

### `/hsm-fuzz <module> [iterations]`
Run fuzz tests to find crashes and edge cases.

**Examples:**
```
/hsm-fuzz 1              # Fuzz crypto-engine (1M iterations)
/hsm-fuzz 1 10000000     # Fuzz crypto-engine (10M iterations)
```

## Hooks

Configured in `settings.json`:

- **pre-commit**: Format check, clippy, compilation before commits
- **post-edit**: Quick compilation check after edits

Hooks run automatically when conditions are met.

## Configuration

Edit `.claude/settings.json` to customize hooks and project settings.

## Module Map

| # | Crate | Purpose |
|---|-------|---------|
| 1 | crypto-engine | Core cryptographic primitives |
| 2 | key-manager | Key lifecycle management |
| 3 | auth | Authentication & authorization |
| 4 | grpc-api | gRPC API server |
| 5 | audit | Audit logging |
| 6 | metrics | Metrics & monitoring |
| 7 | storage | Persistent storage |
| 8 | backup | Backup & recovery |
| 9 | config | Configuration management |
