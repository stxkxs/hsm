---
name: hsm-deps
description: Dependency maintenance pass across every surface in the repo — triage open Dependabot PRs and alerts, update and audit each surface, take or hold major bumps, keep .github/dependabot.yml and the MSRV references consistent, and land it all as one verified PR. Use for "maintenance check", "dependency update", "Dependabot PRs are failing", or "clear the security alerts".
---

# HSM dependency maintenance

Work on a branch (`chore/deps-<yyyy-mm-dd>`); land everything as one commit and one PR that supersedes the open Dependabot PRs.

## Surfaces

`.github/dependabot.yml` lists every surface in its header comment; regenerate the inventory with

```bash
find . \( -name Cargo.toml -o -name package.json -o -name go.mod -o -name pyproject.toml -o -name Dockerfile \) \
  -not -path '*/node_modules/*' -not -path '*/target/*' -not -path '*/.next/*' \
  | grep -vE '^\./crates/[^/]+/Cargo\.toml$'
```

and confirm each directory has an `updates:` entry. Nested Cargo workspaces (`sdks/rust`, `crates/*/fuzz`) are invisible to the root `cargo` entry and need their own.

## 1. Triage before touching anything

```bash
gh pr list --json number,title,statusCheckRollup --jq '.[] | "\(.number) \(.title) fails=\([.statusCheckRollup[]? | select(.conclusion=="FAILURE") | .name] | join(","))"'
gh api 'repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100' --jq '.[] | "\(.security_advisory.severity) \(.dependency.package.name) \(.dependency.manifest_path) fix>=\(.security_vulnerability.first_patched_version.identifier)"'
gh run list --branch main --workflow ci.yml -L 3
```

When every PR fails the same job, the cause is on `main`, not in the PRs — usually new RustSec advisories failing `security`. Read the failing log (`gh run view <id> --log-failed`) and fix `main` first; rebasing PRs onto a red `main` changes nothing.

## 2. Rust (root workspace)

1. `cargo update`, then `cargo audit`.
2. For each remaining advisory, trace the path: `cargo tree -i <crate>@<version> --all-features -e normal --target all`. In order of preference:
   - bump the direct dependency into the patched range;
   - cut the path — often a default feature on an intermediate crate (check `cargo tree --all-features -e features -i <crate>` for which feature pulls it in, then set `default-features = false` with the needed features listed);
   - ignore it, in both `.cargo/audit.toml` and the CI `--ignore` list, with a comment naming the path and why it is unreachable or inert. Remove any existing ignore whose crate has left `Cargo.lock`.
3. Major bumps: `cargo upgrade --incompatible --dry-run` lists every held-back direct dependency. Each one is either taken in this pass (bump, fix call sites, verify) or listed in the root `ignore:` block of `.github/dependabot.yml` with a comment stating the concrete blocker. The comments in that file are the record of what is held and why; read them before retrying a held bump, and delete an entry once its blocker is gone.
4. After a major bump, check what the new version turned on by default. Runtime crates (wasmtime, TLS stacks) enable new features in majors that can conflict with this repo's hardened configuration.

## 3. Other surfaces

| Surface | Update | Audit |
|---|---|---|
| `ui`, `sdks/typescript` | `npm update --save`; majors with `npm install <pkg>@<version>` | `npm audit` |
| `sdks/go` | `go get -u -t ./... && go mod tidy` | `govulncheck ./...` |
| `sdks/python` | raise floors in `pyproject.toml` only when a fix needs it; keep the comment beside each floor | `pip-audit` |
| `sdks/rust`, `crates/*/fuzz` | `cargo update` (lockfiles not committed) | `cargo audit` |
| `Dockerfile` | base image tags are MSRV and glibc declarations; see below | — |

npm `overrides`: an override pin goes stale and ends up *below* the patched version, becoming the vulnerability. On every pass, check each override against current advisories and against what the parent package now declares; delete it once the parent's own range is patched. `npm audit` "fixes" that downgrade a direct dependency across a major are not fixes — record the advisory as unpatched instead.

## 4. Dependabot configuration rules

- **Pre-1.0 crates and packages:** a minor bump is breaking. Hold with `update-types: ["version-update:semver-minor", "version-update:semver-major"]`. Holding only `semver-major` on a `0.y.z` dependency never fires.
- **1.0+:** hold with `update-types: ["version-update:semver-major"]`.
- **Never** write an `ignore` entry without `update-types` (or a bounded `versions`) — it blocks patch releases, which carry the security fixes.
- **Groups** take the first matching group; a group without `patterns` matches everything, so specific groups go before broad ones.
- **MSRV references** must move together: `rust-toolchain.toml` `channel`, `Dockerfile` `FROM rust:<msrv>-bookworm`, the README badge and prerequisites, and the `dtolnay/rust-toolchain@<msrv>` ref in the CI `msrv` job (also listed in `CLAUDE.md`). Dependabot must not bump the `dtolnay/rust-toolchain` ref or the `rust` image minor — both are MSRV declarations, and the image bump stays green in CI because `rust-toolchain.toml` re-pins the toolchain inside it. The `debian` runtime stage must match the builder's Debian release.

## 5. Verify

Run `/verify` with every touched surface, including the `aws-nitro` clippy step when AWS, TLS or HTTP crates moved. Re-run every audit from steps 2–3; the pass is done when each is clean or every remaining finding is an ignore with a stated reason or an unpatched advisory with no fix.

## 6. Land

1. Commit by surface in one structured message (`/commit`), stating for each change what moved, what broke and how it was fixed, and why anything was held.
2. Push, open the PR, wait for CI.
3. `/merge`, then close each superseded Dependabot PR with `gh pr close <n> --delete-branch --comment "Superseded by #<pr>."`.
4. Dependabot rescans after the merge and may open major-bump PRs against the refreshed tree. Triage them with the same rules (take, or hold in `dependabot.yml` with a reason) — usually a second, smaller PR.
5. Confirm the end state: `main` CI green, open alerts at zero or each one explained.
