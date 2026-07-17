# Supply-Chain Security

## Verification Boundary

The supply-chain workflow is configured for explicit or scheduled execution. The tools and remote checks described below were not installed or run during implementation. Local verification is limited to configuration parsing and formatting, JavaScript syntax, the license policy against already installed packages, Cargo metadata, UTF-8, and whitespace checks.

`.github/workflows/supply-chain.yml` has only `workflow_dispatch` and a weekly `schedule`. It is not connected to `push`, `pull_request`, or `pull_request_target`. It grants only `contents: read`, permits one non-cancelling workflow run at a time, and caps each independent audit and SBOM job at 60 minutes. A failure in one job does not prevent the other job from running. The ordinary compile workflow downloads build dependencies but does not call advisory services; its npm bootstrap explicitly disables npm audit and funding requests.

The dedicated workflow can access the network for these bounded purposes:

- Git checkout and pinned Node/Rust toolchain installation.
- Frozen pnpm dependency installation with lifecycle scripts disabled.
- Exact cargo tool installation from crates.io.
- RustSec advisory retrieval by `cargo audit` and `cargo deny`.
- npm registry advisory lookup by `pnpm audit`.
- Exact cdxgen package retrieval and SBOM generation.

No external audit GitHub Action is used. All GitHub Actions are referenced by reviewed 40-character commit SHA values.

## Pinned Tools And Commands

| Tool | Version | Workflow command |
|---|---:|---|
| Node.js | 22.23.1 | `actions/setup-node` input |
| pnpm | 11.9.0 | `npm install --global --ignore-scripts --no-audit --no-fund pnpm@11.9.0` |
| Rust | 1.97.0 | `rustup toolchain install 1.97.0 --profile minimal` |
| cargo-audit | 0.21.2 | `cargo install cargo-audit --version 0.21.2 --locked` |
| cargo-deny | 0.18.4 | `cargo install cargo-deny --version 0.18.4 --locked` |
| cargo-cyclonedx | 0.5.7 | `cargo install cargo-cyclonedx --version 0.5.7 --locked` |
| cdxgen | 11.10.0 | `pnpm dlx @cyclonedx/cdxgen@11.10.0 ...` |

The enforcement commands are:

```text
cargo audit --deny warnings
cargo deny check advisories bans licenses sources
pnpm run licenses:check:js
pnpm audit --audit-level high
```

`cargo audit` scans the complete lockfile against RustSec. `cargo deny` additionally applies the target-aware source, version, advisory, and license policy in `deny.toml`. Neither command substitutes for compiling on the three supported target runners.

## Dependency Policy

The Rust graph is evaluated for Windows x64, macOS Intel, and macOS Apple Silicon with all features. Only the crates.io registry is accepted. Unknown registries, all git sources, and wildcard dependency versions fail closed. Private, non-published workspace packages are excluded from third-party license enforcement.

The Rust SPDX allowlist is closed. MPL-2.0 is not generally allowed; it is limited to these exact existing packages:

- `cssparser@0.36.0`
- `cssparser-macros@0.6.1`
- `dtoa-short@0.3.5`
- `option-ext@0.2.0`
- `selectors@0.36.1`

These are reviewed file-level-copyleft dependencies in the desktop web rendering dependency graph. A name, version, license, source, or usage change requires a new review rather than a wildcard exception.

JavaScript policy consumes the structured object emitted by `pnpm licenses list --json`. It matches complete license expressions, package names, and versions; filesystem paths are validated structurally but never used for a decision or printed. Unknown or missing expressions, empty reports, duplicate package versions, and new unlisted expressions fail. The production-only report is checked separately and cannot use exceptions. The scheduled workflow dynamically enumerates packages installed on its Linux x64 runner. Windows and macOS native exceptions are reviewed static policy entries, not a claim that the workflow enumerated those platforms.

MPL-2.0 JavaScript exceptions are limited to `lightningcss@1.32.0` and its exact Windows x64, macOS Intel, macOS Apple Silicon, and Linux CI native companions. They are build-time CSS tooling. If any enters the production dependency report, the production policy fails even though the full development policy recognizes the exception.

## SBOM Output

Both ecosystems generate CycloneDX JSON using specification version 1.5:

- cdxgen describes the complete pnpm workspace in `artifacts/sbom/javascript.cdx.json`.
- cargo-cyclonedx describes every Rust workspace package with all features separately for `x86_64-pc-windows-msvc`, `x86_64-apple-darwin`, and `aarch64-apple-darwin` under `artifacts/sbom/rust/<target>/<workspace-package-path>/bom.json`.

The generator commands are:

```text
pnpm dlx @cyclonedx/cdxgen@11.10.0 -t js --no-babel --validate --spec-version 1.5 -o artifacts/sbom/javascript.cdx.json .
cargo cyclonedx --all --all-features --format json --spec-version 1.5 --target <supported-target> --override-filename bom
git diff --exit-code -- Cargo.lock pnpm-lock.yaml
```

The workflow rejects missing or empty output and checks the expected Rust package-by-target file count before upload. The single `magictools-sbom` artifact is uploaded with `actions/upload-artifact` v4.6.2 pinned by commit SHA and retained for 14 days. Generated files under `artifacts/sbom/` are ignored locally and are not release attestations or proof that the corresponding platform compiled successfully.

## Acceptance Checklist

- The workflow triggers only by weekly schedule or explicit dispatch, has `contents: read`, fixed concurrency, and 60-minute job timeouts.
- Every remote `uses:` reference is a reviewed 40-character commit SHA.
- Node.js, pnpm, Rust, cargo-audit, cargo-deny, cargo-cyclonedx, and cdxgen match the pinned versions above.
- Dependency installation remains frozen or locked, and JavaScript lifecycle scripts are disabled.
- `deny.toml` covers exactly the three supported targets and fails closed for wildcard, git, and unknown-registry sources.
- JavaScript full and production reports both pass; production cannot consume MPL exceptions.
- The Rust SBOM count equals three times the workspace package count, every file is non-empty, and all features are included.
- JavaScript and Rust outputs parse as CycloneDX JSON 1.5 before the `artifacts/sbom/**` upload retained for 14 days.
- The ordinary compile workflow contains no advisory lookup, external audit Action, or movable pnpm Action tag.
- Local acceptance uses only format, syntax, offline license, Cargo metadata, diff, UTF-8, and whitespace checks. Remote audit, SBOM generation, and target compilation remain pending until the dedicated workflow or platform runners execute them.
