# OSS Security Policy as Code Starter Kit

Evaluate clone-visible OSS repository governance plus GitHub Actions, Azure Pipelines, and AWS CodeBuild/CodePipeline signals from a local clone. Platform truth outside the repository still requires evidence or manual review.

This project is intentionally small and explicit about trust boundaries. GitHub support is the most mature path today; Azure and AWS support are clone-based and evidence-driven rather than live platform verification.

Operational privacy: evaluation is local and clone-visible by default. API-backed evidence collection runs only when explicitly invoked, and should be scoped to the platform/repository being assessed.

## Quick Links

- [What's new in v5.0.0](#whats-new-in-v500)
- [Current Release State](#current-release-state)
- [Recommended First Command](#recommended-first-command)
- [Quickstart](#quickstart)
- [CI/CD Integration](#cicd-integration)
- [Outputs](#outputs)
- [Documentation](#documentation)
- [CHANGELOG.md](CHANGELOG.md)
- [GitHub Releases](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/releases)
- [Validation walkthrough](docs/validation-walkthrough.md)
- [CLI reference](docs/cli-reference.md)
- [Results guide](docs/results-guide.md)
- [Bundled profiles overview](docs/profiles/overview.md)
- [Release hard-gate playbook](docs/release-playbook-hardgate.md)
- [v5.0.0 migration guide](docs/v5.0.0-migration-guide.md)

## At A Glance

| Area | What you get |
| --- | --- |
| Current release | `v5.0.0` / Python package `oss-policy-kit==5.0.0` |
| Input | A local repository clone |
| Output | `evaluation-report.json` and `evaluation-report.md` (optional SARIF 2.1.0 via `--sarif-output`) |
| Core scope | Clone-visible governance and GitHub/Azure/AWS CI/CD signals |
| Profiles | `github-*`, `azure-*`, `aws-*` ladders (`level-1..3`, `release-hardening-*`) — list with `python -m oss_policy_kit profiles`; optional bundled hybrids `github-aws-level-2` / `github-azure-level-2` are **advisory-only; not for use as release gates** |
| Exceptions | Waiver registry with owner, reason, and expiry |
| Examples | Hardened and vulnerable sample repositories |
| Assurance model | Each control is labelled `deterministic`, `signal`, or `evidence-backed`; the value flows into `reports/1.0` JSON and Markdown so consumers can reason about proof strength. See [docs/profiles/overview.md](docs/profiles/overview.md). |

## Recommended First Command

After installing, run the hardened example first:

```bash
python -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened --summary-only
```

This confirms the CLI, bundled profile data, example repository, and report generation path before you evaluate your own repository.

## Current Release State

`v5.0.0` is the current public release line. It graduates the JSON report contract to the new default `reports/1.0`, introduces the Evidence Model v2 plus optional SARIF 2.1.0 output via `--sarif-output`, removes the legacy bundled profile alias `github-release-hardening` (use `github-release-hardening-1`), and tightens public-hygiene posture. The control catalog and profile control IDs are unchanged.

| Surface | Current state |
| --- | --- |
| Package | `oss-policy-kit==5.0.0` |
| GitHub Release | `v5.0.0` is the release target for wheel and sdist assets; `v4.0.4` remains available as an immutable predecessor |
| Default branch | `master` |
| License | Apache-2.0 (`LICENSE` + `NOTICE`) |
| Report contract | `reports/1.0` by default; `0.3` and `0.2` remain selectable via `--report-json-contract`. `0.1` was removed in v5.0.0 |
| Security workflow | Scanners run in `Security CI/CD`; SARIF upload is gated by `ENABLE_CODE_SCANNING_UPLOAD=true` so validation does not fail when Code Scanning upload APIs are unavailable |

The repository is designed to be reproducible from a clean clone: install the package, run the built-in examples, and compare the generated JSON/Markdown reports.

## What's new in v5.0.0

Highlights only — full detail in [`CHANGELOG.md`](CHANGELOG.md) and the migration steps in [`docs/v5.0.0-migration-guide.md`](docs/v5.0.0-migration-guide.md).

- **Default JSON report contract is now `reports/1.0`.** The new shape decouples wire stability from the package version. `--report-json-contract 0.3` keeps the v4 shape byte-for-byte; `0.2` remains selectable; `0.1` was removed.
- **Evidence Model v2.** Each result in `reports/1.0` carries a structured `evidence` object with `source_type`, `collection_method`, `trust_level`, `attestation_status`, `freshness_status`, `evidence_required`, and `limitations`. See [`docs/reports-contract-v1.0.md`](docs/reports-contract-v1.0.md).
- **SARIF 2.1.0 output.** New `--sarif-output PATH` flag on `evaluate`. One SARIF result per `fail` or `manual-review-required` finding.
- **Legacy profile alias removed.** `github-release-hardening` (no numeric suffix) returns exit `2` with a migration error. Use `github-release-hardening-1` (same control set).
- **UTF-8 schema hygiene.** The bundled `evaluation-report-v3.schema.json` is now UTF-8 without BOM (was UTF-16 in v4).
- **Public-hygiene gate.** `scripts/check_public_hygiene.py` is part of the release validation flow.

Breaking changes are limited to the items above. The `--fail-on` semantics, the bundled control catalog, profile control IDs, the Markdown report layout, and the surfaces of `evaluate-many` / `recommend-profile` / `scaffold-evidence` / `collect-evidence` / `diff-reports` are unchanged.

## What This Kit Does

The starter kit helps you assess whether a repository shows a practical OSS baseline in files and workflows that are observable locally. It focuses on:

- `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`, `CODEOWNERS`, changelog presence
- clone-visible GitHub Actions, Azure Pipelines, and AWS build/pipeline structure and hygiene signals
- report generation for humans and pipelines
- policy lifecycle markers such as `stable`, `experimental`, and `deprecated`
- additive local evidence such as waivers and optional platform evidence files

It is **not** a universal application scanner, an OSPS certification engine, a compliance guarantee, or a substitute for threat modeling, secure code review, pentesting, or GitHub settings review. See [docs/results-guide.md](docs/results-guide.md) for the full applicability discussion.

## Quickstart

Requires Python 3.12+.

### Install (official channels)

1. **From PyPI** (recommended for most consumers):

   ```bash
   python -m pip install oss-policy-kit
   python -m oss_policy_kit --version
   ```

2. **From GitHub Release artifacts** — download `oss_policy_kit-*.whl` or `oss_policy_kit-*.tar.gz` from the [Releases](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/releases) page, then `pip install /path/to/wheel`.

3. **From source** (contributors):

   ```bash
   python -m pip install -e ".[dev]"
   ```

Prefer `python -m oss_policy_kit` for CLI entry on Windows so you do not depend on `Scripts\` being on `PATH`.

### Run The Built-In Examples

```bash
python -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/vulnerable
python -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened
```

### What Success Usually Looks Like

- `examples/hardened-repo` on `github-level-1`: `pass: 14` (all active controls in the profile)
- `examples/vulnerable-repo` on `github-level-1`: multiple `fail`
- `github-release-hardening-1`: typically `pass` plus one branch-protection result that remains `manual-review-required` or `self-attested`, depending on local evidence

For the full step-by-step demo (CLI help, profile discovery, fixture comparison, controls table, CI gating), see [docs/validation-walkthrough.md](docs/validation-walkthrough.md).

## CI/CD Integration

Starter workflows live under [`templates/workflows/`](./templates/workflows/):

- [`github-oss-policy-check.yml`](./templates/workflows/github-oss-policy-check.yml) — baseline `evaluate` against `github-level-1`, fail the job when any control is `fail`.
- [`github-oss-policy-check-with-waivers.yml`](./templates/workflows/github-oss-policy-check-with-waivers.yml) — same as above but passes `--waivers ./waivers/waivers.yaml`.
- [`github-oss-policy-check-level-2.yml`](./templates/workflows/github-oss-policy-check-level-2.yml) — stricter `github-level-2` profile.
- [`pipelines/azure/azure-pipelines.yml`](./pipelines/azure/azure-pipelines.yml) — Azure Pipelines example for lint, tests, package build, SBOM artifact generation, and self-check gating on a Linux/Ubuntu agent.

Typical CI command:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --fail-on fail --output-dir ./oss-policy-reports
```

**Exit codes** in pipelines: `0` evaluation finished and the `--fail-on` threshold was not violated; `1` the gate tripped; `2` is usage or load errors. Keep the output directory as an artifact with `if: always()` so reviewers can inspect reports after a blocked run.

GitHub Releases for this kit include **wheel** and **sdist** distribution assets. The publish workflow also generates a CycloneDX SBOM as a CI artifact for release evidence.

## Outputs

Each `evaluate` run writes:

- `evaluation-report.md` — human-readable report (summary, controls table, per-control detail)
- `evaluation-report.json` — machine-readable contract (default `reports/1.0`)
- `evaluation-report.sarif` — SARIF 2.1.0, only when `--sarif-output` is passed

For the JSON contract details see [docs/reports-contract-v1.0.md](docs/reports-contract-v1.0.md) and the legacy [docs/reports-contract-v0.3.md](docs/reports-contract-v0.3.md). For result statuses (`pass`, `fail`, `manual-review-required`, `self-attested`, etc.) and how to interpret each one see [docs/results-guide.md](docs/results-guide.md).

## Maintainer Self-Check

Run the kit against this repository:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck
```

Treat the generated self-check report as authoritative for the current revision.

Optional maintainer scripts under [`scripts/`](./scripts/):

- `consumer_smoke.py` — install the wheel into a clean venv and exercise the CLI end-to-end.
- `twine_check_dist.py` — run `twine check` against `dist/*.whl` / `dist/*.tar.gz`.
- `check_public_hygiene.py` — fail-fast guard against private tokens leaking into public files.
- `demo-video.ps1` — PowerShell helper to record a CLI demo GIF/video; not part of CI or packaging.

## Documentation

- [docs/README.md](docs/README.md) — documentation hub
- [Project site](https://lucashgrifoni.github.io/OSS-Security-Policy-as-Code-Starter-Kit/) — public product site
- [docs/validation-walkthrough.md](docs/validation-walkthrough.md) — full step-by-step demo with screenshots
- [docs/cli-reference.md](docs/cli-reference.md) — full CLI reference
- [docs/results-guide.md](docs/results-guide.md) — how to interpret report statuses
- [docs/profiles/overview.md](docs/profiles/overview.md) — bundled profiles matrix, assurance vocabulary, decision tree
- [docs/framework-alignment.md](docs/framework-alignment.md) — cross-framework mapping (Scorecard, OSPS, OWASP CICD Top 10, SLSA v1.0, NIST SSDF, S2C2F, CIS SSCS, AWS Well-Architected, Azure DevOps Security)
- [docs/profiles/github.md](docs/profiles/github.md) / [docs/profiles/aws.md](docs/profiles/aws.md) / [docs/profiles/azure.md](docs/profiles/azure.md) — operator guides by platform family
- [docs/release-playbook-hardgate.md](docs/release-playbook-hardgate.md) — release gate with real CLI commands
- [docs/release-hardening-workflow.md](docs/release-hardening-workflow.md) — end-to-end L3 and release-hardening workflow with evidence paths
- [docs/adoption-guide.md](docs/adoption-guide.md) — baseline selection and expected outcomes
- [docs/recommended-adoption-playbook.md](docs/recommended-adoption-playbook.md) — copy/paste adoption path
- [docs/architecture.md](docs/architecture.md) — package boundaries, trust model, and evidence semantics
- [docs/packaging-and-release.md](docs/packaging-and-release.md) — install, build, and distribution guidance
- [docs/release-readiness.md](docs/release-readiness.md) — release gate and public launch checks

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
