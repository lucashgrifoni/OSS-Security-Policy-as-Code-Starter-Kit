# OSS Security Policy as Code Starter Kit

Evaluate clone-visible OSS repository governance plus GitHub Actions, Azure Pipelines, and AWS CodeBuild/CodePipeline signals from a local clone. Platform truth outside the repository still requires evidence or manual review.

This project is intentionally small and explicit about trust boundaries. GitHub support is the most mature path today; Azure and AWS support are clone-based and evidence-driven rather than live platform verification.

Operational privacy: evaluation is local and clone-visible by default. API-backed evidence collection runs only when explicitly invoked, and should be scoped to the platform/repository being assessed.

> **In development**: `feat/v6.0.0-evolution` is the active development branch for the next major. Items marked under `Roadmap (v6.0.0 — in development)` in [`docs/positioning.md`](docs/positioning.md) are not yet shipped. The current published release line is `v5.9.x`.

## Quick Links

- [What's new in v5.9.0](#whats-new-in-v590)
- [Current Release State](#current-release-state)
- [Recommended First Command](#recommended-first-command)
- [Quickstart](#quickstart)
- [CI/CD Integration](#cicd-integration)
- [Outputs](#outputs)
- [Documentation](#documentation)
- [CHANGELOG.md](CHANGELOG.md)
- [GitHub Releases](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/releases)
- [Positioning vs adjacent OSS tooling](docs/positioning.md)
- [CRA readiness](docs/cra-readiness.md)
- [VEX emission (`emit-vex`)](docs/vex-emission.md)
- [Pre-commit integration](docs/pre-commit-integration.md)
- [Validation walkthrough](docs/validation-walkthrough.md)
- [CLI reference](docs/cli-reference.md)
- [Results guide](docs/results-guide.md)
- [Bundled profiles overview](docs/profiles/overview.md)
- [Release hard-gate playbook](docs/release-playbook-hardgate.md)
- [v5.9.0 migration guide](docs/v5.9.0-migration-guide.md)
- [v5.1.0 migration guide](docs/v5.1.0-migration-guide.md)
- [v5.0.0 migration guide](docs/v5.0.0-migration-guide.md)

## At A Glance

| Area | What you get |
| --- | --- |
| Current release | `v5.9.1` / Python package `oss-policy-kit==5.9.1` (Development Status: `Production/Stable`). `v5.9.1` is a patch release over `v5.9.0` — see `CHANGELOG.md`. |
| Input | A local repository clone |
| Output | `evaluation-report.json` and `evaluation-report.md` (optional SARIF 2.1.0 via `--sarif-output`); `oss-policy-kit emit-vex` also emits CycloneDX VEX 1.6 from OSV-Scanner SARIF |
| Core scope | Clone-visible governance and GitHub/Azure/AWS CI/CD signals; ingests SARIF from zizmor, poutine, OSV-Scanner v2, Gitleaks, and Semgrep |
| Profiles | **38 bundled profiles** — platform ladders (`github-*`, `azure-*`, `aws-*` levels 1-3 and release-hardening 1-3), advisory hybrids (`github-aws-level-2`, `github-azure-level-2`), regulatory (`cra-eu-reporting-1` — 2026-09-11 24h reporting; `cra-eu-ready-1`; `cra-eu-strict-1`), framework alignment (`osps-baseline-1`, `slsa-build-l2-1`, `ssdf-baseline-1`, `cis-supply-chain-1`, `owasp-cicd-top10-1`, `s2c2f-l1-1`), AppSec native bundle (`appsec-sast-sca-1` — now 15 controls with v5.9 SARIF adapters), **GitLab CI starter** (`gitlab-level-1` — new in v5.9.0), posture profiles (`iac-terraform-baseline-1`, `iac-cfn-baseline-1`, `iac-pulumi-baseline-1`, `iac-bicep-baseline-1`, `kubernetes-baseline-1`, `container-baseline-1`), and webhook receiver hardening (`webhook-security-1`). List with `python -m oss_policy_kit profiles`; full matrix in [`docs/profiles/overview.md`](docs/profiles/overview.md). |
| Exceptions | Waiver registry with owner, reason, and expiry |
| Examples | Hardened and vulnerable sample repositories |
| Assurance model | Each control is labelled `deterministic`, `signal`, or `evidence-backed`; the value flows into `reports/1.0` JSON and Markdown so consumers can reason about proof strength. See [docs/profiles/overview.md](docs/profiles/overview.md). |

## Recommended First Command

After installing, run the hardened example first:

```bash
python -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened --summary-only
```

This confirms the CLI, bundled profile data, example repository, and report generation path before you evaluate your own repository.

### Two-line bootstrap (v5.4.0+; available in current v5.9.0)

For brand new adopters, `init` collapses the first run into two commands:

```bash
python -m oss_policy_kit init --target . --with-evidence --with-workflow
python -m oss_policy_kit evaluate --target .
```

`init` writes a persisted `oss-policy-kit.yaml`; `evaluate` reads the profile from it when `--profile` is omitted. See [docs/cli-reference.md](docs/cli-reference.md#project-initialization) for all flags.

### Use as a GitHub Action

The kit ships a composite GitHub Action so adopters can evaluate the bundled baseline on every pull request without managing Python in their build images:

```yaml
- uses: lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit@v5
  with:
    profile: github-level-1
    fail-on: fail
```

Inputs map 1:1 to CLI flags. Full reference and SARIF forwarding example in [docs/github-action.md](docs/github-action.md).

## Current Release State

`v5.9.0` is the current public release line. It lands **Fase 4** of the v5 trajectory: four new SARIF-ingest adapters for the de-facto OSS scanner ecosystem (`SAST-ZIZMOR-066`, `SAST-POUTINE-067`, `SAST-OSV-068`, `SAST-GITLEAKS-069`), a CRA-reporting-readiness profile aligned with the 2026-09-11 deadline (`cra-eu-reporting-1`), a new evidence-backed disclosure-SLA control (`GOV-DISC-065`), the first `emit-vex` subcommand (CycloneDX VEX 1.6 emission from OSV-Scanner SARIF), the first two ADRs (`docs/decisions/`), a public positioning page, pre-commit hooks for downstream adopters, and a CRA-readiness narrative tying it all together. The kit's `Development Status` classifier is now `Production/Stable`. The JSON report contract is unchanged (`reports/1.0`); `0.3` and `0.2` remain selectable. v5.8.0 (catalog/profile/evidence invariant suites + 5 evaluator-package boundaries), v5.7.0 (Pulumi/CFN/Bicep IaC), v5.6.0 (Kubernetes + container), v5.5.0 (Terraform), and v5.4.0 (`init` wizard + Semgrep adapter) remain part of the catalog. See `CHANGELOG.md` for full details.

| Surface | Current state |
| --- | --- |
| Package | `oss-policy-kit==5.9.1` (`Development Status :: 5 - Production/Stable`); `v5.9.1` is a patch release over `v5.9.0` (no code, profile, or contract changes — see `CHANGELOG.md`) |
| GitHub Release | `v5.9.1` is the current release target; `v5.9.0`, `v5.8.1`, `v5.8.0`, `v5.7.0`, `v5.6.0`, `v5.5.0`, `v5.4.0`, and earlier versions remain available as predecessors. `v6.0.0` is in development on `feat/v6.0.0-evolution` (see `CHANGELOG.md` Unreleased section). |
| Default branch | `master` |
| License | Apache-2.0 (`LICENSE` + `NOTICE`) |
| Report contract | `reports/1.0` by default; `0.3` and `0.2` remain selectable via `--report-json-contract`. `0.1` was removed in v5.0.0 |
| Security workflow | Scanners run in `Security CI/CD`; SARIF upload is gated by `ENABLE_CODE_SCANNING_UPLOAD=true` so validation does not fail when Code Scanning upload APIs are unavailable |
| CLI subcommands | 13 — `evaluate`, `evaluate-many`, `profiles`, `recommend-profile`, `scaffold-evidence`, `collect-evidence`, `diff-reports`, `init`, `scan-sast`, `scan-iac`, `scan-k8s`, `scan-cfn`, `scan-pulumi`, `scan-bicep`, **`emit-vex`** (new in v5.9.0) |

The repository is designed to be reproducible from a clean clone: install the package, run the built-in examples, and compare the generated JSON/Markdown reports.

## What's new in v5.9.0

Highlights only — full detail in [`CHANGELOG.md`](CHANGELOG.md). Migration notes in [`docs/v5.9.0-migration-guide.md`](docs/v5.9.0-migration-guide.md).

- **Four new SARIF-ingest adapters.** `SAST-ZIZMOR-066` (GitHub Actions AST analysis), `SAST-POUTINE-067` (GitHub Actions + GitLab CI), `SAST-OSV-068` (OSV-Scanner v2 reachability-aware SCA), and `SAST-GITLEAKS-069` (secret leak detection). Each reads raw SARIF 2.1.0 dropped at `.oss-policy-kit/evidence/sast/<tool>.sarif.json` and grades findings by severity. Gitleaks is zero-tolerance (any finding blocks); the others fail only on `error`-level results. All four are bundled into `appsec-sast-sca-1` (which grows from 11 to 15 controls).
- **`cra-eu-reporting-1` profile** focused on the EU CRA's **2026-09-11** 24-hour reporting deadline. Eleven controls covering disclosure channel + SLA, detection capability, audit trail, risk handling discipline, and affected-artifact identification. Advisory (`--fail-on degraded`). Distinct from the existing `cra-eu-ready-1` (broader preparation) and `cra-eu-strict-1` (2027-12-11 full obligations).
- **`GOV-DISC-065` — disclosure SLA evidence-backed control.** Reads `.oss-policy-kit/evidence/disclosure-policy.json` (schema `disclosure-policy/v1`) with required fields `contact.method/value`, `acknowledgement_sla_hours`, `triage_sla_hours`, `public_disclosure_policy`. Signal fallback: looks for SLA keywords in `SECURITY.md` (root, `.github/`, `docs/`). The kit checks that an SLA is documented at all — it does not judge whether the SLA is fast enough.
- **`oss-policy-kit emit-vex` subcommand.** Emits a CycloneDX VEX 1.6 document from OSV-Scanner SARIF — every distinct vulnerability ID (CVE / GHSA / OSV / RUSTSEC) is listed with `analysis.state: in_triage`. The manufacturer fills the analysis post-hoc; per-CVE waiver integration is tracked for v5.9.x (see ADR-002). See [`docs/vex-emission.md`](docs/vex-emission.md).
- **First two ADRs.** [`docs/decisions/adr-001-sca-scanner-choice.md`](docs/decisions/adr-001-sca-scanner-choice.md) — OSV-Scanner v2 chosen as SCA primary, Trivy repositioned as future container-scanning candidate. [`docs/decisions/adr-002-emit-vex-scope.md`](docs/decisions/adr-002-emit-vex-scope.md) — emit-vex v0.1 scope (this release) plus v5.9.x extensions.
- **Public positioning page.** New [`docs/positioning.md`](docs/positioning.md) answering "why use this kit if Scorecard v6 / zizmor / OSV-Scanner / Harden-Runner exist". Honest boundary-drawing — composition, not replacement.
- **CRA readiness narrative.** New [`docs/cra-readiness.md`](docs/cra-readiness.md) walks both CRA deadlines, maps each of the three bundled CRA profiles, and is explicit about what the kit does **not** prove (24-hour clock, conformity assessment, CE-marking).
- **Pre-commit hook surface.** New `.pre-commit-hooks.yaml` with three published hooks (`oss-policy-kit-evaluate`, `oss-policy-kit-evaluate-degraded`, `oss-policy-kit-validate-profiles`). See [`docs/pre-commit-integration.md`](docs/pre-commit-integration.md).
- **Development Status promoted** from `4 - Beta` to `5 - Production/Stable`.

### Breaking — `cra-eu-strict-1` description rewrite

`cra-eu-strict-1` previously self-described as "hard-gate-capable when evidence files are filled" while its CLI maturity label was "framework-aligned advisory (regulatory)". The inconsistency is resolved in favor of advisory. The profile is **functionally unchanged** (same 19 controls, same `--fail-on degraded` recommendation); only the description text changed. This may surface in adopter dashboards that parse the profile description string. See [`docs/v5.9.0-migration-guide.md`](docs/v5.9.0-migration-guide.md) for full impact analysis.

Other release contracts are unchanged: the `--fail-on` semantics, JSON report contracts (`reports/1.0`, `0.3`, `0.2` byte-stable), Markdown report layout, every existing profile ID, every existing control ID, and `EVALUATOR_REGISTRY` membership for the v5.8 surface are preserved (v5.9 adds new IDs additively). No new hard dependencies were added.

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

2. **From GitHub Release artifacts** — when wheel or sdist assets are attached to a release, download `oss_policy_kit-*.whl` or `oss_policy_kit-*.tar.gz` from the [Releases](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/releases) page, then `pip install /path/to/wheel`. PyPI remains the primary install channel.

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

**Exit codes** in pipelines: `0` evaluation finished and the `--fail-on` threshold was not violated; `1` the gate tripped; `2` is usage or load errors; `3` is an unexpected internal error (re-raised stack trace). Keep the output directory as an artifact with `if: always()` so reviewers can inspect reports after a blocked run.

GitHub Release assets are the intended alternate install path when wheel or sdist artifacts are attached. PyPI remains the primary install channel, and the publish workflow generates both distribution artifacts and a CycloneDX SBOM as workflow artifacts for release evidence.

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

## Governance

See [GOVERNANCE.md](GOVERNANCE.md) for maintainers, decision-making, release process, and the path to becoming a maintainer.

## Security

See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
