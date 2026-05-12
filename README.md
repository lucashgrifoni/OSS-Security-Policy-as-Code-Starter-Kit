# OSS Security Policy as Code Starter Kit

Evaluate clone-visible OSS repository governance plus GitHub Actions, Azure Pipelines, and AWS CodeBuild/CodePipeline signals from a local clone. Platform truth outside the repository still requires evidence or manual review.

This project is intentionally small and explicit about trust boundaries. GitHub support is the most mature path today; Azure and AWS support are clone-based and evidence-driven rather than live platform verification.

Operational privacy: evaluation is local and clone-visible by default. API-backed evidence collection runs only when explicitly invoked, and should be scoped to the platform/repository being assessed.

## Quick Links

- [What's new in v5.8.0](#whats-new-in-v580)
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
- [v5.1.0 migration guide](docs/v5.1.0-migration-guide.md)
- [v5.0.0 migration guide](docs/v5.0.0-migration-guide.md)

## At A Glance

| Area | What you get |
| --- | --- |
| Current release | `v5.8.0` / Python package `oss-policy-kit==5.8.0` |
| Input | A local repository clone |
| Output | `evaluation-report.json` and `evaluation-report.md` (optional SARIF 2.1.0 via `--sarif-output`) |
| Core scope | Clone-visible governance and GitHub/Azure/AWS CI/CD signals |
| Profiles | **36 bundled profiles** — platform ladders (`github-*`, `azure-*`, `aws-*` levels 1-3 and release-hardening 1-3), advisory hybrids (`github-aws-level-2`, `github-azure-level-2`), regulatory (`cra-eu-ready-1`, `cra-eu-strict-1`), framework alignment (`osps-baseline-1`, `slsa-build-l2-1`, `ssdf-baseline-1`, `cis-supply-chain-1`, `owasp-cicd-top10-1`, `s2c2f-l1-1`), AppSec native bundle (`appsec-sast-sca-1`), posture profiles (`iac-terraform-baseline-1`, `iac-cfn-baseline-1`, `iac-pulumi-baseline-1`, `iac-bicep-baseline-1`, `kubernetes-baseline-1`, `container-baseline-1`), and webhook receiver hardening (`webhook-security-1`). List with `python -m oss_policy_kit profiles`; full matrix in [`docs/profiles/overview.md`](docs/profiles/overview.md). |
| Exceptions | Waiver registry with owner, reason, and expiry |
| Examples | Hardened and vulnerable sample repositories |
| Assurance model | Each control is labelled `deterministic`, `signal`, or `evidence-backed`; the value flows into `reports/1.0` JSON and Markdown so consumers can reason about proof strength. See [docs/profiles/overview.md](docs/profiles/overview.md). |

## Recommended First Command

After installing, run the hardened example first:

```bash
python -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened --summary-only
```

This confirms the CLI, bundled profile data, example repository, and report generation path before you evaluate your own repository.

### Two-line bootstrap (v5.4.0+; available in current v5.8.0)

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

`v5.8.0` is the current public release line. It is an additive minor release on top of `v5.7.0`: the JSON report contract remains `reports/1.0`, legacy `0.3` and `0.2` report shapes remain selectable, and every existing profile ID, control ID, evaluator function object, and CLI surface stays stable. The release lands the v5.7 → v5.8 catalog-quality and refactor trajectory: catalog/profile/evidence invariant test suites, five new evaluator package boundaries (`evaluators_ci_cd`, `_platform`, `_release`, `_vuln_management`, `_sast`) with `EVALUATOR_REGISTRY` identity-equivalent across the transition, an advisory profile banner expanded to the full bundled set, a completed maturity matrix for all 36 profiles, a 15-minute quickstart, the `scripts/validate-bundled-profiles.py` validator, and a cluster of maintenance fixes (BOM-stripped GitHub evidence schemas, README factual drift, Helm pre-pass tmp cleanup, `engine.evaluate_repository` default-contract docstring, Bandit B506 rationale). v5.7.0 (Pulumi/CFN/Bicep IaC + Helm pre-pass + SEC-WEBHOOK + evaluators steps 2-3), v5.6.0 (Kubernetes manifest coverage + container hardening), v5.5.0 (Terraform IaC posture), and v5.4.0 (`init` wizard + `scan-sast` + Semgrep adapter) remain part of the catalog. See `CHANGELOG.md` for full details.

| Surface | Current state |
| --- | --- |
| Package | `oss-policy-kit==5.8.0` |
| GitHub Release | `v5.8.0` is the current release target; `v5.7.0`, `v5.6.0`, `v5.5.0`, `v5.4.0`, and earlier versions remain available as predecessors |
| Default branch | `master` |
| License | Apache-2.0 (`LICENSE` + `NOTICE`) |
| Report contract | `reports/1.0` by default; `0.3` and `0.2` remain selectable via `--report-json-contract`. `0.1` was removed in v5.0.0 |
| Security workflow | Scanners run in `Security CI/CD`; SARIF upload is gated by `ENABLE_CODE_SCANNING_UPLOAD=true` so validation does not fail when Code Scanning upload APIs are unavailable |

The repository is designed to be reproducible from a clean clone: install the package, run the built-in examples, and compare the generated JSON/Markdown reports.

## What's new in v5.8.0

Highlights only — full detail in [`CHANGELOG.md`](CHANGELOG.md). For migration notes from earlier releases, see [`docs/v5.1.0-migration-guide.md`](docs/v5.1.0-migration-guide.md) and [`docs/v5.0.0-migration-guide.md`](docs/v5.0.0-migration-guide.md).

- **Catalog / profile / evidence invariant test suites.** Three new test modules pin properties that previously had to be checked by hand: catalog consistency (unique IDs, recognized lifecycle/assurance, no orphan controls), evidence schema versioning (every packaged `evidence-*.schema.json` declares its `$schema` and explicit `oss-policy-kit/evidence/.../v<n>` version, with the packaged copy and the `reports/schema/` mirror byte-identical), and profile-maturity-matrix drift (`docs/profiles/overview.md` is locked to reflect the actual lifecycle composition of every bundled profile).
- **`evaluators.py` decomposition steps 4-8 — five new public package boundaries.** Following the v5.7 governance / supply-chain extraction, v5.8 adds `evaluators_ci_cd.py` (`CI-*`), `evaluators_platform.py` (`PLAT-*`, `GH-PLAT-*`, `AZ-PLAT-*`), `evaluators_release.py` (`REL-*`, `GH-REL-*`, release archive), `evaluators_vuln_management.py` (`DEP-UPDATE-*`, dependency review, fuzzing aggregation), and `evaluators_sast.py` (dedicated SAST adapter surface; `SAST-SEMGREP-064` moved here from supply-chain so v5.9 adapters such as Trivy / Gitleaks / Grype plug into a single boundary). All five modules re-export the existing callables — `EVALUATOR_REGISTRY` is **identity-equivalent** to v5.7.0 (validated by `tests/application/test_evaluators_v58_shims.py`).
- **Advisory profile banner expanded to the full bundled set.** The `[advisory profile]` operator banner now fires for every bundled advisory profile (IaC posture profiles, Kubernetes, container, webhook-security, AppSec native, plus every framework-alignment profile: `osps-*`, `slsa-*`, `ssdf-*`, `cis-*`, `owasp-*`, `s2c2f-*`, `cra-*`). Operators get consistent guidance to run `--fail-on degraded` (not `fail`) on every advisory profile.
- **Profile maturity matrix completed for all 36 bundled profiles.** `docs/profiles/overview.md` now lists every bundled profile with its lifecycle blend, assurance blend, recommended `--fail-on` setting, and adoption stage. Locked by `tests/application/test_profile_maturity_drift.py`.
- **15-minute quickstart.** New [`docs/quickstart-15-min.md`](docs/quickstart-15-min.md) walks a brand-new adopter from `pip install` to a passing gate against the hardened example in under 15 minutes (install → `init` → first `evaluate` → read the report → wire a CI gate → add the first waiver).
- **`scripts/validate-bundled-profiles.py`.** New maintainer-side validator that loads every bundled profile, checks each `control_ids` member against the catalog, surfaces unknown IDs / removed IDs / orphan controls, and emits a non-zero exit code on any drift.
- **Fixes.** Stripped UTF-8 BOM from three GitHub evidence schemas (`evidence-github-environment-protection`, `evidence-github-rulesets`, `evidence-github-secret-scanning`); README factual drift corrected (release row, profile count `32 → 36`, anchor for the "What's new" section, two-line bootstrap version, pipeline exit codes `0 / 1 / 2 / 3`); Helm pre-pass tmp-directory leak (`HelmRenderOutcome.tmp_root` is now surfaced and `scan-k8s` cleans it up via `try/finally`); `engine.evaluate_repository` default contract documented (programmatic default stays `"0.3"` for v4.x callers, CLI / config / init template default to `"1.0"`); Bandit B506 on the CFN parser annotated with rationale (`_CfnSafeLoader` is a `SafeLoader` subclass that only adds CFN intrinsic constructors).

There are no breaking changes in `v5.8.0`. The `--fail-on` semantics, JSON report contracts (`reports/1.0`, `0.3`, `0.2` byte-stable), Markdown report layout, the surfaces of `evaluate` / `evaluate-many` / `recommend-profile` / `scaffold-evidence` / `collect-evidence` / `diff-reports` / `init` / `scan-sast` / `scan-iac` / `scan-k8s` / `scan-cfn` / `scan-pulumi` / `scan-bicep`, every profile ID, every control ID, and `EVALUATOR_REGISTRY` itself are unchanged. No new hard dependencies were added.

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

## Governance

See [GOVERNANCE.md](GOVERNANCE.md) for maintainers, decision-making, release process, and the path to becoming a maintainer.

## Security

See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
