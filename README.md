# OSS Security Policy as Code Starter Kit

Pass/fail security policy gates for OSS repositories, with explicit assurance grading and framework mappings.

[![CI](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/actions/workflows/github-ci-cd.yml/badge.svg)](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/actions/workflows/github-ci-cd.yml)
[![Security CI](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/actions/workflows/security-ci-cd.yml/badge.svg)](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/actions/workflows/security-ci-cd.yml)
[![PyPI](https://img.shields.io/pypi/v/oss-policy-kit?label=PyPI&color=success)](https://pypi.org/project/oss-policy-kit/)
[![Python](https://img.shields.io/pypi/pyversions/oss-policy-kit)](https://pypi.org/project/oss-policy-kit/)
[![License](https://img.shields.io/github/license/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit?color=informational)](LICENSE)

## At a Glance

`oss-policy-kit` evaluates a local repository clone plus optional evidence files, then emits Markdown, JSON, and optional SARIF reports for humans and CI gates.

| Current release | Bundled profiles | Controls | CLI commands | Python |
|---|---:|---:|---:|---|
| v7.0.1 <!-- x-release-please-version --> | 56 | 212 | 19 | 3.12+ |

Use it when you need a local-first gate that combines repository governance, CI/CD hardening, release posture, scanner evidence, waivers, and framework-oriented reporting. It is not a vulnerability scanner, certification engine, or legal compliance guarantee.

## Quickstart

```bash
python -m pip install oss-policy-kit
python -m oss_policy_kit init --target . --with-evidence --with-workflow
python -m oss_policy_kit evaluate --target . --profile github-level-1 --fail-on fail
```

The evaluation writes:

- `evaluation-report.md` for review.
- `evaluation-report.json` for automation.
- `evaluation-report.sarif` when `--sarif-output` is set.

First-time tutorial: [docs/tutorial-first-pr-gate.md](docs/tutorial-first-pr-gate.md). Compact CLI reference: [docs/quickstart-15-min.md](docs/quickstart-15-min.md).

## What It Does

- Evaluates bundled policy profiles against a repository clone.
- Uses optional evidence under `.oss-policy-kit/evidence/` for platform-only facts.
- Composes signals from local files, workflows, SARIF/JSON scanner outputs, waivers, and release evidence.
- Labels controls by assurance type: deterministic, signal, or evidence-backed.
- Supports Markdown, JSON report contracts, and optional SARIF for code-scanning workflows.
- Keeps waivers visible with owner, reason, and expiry metadata.

## What It Does Not Do

- It does not certify CRA, SLSA, OSPS, SSDF, or AI Act compliance.
- It does not replace SAST, SCA, secrets scanning, threat modeling, secure code review, pentesting, or live platform review.
- It does not prove branch protection, rulesets, MFA, cloud posture, or registry settings unless you provide API-backed evidence.
- It does not claim SLSA Build L3. The current trust model is documented in [docs/supply-chain-verification.md](docs/supply-chain-verification.md).

## Core Capabilities

| Area | Included |
|---|---|
| Repository governance | LICENSE, SECURITY, CONTRIBUTING, CODEOWNERS, branch protection evidence, release hygiene |
| CI/CD posture | GitHub Actions, Azure Pipelines, AWS CodeBuild/CodePipeline, GitLab CI signals |
| Release hardening | OIDC publishing, provenance evidence, artifact verification, source-built container flow |
| Scanner composition | SARIF/JSON ingestion for tools such as zizmor, OSV-Scanner, Gitleaks, Scorecard, and Semgrep |
| Framework mapping | OSPS, NIST SSDF, SLSA, S2C2F, OWASP CI/CD, EU CRA, EU AI Act readiness signals |
| AI and agent security | AI agent source-side checks, MCP server security, OWASP Agentic ASI mapping |
| Exception handling | Waiver registry with reason, owner, scope, and expiry |

## Profiles

List bundled profiles:

```bash
python -m oss_policy_kit profiles
```

Common starting points:

| Profile | Use when |
|---|---|
| `github-level-1` | First GitHub repository gate |
| `github-level-2` | Stricter GitHub governance and CI/CD posture |
| `oss-publish-readiness-1` | Release/publish readiness for OSS packages |
| `appsec-sast-sca-1` | Compose SAST/SCA/secrets scanner evidence |
| `osps-baseline-2026-1` | OpenSSF OSPS Baseline 2026-oriented review |
| `cra-eu-ready-2-1` | EU CRA Article 13/14 readiness signals |
| `ai-agent-baseline-1` | Source-side checks for AI agent repositories |
| `appsec-mcp-server-1` | MCP server security readiness |

Full profile guide: [docs/profiles/overview.md](docs/profiles/overview.md).

## GitHub Action

```yaml
- uses: lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit@v7.0.0
  with:
    profile: github-level-1
    fail-on: fail
```

Action reference: [docs/github-action.md](docs/github-action.md). Starter workflows live under [templates/workflows/](templates/workflows/).

## Reports and Contracts

By default, `evaluate` writes `reports/2.0` JSON (the default flipped from `reports/1.0` in v7.0.0 — ADR-027). `reports/1.0` stays selectable via `--report-json-contract=1.0` for one minor cycle, then deprecates. Contracts and migration:

- [docs/reports-contract-v2.0.md](docs/reports-contract-v2.0.md) — current default
- [docs/reports-contract-v1.0.md](docs/reports-contract-v1.0.md) — previous default (still selectable)
- [docs/v7.0.0-migration-guide.md](docs/v7.0.0-migration-guide.md) — upgrading across the flip
- [docs/sample-reports/](docs/sample-reports/README.md)

Exit codes:

| Code | Meaning |
|---:|---|
| 0 | Success; configured fail threshold was not violated |
| 1 | Evaluation completed and the fail threshold was violated |
| 2 | Usage, validation, or load error |
| 3 | Unexpected internal error |

## Supply Chain Verification

PyPI publication uses Trusted Publishing and registry attestations. Release artifacts also use GitHub Artifact Attestations. Container images are built from the checked-out release source tree, signed with cosign keyless, and attested.

Verification commands and limits are in [docs/supply-chain-verification.md](docs/supply-chain-verification.md).

## Documentation Map

| Topic | Link |
|---|---|
| Documentation index | [docs/README.md](docs/README.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| CLI reference | [docs/cli-reference.md](docs/cli-reference.md) |
| Results guide | [docs/results-guide.md](docs/results-guide.md) |
| Framework alignment | [docs/framework-alignment.md](docs/framework-alignment.md) |
| Positioning and limits | [docs/positioning.md](docs/positioning.md) |
| EU CRA readiness | [docs/cra-readiness.md](docs/cra-readiness.md) |
| EU AI Act readiness | [docs/eu-ai-act-readiness.md](docs/eu-ai-act-readiness.md) |
| MCP server security | [docs/mcp-server-security.md](docs/mcp-server-security.md) |
| Release readiness | [docs/release-readiness.md](docs/release-readiness.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Repository Layout

| Path | Purpose |
|---|---|
| `src/oss_policy_kit/` | Python package, CLI, evaluators, parsers, reporting |
| `src/oss_policy_kit/data/` | Bundled controls, profiles, and schemas |
| `templates/` | Starter workflows, waivers, docs, and ruleset examples |
| `examples/` | Hardened and vulnerable example repositories |
| `tests/` | Unit, application, integration, infrastructure, and property tests |
| `docs/` | User docs, architecture, mappings, ADRs, and release notes |

## Contributing and Security

- Contribution guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Governance: [GOVERNANCE.md](GOVERNANCE.md)
- Vulnerability reporting: [SECURITY.md](SECURITY.md)
- Discussions: <https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/discussions>
- Issues: <https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues>

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
