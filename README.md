<p align="center">
  <img src="screenshots/01-cli-help.png" alt="OSS Policy Kit CLI" width="600">
</p>

<h1 align="center">OSS Security Policy as Code Starter Kit</h1>

<p align="center">
  <strong>Pass/fail security policy gates for your repository - with explicit trust grading.</strong><br>
  Composes zizmor, OSV-Scanner, Gitleaks, Scorecard, Semgrep, and your multi-platform CI/CD signals into one regulatory-aware decision.
</p>

<p align="center">
  <a href="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/actions/workflows/github-ci-cd.yml"><img src="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/actions/workflows/github-ci-cd.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/actions/workflows/security-ci-cd.yml"><img src="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/actions/workflows/security-ci-cd.yml/badge.svg" alt="Security CI"></a>
  <a href="https://pypi.org/project/oss-policy-kit/"><img src="https://img.shields.io/pypi/v/oss-policy-kit?label=PyPI&color=success" alt="PyPI"></a>
  <a href="https://pypi.org/project/oss-policy-kit/"><img src="https://img.shields.io/pypi/pyversions/oss-policy-kit" alt="Python"></a>
  <a href="https://pypi.org/project/oss-policy-kit/"><img src="https://img.shields.io/pypi/dm/oss-policy-kit?color=blue" alt="Downloads"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit?color=informational" alt="License"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit"><img src="https://api.securityscorecards.dev/projects/github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/releases/latest"><img src="https://img.shields.io/github/v/release/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit?label=release" alt="Release"></a>
  <a href="docs/cra-readiness.md"><img src="https://img.shields.io/badge/EU%20CRA-ready-success" alt="CRA Ready"></a>
</p>

The current public package is `oss-policy-kit==5.9.1`. The active v6.0.0 development branch has landed locally with **52 bundled profiles**, **212 controls**, and **17 CLI subcommands**. v6 remains unreleased until maintainer review, remote push, release tagging, PyPI publish, and container publish complete.

## Why use this

- **One decision from many signals.** Composes SARIF and JSON evidence from zizmor, OSV-Scanner, Gitleaks, Scorecard, Semgrep, and the bundled evaluators into a single gate result.
- **Multi-platform CI/CD in one report.** GitHub Actions, Azure Pipelines, AWS CodeBuild/CodePipeline, and GitLab CI signals are evaluated from a local clone plus optional evidence files.
- **Regulatory-aware out of the box.** EU CRA, NIST SSDF, OSPS, SLSA, S2C2F, and OWASP CI/CD Top 10 mappings ship as profiles and docs, without requiring Rego.
- **Honest about limits.** Each control is labelled `deterministic`, `signal`, or `evidence-backed`, so reviewers can see what was proven and what still needs platform evidence.

## Quickstart

Python 3.12+ required.

```bash
python -m pip install oss-policy-kit
python -m oss_policy_kit init --target . --with-evidence --with-workflow
python -m oss_policy_kit evaluate --target .
```

You get `evaluation-report.md` and `evaluation-report.json` with pass/fail states, remediation text, waiver visibility, and trust grading per control. Optional SARIF output is available with `--sarif-output`.

Full first-time adopter tutorial: [docs/tutorial-first-pr-gate.md](docs/tutorial-first-pr-gate.md). Existing compact quickstart: [docs/quickstart-15-min.md](docs/quickstart-15-min.md).

### Use as a GitHub Action

```yaml
- uses: lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit@v5
  with:
    profile: github-level-1
    fail-on: fail
```

Inputs map 1:1 to CLI flags. See [docs/github-action.md](docs/github-action.md).

## Sample output

Hardened example on the `github-level-1` profile:

<p align="center">
  <img src="screenshots/05-example-hardened.png" alt="Hardened example output" width="700">
</p>

Vulnerable example, same profile:

<p align="center">
  <img src="screenshots/06-example-vulnerable.png" alt="Vulnerable example output" width="700">
</p>

Browse full sample reports: [docs/sample-reports/](docs/sample-reports/README.md). Report schema: [docs/reports-contract-v1.0.md](docs/reports-contract-v1.0.md).

## How it compares

| Capability | OSS Policy Kit | Scorecard | zizmor / OSV / Gitleaks | Conftest / OPA | Kyverno |
|---|:-:|:-:|:-:|:-:|:-:|
| Multi-platform repository and CI/CD gate | Yes | GitHub-centric | Scanner-specific | Adopter writes | Kubernetes-focused |
| Built-in regulatory and framework profiles | Yes | No | No | No | Policy-dependent |
| Assurance grading per control | Yes | Score-based | No | No | Policy-dependent |
| Composes scanner SARIF / JSON | Yes | No | n/a | No | No |
| Waiver registry with owner, reason, expiry | Yes | No | No | Adopter writes | Policy-dependent |
| CycloneDX VEX emission | Yes | No | No | No | No |
| Local-first, no API key by default | Yes | Mostly | Yes | Yes | Yes |

Full positioning, including what this kit is not: [docs/positioning.md](docs/positioning.md).

## What this kit does

The kit reads a repository clone and optional evidence files, evaluates bundled profiles, and emits Markdown, JSON (`reports/1.0` by default), and optional SARIF. v6.0.0 development adds profiles and controls across AI/LLM advisory coverage, EU AI Act Article 11 readiness, SLSA source checks, GitLab L2, OSS publish readiness, WORM publish-defense checks, and AI agent source-side checks.

It is not a universal vulnerability scanner, an OSPS certification engine, a compliance guarantee, or a substitute for threat modeling, secure code review, pentesting, or live platform settings review. See [docs/results-guide.md](docs/results-guide.md).

## CI/CD integration

Starter workflows under [`templates/workflows/`](templates/workflows/):

- [`github-oss-policy-check.yml`](templates/workflows/github-oss-policy-check.yml) - baseline `evaluate` against `github-level-1`.
- [`github-oss-policy-check-with-waivers.yml`](templates/workflows/github-oss-policy-check-with-waivers.yml) - same baseline with waiver registry support.
- [`github-oss-policy-check-level-2.yml`](templates/workflows/github-oss-policy-check-level-2.yml) - stricter `github-level-2`.
- [`pipelines/azure/azure-pipelines.yml`](pipelines/azure/azure-pipelines.yml) - Azure Pipelines example.

Typical CI command:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --fail-on fail --output-dir ./oss-policy-reports
```

Exit codes: `0` success, `1` gate failed, `2` usage/load error, `3` unexpected internal error.

## Outputs

Each `evaluate` run writes `evaluation-report.md` for humans, `evaluation-report.json` for automation, and `evaluation-report.sarif` when `--sarif-output` is passed. Detailed schemas live in [docs/reports-contract-v1.0.md](docs/reports-contract-v1.0.md) and [docs/reports-contract-v2.0.md](docs/reports-contract-v2.0.md).

## Supply chain verification

PyPI publication uses Trusted Publishing and the PyPA publishing action's registry attestations, while the release build also generates GitHub Artifact Attestations for wheel/sdist files. Container images are built from the checked-out release source tree, signed with cosign keyless, and attested with GitHub Artifact Attestations.

This branch does **not** claim SLSA Build L3. See [docs/supply-chain-verification.md](docs/supply-chain-verification.md) for exact verification commands and the current trust model.

## Documentation

| Topic | Doc |
|---|---|
| Documentation index | [docs/README.md](docs/README.md) |
| At a glance | [docs/at-a-glance.md](docs/at-a-glance.md) |
| Release state | [docs/release-state.md](docs/release-state.md) |
| Quickstart tutorial | [docs/tutorial-first-pr-gate.md](docs/tutorial-first-pr-gate.md) |
| CLI reference | [docs/cli-reference.md](docs/cli-reference.md) |
| Results guide | [docs/results-guide.md](docs/results-guide.md) |
| Profiles overview | [docs/profiles/overview.md](docs/profiles/overview.md) |
| Framework alignment | [docs/framework-alignment.md](docs/framework-alignment.md) |
| Positioning vs alternatives | [docs/positioning.md](docs/positioning.md) |
| EU CRA readiness | [docs/cra-readiness.md](docs/cra-readiness.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| Release and supply chain | [docs/release-readiness.md](docs/release-readiness.md) / [docs/supply-chain-verification.md](docs/supply-chain-verification.md) |
| Roadmap | [ROADMAP.md](ROADMAP.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Community and contributing

- [CONTRIBUTING.md](CONTRIBUTING.md) - how to propose changes.
- [GOVERNANCE.md](GOVERNANCE.md) - maintainers, decision-making, and release process.
- [SECURITY.md](SECURITY.md) - vulnerability reporting.
- [GitHub Discussions](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/discussions) - Q&A, ideas, and show-and-tell.
- [Issues](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues) - bugs, feature requests, and false positives.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
