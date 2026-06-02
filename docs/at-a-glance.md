# At a glance

This page keeps the detailed capability snapshot out of the root README so the first page can stay short.

## Current public release

| Area | What you get |
|---|---|
| Current public release | `v7.0.1` (PyPI package `oss-policy-kit`) <!-- x-release-please-version --> |
| Runtime | Python 3.12+ |
| Input | A local repository clone, optional waivers, optional evidence files, optional scanner SARIF/JSON |
| Output | Markdown, JSON (`reports/2.0` default), optional SARIF 2.1.0, CycloneDX VEX through `emit-vex` |
| Core scope | Clone-visible governance and GitHub/Azure/AWS/GitLab CI/CD signals |
| Exceptions | Waiver registry with owner, reason, and expiry |
| Assurance model | Controls are labelled `deterministic`, `signal`, or `evidence-backed` |

## v7.0.1 baseline <!-- x-release-please-version -->

| Area | v7.0.1 <!-- x-release-please-version --> |
|---|---|
| Profiles | 56 bundled profiles |
| Controls | 212 bundled controls |
| CLI subcommands | 19 |
| Report contracts | `reports/2.0` default (v7.0.0 flip); `reports/1.0` selectable for one cycle |
| Profiles added since v6.0.0 | AI/LLM advisory, EU AI Act Article 11 + Annex IV, EU CRA Art.13/14, SLSA Source L1/L2, full GitLab CI family (`gitlab-level-2/3` + `gitlab-release-hardening-1/2/3` + collector), OSS publish readiness, AI agent baseline, OSPS Baseline 2026, MCP server, OWASP Agentic ASI |
| Release state | Published release baseline; see `CHANGELOG.md` and release artifacts for the exact shipped package. |

## First commands

```bash
python -m pip install oss-policy-kit
python -m oss_policy_kit profiles
python -m oss_policy_kit evaluate --target . --profile github-level-1
```

For the guided adopter flow, use [tutorial-first-pr-gate.md](tutorial-first-pr-gate.md).
