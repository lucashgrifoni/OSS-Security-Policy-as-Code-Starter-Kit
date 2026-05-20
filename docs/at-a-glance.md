# At a glance

This page keeps the detailed capability snapshot out of the root README so the first page can stay short.

## Current public release

| Area | What you get |
|---|---|
| Current public release | `v5.9.1` / Python package `oss-policy-kit==5.9.1` |
| Runtime | Python 3.12+ |
| Input | A local repository clone, optional waivers, optional evidence files, optional scanner SARIF/JSON |
| Output | Markdown, JSON (`reports/1.0` default), optional SARIF 2.1.0, CycloneDX VEX through `emit-vex` |
| Core scope | Clone-visible governance and GitHub/Azure/AWS/GitLab CI/CD signals |
| Exceptions | Waiver registry with owner, reason, and expiry |
| Assurance model | Controls are labelled `deterministic`, `signal`, or `evidence-backed` |

## v6.0.0 development baseline

| Area | v6.0.0.dev0 local branch |
|---|---|
| Profiles | 52 bundled profiles |
| Controls | 212 bundled controls |
| CLI subcommands | 17 |
| Report contracts | `reports/1.0` default; `reports/2.0` opt-in |
| New development profiles | AI/LLM advisory, EU AI Act Article 11 + Annex IV, EU CRA Art.13/14, SLSA Source L1/L2, GitLab L2, OSS publish readiness, AI agent baseline, OSPS Baseline 2026, MCP server, OWASP Agentic ASI |
| Release state | Not released until maintainer review, remote push, tag, PyPI publish, and container publish complete |

## First commands

```bash
python -m pip install oss-policy-kit
python -m oss_policy_kit profiles
python -m oss_policy_kit evaluate --target . --profile github-level-1
```

For the guided adopter flow, use [tutorial-first-pr-gate.md](tutorial-first-pr-gate.md).
