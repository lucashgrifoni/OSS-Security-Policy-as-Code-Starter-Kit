# OSS Policy Kit - evaluation report

- **Generated (UTC)**: `2026-08-06T00:00:00+00:00`
- **Kit version**: `10.0.16`
- **Target**: `vulnerable-repo`
- **Profile**: `github-level-1` - GitHub OSS starter baseline (level 1)

## Summary

| Status | Count |
| --- | ---: |
| `fail` | 11 |
| `manual-review-required` | 1 |
| `pass` | 2 |

## Weighted posture score

**4 / 28 points (14.3%)** — risk-adjusted score based on control weights (critical=3, high=2, medium=1). Controls with status `not-applicable` or `not-evaluated` are excluded.

## Prioritization (structural causes)

### Top structural buckets

- **Governance and release artifacts (README, LICENSE, SECURITY, changelog)** — 7 control(s) failing or requiring manual review in this bucket.
- **GitHub Actions CI/CD (workflows, permissions, pins)** — 3 control(s) failing or requiring manual review in this bucket.
- **Security scanning and vulnerability management in CI** — 2 control(s) failing or requiring manual review in this bucket.

### Recommended next actions

- Add SECURITY.md at the repo root with a monitored private reporting channel.
- Add a recognizable LICENSE file at the repository root.
- Add CONTRIBUTING.md aligned with security expectations.
- Add SAST or code scanning in CI (CodeQL, Semgrep, Bandit, etc.).
- Declare explicit permissions at the top of workflows.

### Failing controls by category

- **ci_cd**: `CI-DANGER-007`, `CI-PERM-006`
- **governance**: `GOV-CON-002`, `GOV-COWN-003`, `GOV-DISC-013`, `GOV-LIC-004`, `GOV-SEC-001`, `GOV-WAIV-014`
- **release**: `REL-CHANGE-012`
- **supply_chain**: `CI-PIN-008`, `SEC-DEPREV-011`
- **vulnerability_management**: `SEC-CODEQL-010`

## Waivers and trust boundary

This evaluation only observes what is visible in a local clone (plus optional evidence under `.oss-policy-kit/evidence/`). It **does not** replace human audit or prove absence of risk.

- No external waiver file was passed via `--waivers` in this run. `GOV-WAIV-014` continues to evaluate **versioned in-repo** waivers only.

## Controls

| ID | Category | Lifecycle | Assurance | Status | Confidence | Reason | Remediation | Waiver |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `GOV-SEC-001` | governance | stable | `deterministic` | `fail` | high | SECURITY.md not found at repository root. | Add SECURITY.md describing supported versions and how to report vulnerabilities. |  |
| `GOV-CON-002` | governance | stable | `deterministic` | `fail` | high | CONTRIBUTING guide not found. | Add CONTRIBUTING.md with workflow, review expectations, and security notes. |  |
| `GOV-COWN-003` | governance | stable | `deterministic` | `fail` | high | CODEOWNERS not found at .github/CODEOWNERS or repository root. | Add CODEOWNERS to route reviews for sensitive areas. |  |
| `GOV-LIC-004` | governance | stable | `deterministic` | `fail` | high | No LICENSE file detected at repository root. | Add a LICENSE file consistent with your SPDX identifier. |  |
| `CI-WF-005` | ci_cd | stable | `deterministic` | `pass` | high | Found 1 workflow file(s). | Keep CI workflows minimal, pinned, and least-privilege. |  |
| `CI-PERM-006` | ci_cd | stable | `deterministic` | `fail` | medium | Workflows missing top-level permissions: unsafe.yml | Declare top-level `permissions:` with the narrowest scope required. |  |
| `CI-DANGER-007` | ci_cd | stable | `deterministic` | `fail` | medium | pull_request_target detected in: unsafe.yml | Remove pull_request_target or restrict to audited, minimal patterns; prefer pull_request. |  |
| `CI-PIN-008` | supply_chain | stable | `deterministic` | `fail` | medium | Mutable action references (tags/branches) detected. | Pin actions to immutable SHAs (40-char commit) from trusted repos. |  |
| `CI-LEAST-009` | ci_cd | stable | `signal` | `pass` | medium | No obviously over-broad workflow permissions detected. | Review permissions when adding publishing or release jobs. |  |
| `SEC-CODEQL-010` | vulnerability_management | stable | `signal` | `fail` | medium | No CodeQL (or equivalent) signal in local workflows. | Add GitHub CodeQL workflow or equivalent SAST in CI. |  |
| `SEC-DEPREV-011` | supply_chain | stable | `deterministic` | `fail` | medium | No dependency-review-action detected in workflows. | Add GitHub Dependency Review to pull request workflows. |  |
| `REL-CHANGE-012` | release | stable | `deterministic` | `fail` | high | No CHANGELOG-style file detected. | Add CHANGELOG.md and reference it from releases. |  |
| `GOV-DISC-013` | governance | stable | `signal` | `fail` | high | Disclosure reporting mechanism not implemented (SECURITY.md missing at repository root). | Add SECURITY.md with a clear reporting channel (email or form). |  |
| `GOV-WAIV-014` | governance | stable | `deterministic` | `manual-review-required` | medium | No versioned waiver policy file found in repository. If waivers are not applicable, create a waivers/ directory with a documented policy statement or use an empty waivers file. | Create waivers/policy.yaml or waivers/README.md documenting the waiver governance approach. |  |

## Detail

### `GOV-SEC-001` - SECURITY.md present

- **Status**: `fail`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: SECURITY.md not found at repository root.
- **Remediation**: Add SECURITY.md describing supported versions and how to report vulnerabilities.

### `GOV-CON-002` - CONTRIBUTING guide present

- **Status**: `fail`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: CONTRIBUTING guide not found.
- **Remediation**: Add CONTRIBUTING.md with workflow, review expectations, and security notes.

### `GOV-COWN-003` - CODEOWNERS configured

- **Status**: `fail`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: CODEOWNERS not found at .github/CODEOWNERS or repository root.
- **Remediation**: Add CODEOWNERS to route reviews for sensitive areas.

### `GOV-LIC-004` - LICENSE file present

- **Status**: `fail`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: No LICENSE file detected at repository root.
- **Remediation**: Add a LICENSE file consistent with your SPDX identifier.

### `CI-WF-005` - GitHub Actions workflows exist

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: Found 1 workflow file(s).
- **Remediation**: Keep CI workflows minimal, pinned, and least-privilege.
- **Evidence**:
  - `<redacted-absolute>/unsafe.yml`

### `CI-PERM-006` - Workflows declare explicit top-level permissions

- **Status**: `fail`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: medium
- **Reason**: Workflows missing top-level permissions: unsafe.yml
- **Remediation**: Declare top-level `permissions:` with the narrowest scope required.
- **Evidence**:
  - `<redacted-absolute>/unsafe.yml`

### `CI-DANGER-007` - No pull_request_target without strong justification

- **Status**: `fail`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: medium
- **Reason**: pull_request_target detected in: unsafe.yml
- **Remediation**: Remove pull_request_target or restrict to audited, minimal patterns; prefer pull_request.
- **Evidence**:
  - `<redacted-absolute>/unsafe.yml`

### `CI-PIN-008` - Third-party actions pinned to immutable references

- **Status**: `fail`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: medium
- **Reason**: Mutable action references (tags/branches) detected.
- **Remediation**: Pin actions to immutable SHAs (40-char commit) from trusted repos.
- **Evidence**:
  - `unsafe.yml: actions/checkout@v4`

### `CI-LEAST-009` - Workflow permissions are not obviously over-broad

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `signal`
- **Evidence collection method**: `static`
- **Confidence**: medium
- **Reason**: No obviously over-broad workflow permissions detected.
- **Remediation**: Review permissions when adding publishing or release jobs.

### `SEC-CODEQL-010` - CodeQL or equivalent security scanning in CI

- **Status**: `fail`
- **Lifecycle**: stable
- **Assurance**: `signal`
- **Evidence collection method**: `static`
- **Confidence**: medium
- **Reason**: No CodeQL (or equivalent) signal in local workflows.
- **Remediation**: Add GitHub CodeQL workflow or equivalent SAST in CI.

### `SEC-DEPREV-011` - Dependency review in pull requests

- **Status**: `fail`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: medium
- **Reason**: No dependency-review-action detected in workflows.
- **Remediation**: Add GitHub Dependency Review to pull request workflows.

### `REL-CHANGE-012` - Changelog or documented release notes

- **Status**: `fail`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: No CHANGELOG-style file detected.
- **Remediation**: Add CHANGELOG.md and reference it from releases.

### `GOV-DISC-013` - Responsible disclosure channel documented

- **Status**: `fail`
- **Lifecycle**: stable
- **Assurance**: `signal`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: Disclosure reporting mechanism not implemented (SECURITY.md missing at repository root).
- **Remediation**: Add SECURITY.md with a clear reporting channel (email or form).

### `GOV-WAIV-014` - Versioned waiver policy file present in repository (not CLI-only waivers)

- **Status**: `manual-review-required`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: medium
- **Reason**: No versioned waiver policy file found in repository. If waivers are not applicable, create a waivers/ directory with a documented policy statement or use an empty waivers file.
- **Remediation**: Create waivers/policy.yaml or waivers/README.md documenting the waiver governance approach.
