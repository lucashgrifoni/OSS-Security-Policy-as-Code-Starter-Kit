# OSS Policy Kit - evaluation report

- **Generated (UTC)**: `2026-08-06T00:00:00+00:00`
- **Kit version**: `10.0.19`
- **Target**: `hardened-repo`
- **Profile**: `github-level-1` - GitHub OSS starter baseline (level 1)

## Summary

| Status | Count |
| --- | ---: |
| `pass` | 14 |

## Weighted posture score

**28 / 28 points (100.0%)** — risk-adjusted score based on control weights (critical=3, high=2, medium=1). Controls with status `not-applicable` or `not-evaluated` are excluded.

## Prioritization (structural causes)

### Top structural buckets

- (no aggregated structural findings in this run)

### Recommended next actions

- Keep the repository aligned with the profile; review self-attested or not-observable items.

### Failing controls by category

- (no controls in `fail` or `manual-review-required`)

## Waivers and trust boundary

This evaluation only observes what is visible in a local clone (plus optional evidence under `.oss-policy-kit/evidence/`). It **does not** replace human audit or prove absence of risk.

- No external waiver file was passed via `--waivers` in this run. `GOV-WAIV-014` continues to evaluate **versioned in-repo** waivers only.

## Operational warnings

- Signal came from supplemental evidence only; prefer in-repo workflow evidence or API-backed collection for hard gates.

## Controls

| ID | Category | Lifecycle | Assurance | Status | Confidence | Reason | Remediation | Waiver |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `GOV-SEC-001` | governance | stable | `deterministic` | `pass` | high | SECURITY.md present. | Keep SECURITY.md current and linked from the repository README. |  |
| `GOV-CON-002` | governance | stable | `deterministic` | `pass` | high | Contributing guide present. | Keep contribution expectations and security expectations aligned. |  |
| `GOV-COWN-003` | governance | stable | `deterministic` | `pass` | high | CODEOWNERS file present. | Review CODEOWNERS coverage for critical paths. |  |
| `GOV-LIC-004` | governance | stable | `deterministic` | `pass` | high | LICENSE (or COPYING) file detected. | Ensure LICENSE matches declared SPDX and distribution intent. |  |
| `CI-WF-005` | ci_cd | stable | `deterministic` | `pass` | high | Found 3 workflow file(s). | Keep CI workflows minimal, pinned, and least-privilege. |  |
| `CI-PERM-006` | ci_cd | stable | `deterministic` | `pass` | medium | All workflows declare top-level permissions. | Re-audit permissions when adding new jobs. |  |
| `CI-DANGER-007` | ci_cd | stable | `deterministic` | `pass` | medium | No pull_request_target detected in workflows. | Continue avoiding pull_request_target unless necessary. |  |
| `CI-PIN-008` | supply_chain | stable | `deterministic` | `pass` | medium | No obvious mutable third-party action pins detected. | Re-check when editing workflows; verify transitive action versions. |  |
| `CI-LEAST-009` | ci_cd | stable | `signal` | `pass` | medium | No obviously over-broad workflow permissions detected. | Review permissions when adding publishing or release jobs. |  |
| `SEC-CODEQL-010` | vulnerability_management | stable | `signal` | `pass` | high | github/codeql-action usage detected in security.yml. | Keep the CodeQL action pinned to an immutable SHA. |  |
| `SEC-DEPREV-011` | supply_chain | stable | `deterministic` | `pass` | medium | dependency-review-action detected in workflows. | Keep dependency review enabled for pull requests. |  |
| `REL-CHANGE-012` | release | stable | `deterministic` | `pass` | high | Changelog or release notes file detected. | Keep changelog entries aligned with semver and releases. |  |
| `GOV-DISC-013` | governance | stable | `signal` | `pass` | low | SECURITY.md includes private disclosure/reporting cues (heuristic text signal; channel monitoring is not validated from clone-only evidence). | Ensure the reporting channel is monitored and SLA-aligned. |  |
| `GOV-WAIV-014` | governance | stable | `deterministic` | `pass` | high | Versioned waiver file detected in repository. | Keep waivers justified, owned, time-bounded, and reviewed. |  |

## Detail

### `GOV-SEC-001` - SECURITY.md present

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: SECURITY.md present.
- **Remediation**: Keep SECURITY.md current and linked from the repository README.
- **Evidence**:
  - `<redacted-absolute>SECURITY.md`

### `GOV-CON-002` - CONTRIBUTING guide present

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: Contributing guide present.
- **Remediation**: Keep contribution expectations and security expectations aligned.
- **Evidence**:
  - `<redacted-absolute>CONTRIBUTING.md`

### `GOV-COWN-003` - CODEOWNERS configured

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: CODEOWNERS file present.
- **Remediation**: Review CODEOWNERS coverage for critical paths.

### `GOV-LIC-004` - LICENSE file present

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: LICENSE (or COPYING) file detected.
- **Remediation**: Ensure LICENSE matches declared SPDX and distribution intent.

### `CI-WF-005` - GitHub Actions workflows exist

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: Found 3 workflow file(s).
- **Remediation**: Keep CI workflows minimal, pinned, and least-privilege.
- **Evidence**:
  - `<redacted-absolute>ci.yml`
  - `<redacted-absolute>release-example.yml`
  - `<redacted-absolute>security.yml`

### `CI-PERM-006` - Workflows declare explicit top-level permissions

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: medium
- **Reason**: All workflows declare top-level permissions.
- **Remediation**: Re-audit permissions when adding new jobs.

### `CI-DANGER-007` - No pull_request_target without strong justification

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: medium
- **Reason**: No pull_request_target detected in workflows.
- **Remediation**: Continue avoiding pull_request_target unless necessary.

### `CI-PIN-008` - Third-party actions pinned to immutable references

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: medium
- **Reason**: No obvious mutable third-party action pins detected.
- **Remediation**: Re-check when editing workflows; verify transitive action versions.

### `CI-LEAST-009` - Workflow permissions are not obviously over-broad

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `signal`
- **Evidence collection method**: `static`
- **Confidence**: medium
- **Reason**: No obviously over-broad workflow permissions detected.
- **Remediation**: Review permissions when adding publishing or release jobs.

### `SEC-CODEQL-010` - CodeQL or equivalent security scanning in CI

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `signal`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: github/codeql-action usage detected in security.yml.
- **Remediation**: Keep the CodeQL action pinned to an immutable SHA.
- **Evidence**:
  - `<redacted-absolute>security.yml`

### `SEC-DEPREV-011` - Dependency review in pull requests

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: medium
- **Reason**: dependency-review-action detected in workflows.
- **Remediation**: Keep dependency review enabled for pull requests.

### `REL-CHANGE-012` - Changelog or documented release notes

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: Changelog or release notes file detected.
- **Remediation**: Keep changelog entries aligned with semver and releases.

### `GOV-DISC-013` - Responsible disclosure channel documented

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `signal`
- **Evidence collection method**: `static`
- **Confidence**: low
- **Reason**: SECURITY.md includes private disclosure/reporting cues (heuristic text signal; channel monitoring is not validated from clone-only evidence).
- **Remediation**: Ensure the reporting channel is monitored and SLA-aligned.

### `GOV-WAIV-014` - Versioned waiver policy file present in repository (not CLI-only waivers)

- **Status**: `pass`
- **Lifecycle**: stable
- **Assurance**: `deterministic`
- **Evidence collection method**: `static`
- **Confidence**: high
- **Reason**: Versioned waiver file detected in repository.
- **Remediation**: Keep waivers justified, owned, time-bounded, and reviewed.
- **Evidence**:
  - `<redacted-absolute>waivers.yaml`
