| Status | Count |
| --- | ---: |
| `pass` | 14 |
| ID | Category | Lifecycle | Assurance | Status | Confidence | Reason | Remediation | Waiver |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `GOV-SEC-001` | governance | stable | `deterministic` | `pass` | high | SECURITY.md present. | Keep SECURITY.md current and linked from the repository README. |  |
| `GOV-CON-002` | governance | stable | `deterministic` | `pass` | high | Contributing guide present. | Keep contribution expectations and security expectations aligned. |  |
| `GOV-COWN-003` | governance | stable | `deterministic` | `pass` | high | CODEOWNERS names an owner for 1 path pattern(s). | Review CODEOWNERS coverage for critical paths. |  |
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
