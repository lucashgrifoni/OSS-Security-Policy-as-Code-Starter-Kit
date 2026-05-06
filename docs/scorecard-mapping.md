# OpenSSF Scorecard mapping (concrete)

[OpenSSF Scorecard](https://scorecard.dev/) provides automated checks for OSS repositories.
This kit is **complementary**, not a replacement; it accepts a Scorecard JSON export as
supplemental input via `--scorecard-json` and surfaces an explicit threshold control
(`OSS-SCORECARD-001`).

For the master cross-framework mapping (Scorecard, OWASP CICD Top 10, SLSA v1.0, NIST SSDF,
S2C2F, OSPS, CIS SSCS, AWS Well-Architected, Azure DevOps Security), see
[framework-alignment.md](framework-alignment.md).

## How Scorecard fits in this kit

Optional input on `evaluate`:

```bash
python -m oss_policy_kit evaluate \
  --target ./repo \
  --profile github-level-1 \
  --scorecard-json ./scorecard.json
```

The JSON adapter accepts the standard Scorecard shape (`checks: [...]`) and a few common
nested forms (e.g., `scorecard.checks: [...]`).

The kit uses Scorecard JSON as **supplemental evidence** in two places:

1. `OSS-SCORECARD-001` (signal grade): a per-profile "Scorecard score meets minimum threshold"
   gate. Without `--scorecard-json` the control resolves to `not-evaluated`.
2. `SEC-CODEQL-010` (signal grade): may project to `pass` when Scorecard exposes a check whose
   name suggests static analysis posture (for example `Code-QL`), **only if** local workflow
   detection has not already passed it deterministically.

Scorecard does not influence `deterministic` or `evidence-backed` rows — those decisions stand
on their own.

## Per-check coverage matrix

The table below maps every Scorecard check (v4-line) to the bundled kit control(s) that
exercise it. Coverage labels follow the convention from
[framework-alignment.md](framework-alignment.md): YES / PARTIAL / OUT (intentionally not
modeled) / GAP (registered as future work).

| Scorecard check | Kit control(s) | Coverage | Notes |
|---|---|---|---|
| `Binary-Artifacts` | (none) | OUT | Pure-binary detection is not in scope; Scorecard JSON surfaces it externally. |
| `Branch-Protection` | `PLAT-BRPROT-015` | YES | Evidence-backed; collected by `collect-evidence --platform github`. |
| `CI-Tests` | `CI-WF-005`, `AZ-PIPE-027`, `AWS-CI-037` | PARTIAL | We confirm CI files exist; Scorecard separately checks test-run history (platform-side). |
| `CII-Best-Practices` | (none) | OUT | The OpenSSF Best Practices Badge is a separate program and not modeled. |
| `Code-Review` | `GH-PLAT-024`, `PLAT-BRPROT-015`, `GH-PLAT-026` | YES | Required reviewers + status checks + environment approvals. |
| `Contributors` | (none) | OUT | Contributor breadth is not analyzed. |
| `Dangerous-Workflow` | `CI-DANGER-007`, `GH-WF-019`, `GH-WF-020`, `AZ-PIPE-029` | YES | Multiple deterministic checks against unsafe workflow patterns. |
| `Dependency-Update-Tool` | `DEP-UPDATE-001`, `SEC-DEPREV-011` | YES | Dependabot / Renovate config + dependency-review-action detection. |
| `Fuzzing` | (none) | OUT | Not required by this kit. |
| `License` | `GOV-LIC-004` | YES | Deterministic file presence. |
| `Maintained` | (none) | OUT | Maintenance cadence is not inferred from a single snapshot. |
| `Packaging` | (none) | OUT | Publishing-side signals are out of scope. |
| `Pinned-Dependencies` | `CI-PIN-008`, `SEC-PINLOCK-052`, `CI-WFCALLSHA-055`, `CONT-IMAGE-001` | YES | Four deterministic angles: third-party actions, lockfiles, reusable workflow SHAs, container base images. |
| `SAST` | `SEC-CODEQL-010` | PARTIAL | `signal` grade — we detect CodeQL/SAST tool presence in CI YAML; Scorecard can confirm tool runs. |
| `Security-Policy` | `GOV-SEC-001`, `GOV-DISC-013` | YES | SECURITY.md present + responsible disclosure heuristic. |
| `Signed-Releases` | `GH-PROV-023`, `AZ-ARTPRV-059`, `AWS-PROVART-059` | PARTIAL | Detection signal in workflows + artifact-bound provenance evidence; cosign / sigstore signature verification not performed. |
| `Token-Permissions` | `CI-PERM-006`, `GH-WF-020`, `CI-LEAST-009` | YES | Top-level perms + job-level write scopes + breadth heuristic. |
| `Vulnerabilities` | `OSS-SCORECARD-001` | INDIRECT | The kit accepts Scorecard JSON; it does not query the OSV API itself. |
| `Webhooks` | (none) | OUT | Repository-webhook posture is not modeled. |

**Coverage**: 11 YES, 3 PARTIAL, 5 OUT, 0 GAP, 1 INDIRECT.

## Evidence flow with Scorecard

```text
Scorecard runs in CI ─→ scorecard.json
                            │
                            ▼
     evaluate --scorecard-json ./scorecard.json
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
   OSS-SCORECARD-001 reads          SEC-CODEQL-010 may project
   `score` and gates on threshold   to PASS when a CodeQL-shaped
                                    Scorecard check is present
                                    (and local workflow detection
                                    didn't already pass it)
```

The Scorecard JSON is **never** mutated and **never** elevates a control beyond `signal` grade.
A Scorecard-derived `pass` projects with `trust_level: inferred`, never `verified`. This is
intentional and matches the catalog's `assurance: signal` constraint
([signal-controls-audit.md](signal-controls-audit.md)).

## What Scorecard cannot prove on its own

Scorecard alone does not establish:

- Full OSPS Baseline alignment (see [osps-mapping.md](osps-mapping.md)).
- That your threat model is adequate for your application class.
- That your release process is end-to-end safe.
- Live platform configuration not exposed via Scorecard's checks (e.g., environment approval
  reviewer lists, service connection IAM scope).

Treat Scorecard exports as **additional evidence**, not as a final verdict. Pair Scorecard with
this kit's `*-level-3` or `*-release-hardening-3` profiles to gate on platform-evidence too.

## See also

- [framework-alignment.md](framework-alignment.md) — master cross-framework mapping.
- [controls-catalog.md](controls-catalog.md) — full catalog of 65 controls.
- [signal-controls-audit.md](signal-controls-audit.md) — why signal-grade controls cannot
  project to `verified`.
- [results-guide.md](results-guide.md) — interpreting result statuses (`pass`, `fail`,
  `manual-review-required`, `self-attested`, etc.).
