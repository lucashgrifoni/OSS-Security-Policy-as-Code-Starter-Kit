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
python -P -m oss_policy_kit evaluate \
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

## Ingesting a result with `ingest-scorecard` (read-only)

`oss-policy-kit ingest-scorecard` is the read-only consumer for a Scorecard v5.x JSON result. It maps
each Scorecard check to the kit control it **corroborates**, records Scorecard's own per-check score and
reason **verbatim**, and reports the result's freshness — symmetric with `ingest-insights`.

```bash
scorecard --repo=github.com/you/your-repo --format=json > .oss-policy-kit/evidence/scorecard-result.json
oss-policy-kit ingest-scorecard                       # auto-discovers the file under --target
oss-policy-kit ingest-scorecard --input result.json --format json
```

Exit codes: `0` found-and-parsed or not-found (informational); `1` a result file was found but could
not be parsed; `2` usage error; `3` unexpected internal error.

**Honesty model.** A Scorecard result is **supplemental, inferred-trust signal**. `ingest-scorecard`
**never** elevates a control's assurance grade and changes **no** `evaluate` verdict — it reports how an
external Scorecard result lines up with the kit's controls. A Scorecard run older than **90 days** (by its
`date` field) is reported as `stale` and counts as no current corroboration; an undated result is `undated`.

**Command crosswalk** (the single best-fit control per check that the command reports; the full per-check
matrix below lists every related control). Source of truth: `SCORECARD_CONTROL_MAP` in
[`application/scorecard_ingest.py`](../src/oss_policy_kit/application/scorecard_ingest.py).

| Scorecard check | kit control | note |
| --- | --- | --- |
| `Token-Permissions` | `CI-PERM-006` | OSPS-AC-04 — least-privilege workflow tokens |
| `Pinned-Dependencies` | `CI-PIN-008` | OSPS-BR-01 — pinned third-party actions/deps |
| `Dangerous-Workflow` | `CI-DANGER-007` | dangerous workflow patterns |
| `Branch-Protection` | `PLAT-BRPROT-015` | OSPS-AC-03 — default branch protection |
| `Code-Review` | `SLSA-SRC-004` | two-party review on protected branches |
| `Security-Policy` | `GOV-SEC-001` | OSPS-VM-01 — security policy present |
| `SAST` | `SEC-CODEQL-010` | OSPS-VM-06 — static analysis in CI |
| `Signed-Releases` | `GH-PROV-023` | OSPS-BR-06 — release provenance/attestation |
| `Vulnerabilities` | `SAST-OSV-068` | known-vulnerability scanning |
| `Fuzzing` | `SEC-FUZZ-001` | fuzzing harness present |
| `Dependency-Update-Tool` | `DEP-UPDATE-001` | automated dependency updates |
| `License` | `GOV-LIC-004` | license file present |

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
| `Fuzzing` | `SEC-FUZZ-001` | PARTIAL | `signal` grade — fuzz-harness presence or a Scorecard `Fuzzing` score ≥7; coverage quality is not proven. |
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

**Coverage**: 11 YES, 4 PARTIAL, 4 OUT, 0 GAP, 1 INDIRECT.

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
- [controls-catalog.md](controls-catalog.md) — generated bundled controls catalog.
- [signal-controls-audit.md](signal-controls-audit.md) — why signal-grade controls cannot
  project to `verified`.
- [results-guide.md](results-guide.md) — interpreting result statuses (`pass`, `fail`,
  `manual-review-required`, `self-attested`, etc.).
