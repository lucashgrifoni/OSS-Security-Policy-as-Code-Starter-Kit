# OpenSSF Security Insights emission (`emit-insights`)

> **In development (v6.0.0)**. The `emit-insights` subcommand and the renderer it depends on land with PR-8 on the `feat/v6.0.0-evolution` branch. **They do not ship in v5.9.x.** This page is the design and adopter guide for what will be available when v6.0.0 GA ships.

This page is the OpenSSF Security Insights companion to [`vex-emission.md`](vex-emission.md). It follows the same architectural pattern: a dedicated subcommand that re-projects existing evaluator outputs into a stable external format, without adding new controls to the catalog.

## What is OpenSSF Security Insights 1.0?

[OpenSSF Security Insights 1.0](https://security-insights.openssf.org/) is a YAML format that lets an OSS project publish machine-readable security metadata: security contacts, vulnerability disclosure process, build provenance posture, dependency policy, distribution points. The format is stable since 2023 and is consumed by:

- **Scorecard v6** (when its `--format=osps` ships).
- **CLOMonitor**.
- **OSPS Baseline Scanner**.
- Several ASPM SaaS platforms.

A project that publishes a valid `security-insights.yml` at the conventional location (root of repository) becomes machine-introspectable by the broader OSS-security ecosystem.

## How `emit-insights` will work

```text
$ oss-policy-kit emit-insights --target . --output security-insights.yml --validate
```

The subcommand:

1. **Reads the target repository** — same `--target` semantics as `evaluate`.
2. **Reuses existing evaluators read-only** — no new controls, no side effects on the catalog.
3. **Renders YAML** into the target path (default `./security-insights.yml`).
4. **Optionally validates** the output against the OpenSSF Security Insights 1.0 JSON Schema when `--validate` is passed.
5. **Exits 0** on successful emission, **1** on validation failure, **2** on usage errors.

## Field mapping (planned)

| Insights 1.0 field | Source in the kit | Control / signal |
|---|---|---|
| `header.schema-version: 1.0.0` | Constant. | n/a |
| `header.last-updated` | `date -u` at emit time. | n/a |
| `project.name` | Inferred from `git remote -v` plus `README.md`. | n/a |
| `project.homepage` | Inferred from `git remote -v` (web URL of the origin). | n/a |
| `project.administrators` | `CODEOWNERS` parse. | `GOV-COWN-001` |
| `contributing-policy` | `CONTRIBUTING.md` presence. | `GOV-CON-002` |
| `code-of-conduct` | `CODE_OF_CONDUCT.md` presence. | n/a (no current control; emit only) |
| `security-policy` | `SECURITY.md` presence. | `GOV-SEC-001` |
| `security-contacts` | Parsed from `SECURITY.md` (email / form patterns). | `GOV-DISC-013` |
| `vulnerability-reporting.accepts-vulnerability-reports` | `true` if `SECURITY.md` documents a channel. | `GOV-DISC-013` |
| `vulnerability-reporting.security-policy` | URL to `SECURITY.md`. | `GOV-SEC-001` |
| `vulnerability-reporting.in-scope` / `out-of-scope` | Best-effort parse. | n/a |
| `vulnerability-reporting.email-contact` | Parsed from `SECURITY.md`. | `GOV-DISC-013` |
| `vulnerability-reporting.acknowledgement-sla` | From `.oss-policy-kit/evidence/disclosure-policy.json` (`acknowledgement_sla_hours`). | `GOV-DISC-065` |
| `vulnerability-reporting.triage-sla` | From the same evidence file (`triage_sla_hours`). | `GOV-DISC-065` |
| `dependencies.dependencies-lifecycle` | "regenerated automatically" if Dependabot/Renovate present; "manual" otherwise. | `DEP-UPDATE-001` |
| `dependencies.env-dependencies-policy` | Best-effort from lockfile presence. | `SEC-PINLOCK-052` |
| `dependencies.sbom` | URL to bundled SBOM if `BUILD-SBOM-QUAL-003` finds one. | `BUILD-SBOM-QUAL-003` |
| `distribution-points` | List of CI publish targets inferred from publish workflows. | n/a |
| `release.attestation.predicate-uri` | "https://slsa.dev/provenance/v1" if `PROV-VERIFY-061` evidence file present. | `PROV-VERIFY-061` |
| `release.changelog` | URL to `CHANGELOG.md` if present. | `REL-CHANGE-001` |

Fields not in the table are either Insights-spec optional (skipped if no signal) or out of scope for the kit's clone-visible posture.

## What `emit-insights` will not do

- Run any of the kit's own gates. It is emit-only; pair it with `oss-policy-kit evaluate` when you want a gate decision.
- Fetch external data. It works from the local clone plus optional evidence files.
- Validate the *contents* of the emitted YAML beyond JSON-Schema conformance. Adopters should run their own consumer (Scorecard v6 / CLOMonitor) to verify upstream interpretation.
- Add new controls to the kit's catalog. If a new control is needed to surface a previously-undetected signal, that is a separate ADR.

## What you should still do after emission

1. **Commit `security-insights.yml`** to the repository root (the conventional location).
2. **Periodically re-emit** when SECURITY.md, disclosure SLA, dependency policy, or release process changes. A CI step is straightforward (`emit-insights` on every push to main).
3. **Check downstream consumption** at least once after first publication: does Scorecard v6 read your file? Does CLOMonitor? File issues upstream if a consumer interprets a field unexpectedly.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Emission successful; if `--validate` was passed, validation also passed. |
| 1 | Emission completed but `--validate` was passed and the output failed schema validation. |
| 2 | Usage error (bad flags, missing target, etc.). |

## References

- [OpenSSF Security Insights spec](https://security-insights.openssf.org/) — canonical schema and field semantics
- [OpenSSF Security Insights GitHub repo](https://github.com/ossf/security-insights)
- ADR-011 — design rationale for the subcommand
- ADR-002 (`emit-vex` scope) — architectural precedent
- [`vex-emission.md`](vex-emission.md) — companion page for VEX emission
