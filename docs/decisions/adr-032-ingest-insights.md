# ADR-032 - Ingest a project's OpenSSF Security Insights file (`ingest-insights`, v6.7.0)

- **Status**: accepted (v6.7.0, ADDITIVE / non-breaking) — shipped as the `ingest-insights` command; status line flipped 2026-09-15 after confirming the command is in the released CLI
- **Date**: 2026-05-29
- **Context window**: v7.x roadmap horizon — "Contract modernization & ecosystem interoperability", shipped early as a v6.x additive minor (roadmap decision §11.1: defer the breaking `reports/2.0` flip one cycle; ship low-risk interop first — same lane as ADR-031 OpenVEX)
- **Related**: ADR-011 (`emit-insights` scope), ADR-002 (`emit-vex` scope), ADR-031 (OpenVEX export), `docs/insights-emission.md`, the maintainer's local roadmap (not published) (v7.x)

## Context

The kit **already emits** an OpenSSF Security Insights 1.0 document (`emit-insights`, ADR-011):
it re-projects clone-visible signals into `security-insights.yml`. The **symmetric gap** is
consumption: when the repository being evaluated *already publishes* a `SECURITY-INSIGHTS.yml`,
the kit ignores it. That file is the project's own machine-readable, **self-reported** security
posture (vulnerability-reporting channel, security contacts, project lifecycle, distribution
points). Scorecard v6 **ingests** Security Insights; CLOMonitor and LFX Insights consume it too.
The kit emitting but not ingesting is an interoperability asymmetry the v7.x horizon calls out
(the maintainer's local roadmap (not published) v7.x; roadmap plan §3.6, §6 v7.x).

This is **additive**: a new subcommand that reads, structurally validates, and reports a file the
target already contains. It does not change `evaluate`, the control catalog, the 212 evaluators,
the report contracts (`reports/1.0`/`2.0`), or any existing exit-code semantics — so it ships as a
minor (v6.7.0), not a major.

### The honesty problem this ADR must pin down

A `SECURITY-INSIGHTS.yml` is **self-asserted by the project author**. It is not independent
evidence: a project can claim "accepts vulnerability reports: true" without that being verifiable
from the clone. The kit's core guard-rail is assurance honesty — never inflate a pass/fail gate
with a weak or self-reported signal (`controlled-evolution` guard-rail §5.3; README non-goals).
So the central decision is **what ingestion is allowed to do**, and — just as important — **what it
must not do**.

## Decision

In **v6.7.0**, add `oss-policy-kit ingest-insights`: a **read-only, report-only** subcommand that
discovers, parses, structurally validates, and summarizes the target's Security Insights file as an
explicitly **self-reported** posture summary.

### Scope (v6.7.0)

1. **Discover** the file at conventional locations under `--target` (override with `--input`):
   `SECURITY-INSIGHTS.yml`/`.yaml`, `.github/SECURITY-INSIGHTS.yml`/`.yaml`, and the kit's own
   lowercase emit name `security-insights.yml`/`.yaml` (root and `.github/`), then `docs/`.
2. **Parse** the YAML (size-bounded, UTF-8, `yaml.safe_load`).
3. **Validate** structure against the OpenSSF Security Insights 1.0 shape the kit already knows
   (`header` + `header.schema-version` + `header.last-updated` + `project-lifecycle.status`),
   reusing the schema-version constant from `emit-insights` so emit↔ingest never drift.
4. **Report** the recognized self-reported signals (human table + `--format json`), each labelled
   with `provenance: self-reported`.

### What `ingest-insights` MUST NOT do (assurance fence)

- **It does not feed `evaluate`.** No control's PASS/FAIL/UNKNOWN verdict changes because a
  `SECURITY-INSIGHTS.yml` exists. Wiring Insights fields into specific controls as a
  `self-attested` evidence source is a **separate, follow-up increment** that requires an
  explicit per-control honest-mapping decision (which controls, what status, what provenance
  label). That is deliberately **out of scope for v6.7.0** and tracked for a later ADR, so the
  evidence model stays honest and this release stays contract-safe and regression-free.
- **It does not turn self-report into proof.** Output provenance is always `self-reported`; the
  human output carries a one-line caveat that the kit did not independently verify the claims.
- **It does not fetch anything.** Clone-local file only (same posture as `emit-insights`).
- **It does not mutate** the target or write files.

### Exit-code contract

| Code | Meaning |
|---|---|
| 0 | A valid file was found and summarized **or** no file was found (informational — nothing to ingest). |
| 1 | A file was found but failed structural validation (missing required fields / not a YAML object / unparseable). |
| 2 | Usage error (an explicit `--input` path does not exist; `--target` is not a directory). |

A declared `schema-version` other than the supported `1.0.0` is a **warning, not an error** (a
newer upstream file is still useful to summarize); it does not flip the exit code. This is more
lenient than `emit-insights --validate` (which controls its own output), by design: ingestion
consumes third-party files.

### JSON output shape (new, minimal, stable)

```json
{
  "tool": "oss-policy-kit ingest-insights",
  "kit_version": "6.7.0",
  "schema_version_supported": "1.0.0",
  "found": true,
  "input_path": "SECURITY-INSIGHTS.yml",
  "valid": true,
  "provenance": "self-reported",
  "declared_schema_version": "1.0.0",
  "validation_errors": [],
  "validation_warnings": [],
  "signals": {
    "project_lifecycle_status": "active",
    "accepts_vulnerability_reports": true,
    "security_policy_url": "https://github.com/org/repo/blob/main/SECURITY.md",
    "security_contacts": ["security@example.com"],
    "accepts_pull_requests": true,
    "has_dependency_automation_policy": true,
    "distribution_points": []
  }
}
```

`signals` values are `null`/`[]`/`false` when the corresponding field is absent. The change is
validated by `cli-api-ui-contract-validator` (new subcommand + new JSON shape, no change to any
existing contract) and by tests that pin the exit codes and the `provenance` label.

## Alternatives considered

1. **Wire Insights into existing controls as evidence now (the backlog item's full acceptance
   bar: "≥3 controls accept Insights as evidence").** Rejected for v6.7.0 — it changes
   `evaluate` behavior, touches the 212-evaluator core and golden reports, and needs an honest
   per-control mapping decision that does not exist yet. Splitting it out keeps this release
   additive, regression-free, and shippable in one cycle; the wiring follows once the mapping is
   decided (controlled-evolution: ship the safe increment, fence the risky one).
2. **Fold ingestion into `evaluate` (e.g. `evaluate --insights`).** Rejected — bundles gate
   evaluation with external-format consumption; `emit-vex`/`emit-insights` set the precedent of
   dedicated, single-purpose interop subcommands.
3. **Strict 1.0.0-only validation (hard-fail on any other version).** Rejected — too strict for
   consuming files other tools produced; version mismatch is reported as a warning instead.
4. **Bundle the full OpenSSF Security Insights JSON Schema.** Rejected for v6.7.0 — matches the
   existing `emit-insights` choice (lightweight structural validation, lean dependency); full
   schema validation can follow additively.

## Consequences

- The kit becomes a Security Insights **consumer** as well as a **producer**, closing the
  emit↔ingest asymmetry and feeding the v7.x interoperability narrative — with **zero** change to
  the evaluation engine or any existing contract.
- Adopters get a one-command check that their published `SECURITY-INSIGHTS.yml` parses and carries
  the expected fields, and a JSON summary other tooling can consume.
- The assurance-honesty guard-rail is preserved explicitly: self-reported stays self-reported;
  nothing inflates a gate.
- Trade-off: the kit now has emit and ingest paths for Security Insights that must track the same
  spec version; mitigated by sharing the `_INSIGHTS_SCHEMA_VERSION` constant and by a test that
  round-trips an `emit-insights` document back through `ingest-insights`.

## References

- [OpenSSF Security Insights spec](https://security-insights.openssf.org/) + [GitHub repo](https://github.com/ossf/security-insights)
- ADR-011 (`emit-insights` scope) — the producer side this mirrors
- ADR-031 (OpenVEX export) — the v6.x additive-interop precedent (same roadmap §11.1 lane)
- the maintainer's local roadmap (not published) (v7.x horizon); roadmap plan §3.6, §6 (v7.x)
- `docs/insights-emission.md` — companion producer guide; `docs/insights-ingestion.md` — consumer guide (added with this change)
