# ADR-021 - EPSS + CISA KEV prioritization in SCA

- **Status**: proposed (v6.0.0 Cycle 2)
- **Date**: 2026-05-20
- **Context window**: v6.0.0 Cycle 2, PR-23
- **Related**: `SAST-OSV-068`, `docs/triage-cvss-epss-kev.md`

## Context

Severity alone (CVSS) over-counts. 2026 triage practice triangulates CVSS with
EPSS (30-day exploit probability) and the CISA KEV catalog (confirmed active
exploitation). OSV-Scanner v2+ can emit these signals in SARIF
`result.properties`. The kit already ingests the OSV SARIF for `SAST-OSV-068`.

## Decision

Ship two evidence-backed controls reading the existing OSV SARIF
(`.oss-policy-kit/evidence/sast/osv-scanner.sarif.json`):

- `SCA-KEV-001` — FAIL if any finding carries `properties.kev` truthy. KEV
  overrides standard severity.
- `SCA-EPSS-001` — FAIL if any finding has `epss_score >= 0.5` and (when present)
  `cvss_score >= 7.0`.

Both return manual review when the SARIF is absent. They are bundled into
`appsec-sast-sca-1`.

## Alternatives considered

1. **Call the EPSS/KEV APIs directly.** Rejected — the kit is local-first and
   does not perform network calls during evaluation; the scanner enriches.
2. **A single combined control.** Rejected — KEV (confirmed) and EPSS
   (probabilistic) have different semantics and remediation urgency.

## Consequences

- Findings with confirmed or likely exploitation are surfaced above the backlog.
- Depends on the scanner emitting the properties; absence is honest manual review.

## References

- CISA KEV catalog; EPSS (FIRST)
- v6.0.0 Cycle 2 plan, PR-23; `docs/triage-cvss-epss-kev.md`
