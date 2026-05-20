# OSPS Baseline v2026.02.19 mapping

> **Advisory mapping. Not a compliance certification.** This document maps the
> kit's clone-visible controls to the OpenSSF Open Source Project Security
> Baseline snapshot **v2026.02.19**, and explains the Scorecard v6 conformance
> hook. See ADR-018.

## Profiles

- `osps-baseline-1` — original mapping, retained for compatibility.
- `osps-baseline-2026-1` — snapshot-pinned to v2026.02.19, **canonical**. Adds
  `OSPS-SCORECARD-V6-001`.

The OSPS Baseline is a rolling release. The kit pins snapshots as parallel
profiles (`osps-baseline-YYYY-*`) so adopters can declare a known version rather
than chase a moving target.

## Scorecard v6 conformance

OpenSSF Scorecard v6 adds an OSPS conformance verdict (`PASS / FAIL / UNKNOWN`)
alongside the classic 0-10 score. `OSPS-SCORECARD-V6-001` (evidence-backed)
consumes that report:

```bash
scorecard --format=osps --repo=<url> > scorecard-osps.json
mkdir -p .oss-policy-kit/evidence
cp scorecard-osps.json .oss-policy-kit/evidence/
```

| Evidence state | Control result |
|---|---|
| `scorecard-osps.json` with `conformance: pass` | PASS |
| `scorecard-osps.json` with `conformance: fail` | FAIL |
| classic `scorecard.json` only | manual review |
| no evidence | manual review |

Until Scorecard v6 `--format=osps` reaches GA, the control returns manual review
rather than a false PASS.

## Coverage areas

The `osps-baseline-2026-1` profile maps existing controls to the four OSPS
Baseline areas: Access Control, Build & Release, Documentation, and Quality &
Security Assessment. See the profile definition for the per-area control list.
