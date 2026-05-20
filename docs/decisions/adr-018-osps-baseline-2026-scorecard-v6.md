# ADR-018 - OSPS Baseline v2026.02.19 + Scorecard v6 conformance

- **Status**: proposed (v6.0.0 Cycle 2)
- **Date**: 2026-05-20
- **Context window**: v6.0.0 Cycle 2, PR-20
- **Related**: `osps-baseline-1`, `docs/osps-baseline-2026-mapping.md`

## Context

The OpenSSF OSPS Baseline is a rolling release; the current snapshot is
**v2026.02.19**. OpenSSF Scorecard v6 adds an OSPS conformance verdict
(`PASS / FAIL / UNKNOWN`) alongside the classic 0-10 score. The kit's existing
`osps-baseline-1` profile maps to an earlier snapshot and has no Scorecard v6
hook.

## Decision

Ship `osps-baseline-2026-1`, a snapshot-pinned profile aligned to v2026.02.19,
plus `OSPS-SCORECARD-V6-001` (evidence-backed). The control consumes a
`scorecard --format=osps` report at `.oss-policy-kit/evidence/scorecard-osps.json`
when present, falls back to manual review if only a classic Scorecard result
exists, and to manual review when no evidence is present. `osps-baseline-1` is
retained for compatibility; the 2026 snapshot is canonical.

## Alternatives considered

1. **Mutate `osps-baseline-1` in place.** Rejected — the Baseline is a rolling
   standard; snapshots should be parallel profiles (`osps-baseline-YYYY-*`) so
   adopters can pin a known version.
2. **Make `OSPS-SCORECARD-V6-001` signal-grade.** Rejected — the verdict comes
   from an external tool report, which is exactly an evidence-backed input.

## Consequences

- Procurement-driven adopters can declare a pinned OSPS snapshot.
- When Scorecard v6 `--format=osps` reaches GA, the control already consumes it.
- Until then the control returns manual review, which is honest, not a false PASS.

## References

- OSPS Baseline (baseline.openssf.org), Scorecard v6 PR #4952
- v6.0.0 Cycle 2 plan, PR-20
