# ADR-022 - SLSA v1.2 Source Track Level 2

- **Status**: proposed (v6.0.0 Cycle 2)
- **Date**: 2026-05-20
- **Context window**: v6.0.0 Cycle 2, PR-25
- **Related**: ADR-006 (`slsa-source-l1-1`), `AUDIT-STREAM-060`

## Context

SLSA v1.2 (Nov 2025) formalised the Source Track. L1 (shipped as
`slsa-source-l1-1`, ADR-006) covers version control, branch protection, and
two-party review presence. L2 adds enforced signed commits, a stricter review
threshold (>= 2 approvers), and externally streamed source audit logs.

## Decision

Ship three controls and a `slsa-source-l2-1` profile:

- `SLSA-SRC-006` (evidence-backed) — `required_signatures` enforced in
  `branch-protection.json`.
- `SLSA-SRC-007` (evidence-backed) — `required_approving_review_count >= 2`.
- `SLSA-SRC-008` (evidence-backed) — source-change audit log streamed externally
  (delegates to `AUDIT-STREAM-060`).

The profile bundles `SLSA-SRC-001..008` so it is a self-contained L2 posture.
Advisory; `--fail-on degraded`.

## Alternatives considered

1. **Reuse `SLSA-SRC-002` (signal) for signed commits.** Rejected — L2 requires
   *enforced* signatures, which is an evidence-backed branch-protection fact, not
   a heuristic.
2. **Single L1+L2 profile.** Rejected — keeping `slsa-source-l1-1` separate lets
   adopters declare the exact level they meet.

## Consequences

- Teams already at Source L1 get a clear L2 upgrade path.
- L2 controls require branch-protection evidence; absence is manual review.

## References

- SLSA v1.2 Source requirements
- v6.0.0 Cycle 2 plan, PR-25; ADR-006
