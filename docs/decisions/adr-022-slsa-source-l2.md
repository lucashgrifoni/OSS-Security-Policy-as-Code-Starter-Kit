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

## Amendment (2026-08) — the evidence shape, and why SLSA-SRC-007 is manual review

The Decision above names two top-level fields, `required_signatures` and
`required_approving_review_count`. Neither exists. `evidence-branch-protection.schema.json`
is closed at both levels (`additionalProperties: false` on the root and on `protections`),
the flags live under `protections`, and no approver-count field is defined anywhere in it.
This amendment is normative and supersedes the conflicting wording; the schema itself is
unchanged.

### Amended shape

1. **`SLSA-SRC-006` reads `protections.require_signed_commits`**, not top-level
   `required_signatures`. The flag is optional in `branch-protection/v1` and
   `collect-evidence` does not emit it, so its absence is a gap in the attestation rather
   than a statement that signing is unenforced: the control answers
   `manual-review-required` (ADR-045), `pass` on `true`, `fail` on `false`.
2. **`SLSA-SRC-007` cannot verify the `>= 2` threshold at all.** The only review fact
   `branch-protection/v1` carries is `protections.require_pull_request_reviews`, a boolean.
   `false` is a `fail` — zero required approvals cannot meet L2. `true` proves >= 1 and says
   nothing about >= 2, so the control answers `manual-review-required`; reading that boolean
   as a count would turn unknown into clean, which is the one thing this kit does not do.
   The threshold stays a human check until the evidence schema gains a field for it, and
   changing the schema is a separate decision this amendment does not take.

## References

- SLSA v1.2 Source requirements
- v6.0.0 Cycle 2 plan, PR-25; ADR-006
- ADR-045 — unreadable or unstated evidence is manual review, never fail
