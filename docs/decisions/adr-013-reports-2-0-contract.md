# ADR-013 - reports/2.0 contract with a five-state vocabulary

- **Status**: accepted (v6.0.0)
- **Date**: 2026-05-19
- **Context window**: v6.0.0 Cycle 1, PR-16 (V6-05, BREAKING)
- **Related**: `docs/reports-contract-v2.0.md`, `scripts/migrate-1.0-to-2.0.py`

## Context

The `reports/1.0` contract used a status vocabulary that did not align with the
OpenSSF Scorecard v6 conformance model (`PASS / FAIL / UNKNOWN / NOT_APPLICABLE`).
As the kit positions itself as a local-first evidence layer that composes with
Scorecard and ASPM tooling, the report status vocabulary needed to converge.

A vocabulary change is breaking for any consumer that parses report JSON. It must
not be forced on existing adopters mid-major.

## Decision

Register a parallel `reports/2.0` contract with a five-state vocabulary:
`PASS / FAIL / UNKNOWN / NOT_APPLICABLE / ATTESTED`. The `schema_version` is an
absolute URL (consistent with M-003, ADR-008).

`reports/1.0` **remains the default** in `6.0.0.dev0`. `reports/2.0` is opt-in.
The default-switch is deferred to a later v6.x point release. A standalone
`scripts/migrate-1.0-to-2.0.py` converts offline reports between vocabularies.

## Alternatives considered

1. **Bump `reports/1.0` in place.** Rejected — silently changing status strings
   would break consumers without a migration path.
2. **Default to `reports/2.0` immediately.** Rejected — too disruptive inside a
   single dev release; staged rollout preserves trust.
3. **Skip `ATTESTED`.** Rejected — the kit distinguishes evidence-backed
   attested results from plain passes, and the vocabulary should carry that.

## Consequences

- Consumers can adopt the Scorecard-aligned vocabulary on their own schedule.
- The migration script makes the transition mechanical for stored reports.
- Two contracts coexist during v6.0.x, which is documented as intentional.

## References

- OpenSSF Scorecard v6 conformance model
- v6.0.0 Cycle 1 plan, PR-16
- `docs/reports-contract-v2.0.md`, `scripts/migrate-1.0-to-2.0.py`
