# ADR-043 — Remove the legacy pre-2.0 report contracts (v9.0.0)

- **Status**: accepted (targets v9.0.0, BREAKING) — ratified 2026-06-19
- **Date**: 2026-06-19
- **Related**: ADR-027 (reports/2.0 default flip, which promised the removal "after one cycle"), ADR-041 (v8.0.0 defaults), the maintainer's local roadmap (not published) §11.1

## Context

`reports/2.0` has been the **default** report contract since v7.0.0 (ADR-027), with the
older contracts (`reports/0.1`, `reports/0.2`, `reports/0.3`, `reports/1.0`) kept
**selectable** via `--report-json-contract` for one deprecation cycle. ADR-027 and ADR-041
explicitly promised the legacy contracts would be removed in a later major. That cycle has
now elapsed (v7.0.0 → v8.1.0). Keeping four parallel emit paths + four JSON schemas + the
two `GATE_EXECUTION_MODEL_*` variants is dead weight: it widens the maintenance and test
surface and lets adopters pin a contract that no longer receives feature work.

Removing a selectable contract is breaking for any adopter still pinning
`--report-json-contract 1.0` (or 0.1/0.2/0.3). Keeping `1.0` while dropping the older
`0.x` would be incoherent (1.0 is newer than 0.3), so the removal is scoped to **all
pre-2.0 contracts at once**.

## Decision

In **v9.0.0**, make `reports/2.0` the **only** report contract:

1. **Remove** the `reports/0.1`, `reports/0.2`, `reports/0.3`, and `reports/1.0` emit
   paths from `application/reporting.py` and the matching schema files under
   `data/schema/` (and any `reports/` schema mirror).
2. **`--report-json-contract` accepts only `2.0`.** Passing `1.0`/`0.3`/`0.2`/`0.1`
   becomes a clean usage error (exit 2) that names the removed contract and points at the
   migration guide — never a silent fallback.
3. **Collapse the gate-execution model** to the single v2 model that backs reports/2.0;
   drop `GATE_EXECUTION_MODEL_V1` and the legacy status maps that only the pre-2.0
   contracts used.
4. **Migration guide** (`docs/v9.0.0-migration-guide.md`) documents the removed field
   shapes and the 2.0 equivalents; the `cli-api-ui-contract-validator` gate signs off the
   removed-contract error and the surviving 2.0 contract.

## Alternatives considered

1. **Remove only `reports/1.0`, keep `0.x`.** Rejected — incoherent (1.0 is the newest
   legacy contract; keeping older ones while dropping it makes no sense) and leaves most
   of the legacy surface in place.
2. **Keep all contracts indefinitely.** Rejected — ADR-027 already committed to removal;
   four parallel emit paths + schemas are ongoing maintenance and test cost with no
   feature value.
3. **Deprecate-with-warning for another cycle.** Rejected — the deprecation cycle already
   ran (v7.0.0 → v8.1.0); a hard removal in a major is the honest semver outcome.

## Consequences

- One report contract (`reports/2.0`) — smaller maintenance + test surface, no
  ambiguous "which contract did this report use?" for consumers.
- Breaking for adopters pinning a pre-2.0 contract; mitigated by a clean error that names
  the contract + the migration guide. (Default users are unaffected — 2.0 has been the
  default since v7.0.0.)
- ~48 test files reference the legacy contracts today; they are migrated to assert the
  2.0 shape or the removed-contract error as part of this change.
- Ships in **v9.0.0** alongside ADR-029 (CRA conformance-evidence); the normalized-finding
  model (ADR-030) follows in v10.0.0 (sequenced, one major's worth of breaking surface at
  a time).
