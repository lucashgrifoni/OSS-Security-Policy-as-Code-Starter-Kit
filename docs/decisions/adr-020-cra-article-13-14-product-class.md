# ADR-020 - EU CRA Article 13/14 + product classification signals

- **Status**: proposed (v6.0.0 Cycle 2)
- **Date**: 2026-05-20
- **Context window**: v6.0.0 Cycle 2, PR-22
- **Related**: ADR-010, `cra-eu-ready-1`, `docs/cra-readiness.md`

## Context

The European Commission published its first CRA draft guidance (2026-03-03), and
Implementing Reg (EU) 2025/2392 defines important/critical product classes. CRA
Article 14 incident-reporting obligations apply from **2026-09-11**. Existing
`cra-eu-ready-1` predates these and does not cover Articles 13 (security by
design / default) or 14 (CSAF reporting, coordinated disclosure) or product
classification.

## Decision

Ship five signal-grade controls and a successor profile `cra-eu-ready-2-1`:

- `CRA-ART13-SBD-001`, `CRA-ART13-DEFAULTS-002` — security-by-design / secure
  defaults documented.
- `CRA-ART14-CSAF-001` — CSAF advisory feed present (`.well-known/csaf`).
- `CRA-ART14-COORD-002` — coordinated disclosure policy (reuses
  `disclosure-policy.json` `coordinated_disclosure: true` when present).
- `CRA-PRODUCT-CLASS-001` — product class declared per Impl. Reg 2025/2392.

`cra-eu-ready-2-1` bundles these with `GOV-DISC-065`, `REL-CHANGE-012`, and
`SAST-OSV-068`. Advisory only; `cra-eu-ready-1` retained for compatibility.

## Alternatives considered

1. **Extend `cra-eu-ready-1` in place.** Rejected — a successor profile keeps
   the older bundle stable for current adopters.
2. **Evidence-backed CSAF validation.** Deferred — presence detection is enough
   for a readiness signal; full CSAF schema validation is future work.

## Consequences

- Manufacturers get a clone-visible CRA Article 11/13/14 readiness snapshot.
- The kit does not certify CRA conformity; signals are preparatory only.

## References

- Linklaters CRA draft-guidance summary; Impl. Reg (EU) 2025/2392
- v6.0.0 Cycle 2 plan, PR-22; `docs/cra-readiness.md`
