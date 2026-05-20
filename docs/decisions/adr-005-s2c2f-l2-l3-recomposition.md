# ADR-005 — S2C2F Levels 2 and 3: ship as recomposition of existing controls (no new evaluators)

- **Status**: proposed (v6.0.0)
- **Date**: 2026-05-18
- **Context window**: v6.0.0 planning, Onda 2 (PR-6)
- **Related**: existing `s2c2f-l1-1` (v5.x), Microsoft S2C2F v2 (2023)

## Context

[Microsoft Supply Chain Software Component Framework (S2C2F)](https://github.com/ossf/s2c2f) defines four maturity levels (1–4) for ingesting upstream OSS safely. v5.x ships `s2c2f-l1-1` aligned with Level 1 (minimum acceptance and inventory). Levels 2 and 3 add:

- **Level 2**: scan for known vulnerabilities, scan for licenses, enforce ingestion through a private registry, plus update enforcement (Dependabot/Renovate-style).
- **Level 3**: validate signatures and provenance, mirror to internal registry with audit trail, enforce SBOM presence per ingested artifact, plus build-time SBOM diffing.

Every requirement S2C2F L2 and L3 introduces is **already covered** by a control the kit ships today — but the controls are scattered across the catalog: `SAST-OSV-068` (vulnerability scan), `GOV-LIC-004` (license), `CI-PIN-008` (pinning), `DEP-UPDATE-001` (auto-update), `PROV-VERIFY-061` (provenance verification), `BUILD-SBOM-QUAL-003` (SBOM presence), `AUDIT-STREAM-060` (audit trail), `OSS-SCORECARD-001` (upstream maturity signal), and a few others.

Two ways to add L2 and L3 coverage exist:

A. **Recomposition**: bundle the existing controls under new profile YAML files `s2c2f-l2-1` and `s2c2f-l3-1`, plus a profile README that maps each S2C2F requirement to the bundled control. Zero new evaluators, zero new evidence schemas.

B. **New `S2C2F-*` control family**: write fresh evaluators named after S2C2F practice IDs (e.g. `S2C2F-ING-002`, `S2C2F-AUD-003`), even though the underlying signal is identical to an existing control. Each new control needs its own evaluator, tests, fixtures, and catalog entry.

Option B inflates the catalog by ~12 controls that re-detect the same signals existing controls already detect. It also creates a maintenance liability: if a detection rule needs updating, two evaluators have to change in lockstep.

## Decision

**Choose Option A — recomposition.** Ship `s2c2f-l2-1` and `s2c2f-l3-1` as profile YAML files that bundle the existing relevant controls. Zero new control IDs are added for S2C2F coverage.

Each profile's README documents the S2C2F-requirement → kit-control mapping explicitly so adopters reading the profile know which framework practice each bundled control discharges.

Both profiles are `framework-aligned advisory` (`--fail-on degraded`) at GA, matching the posture of other framework-aligned profiles (`osps-baseline-1`, `slsa-build-l2-1`, `cra-eu-ready-1`).

## Alternatives considered

1. **Option B (new `S2C2F-*` family)** — rejected for the reasons above (duplication, maintenance cost).
2. **Skip L2/L3 in v6.0.0.** Rejected: the gap between L1 and L2 in S2C2F is the most common adopter ask, and the bundling work is small.
3. **Ship L2 only; defer L3.** Rejected: L3 adds no new evaluators, only references SBOM/provenance controls already shipped. Marginal cost is the profile YAML and README.

## Consequences

**Positive**

- Adopters get explicit S2C2F L2 and L3 profiles without inflating the control catalog.
- Per-control trust grading remains coherent — a `pass` on `s2c2f-l3-1` is the conjunction of the underlying control grades, not a re-detection.
- Maintenance footprint stays small.

**Negative / cost**

- Some adopters expect a one-to-one S2C2F-named control surface; they may be surprised that the bundled controls do not carry `S2C2F-*` IDs. The profile README is the mitigation.

**Mitigations**

- Profile README documents the mapping table; `profiles --format detailed` surfaces it.
- `framework-alignment.md` gains rows for S2C2F L2 / L3 pointing to the bundled controls.

## References

- v6.0.0 execution plan §4.2 PR-6
- v6.0.0 proposal §3 O-02
- [S2C2F repo](https://github.com/ossf/s2c2f)
- Existing `s2c2f-l1-1` profile
