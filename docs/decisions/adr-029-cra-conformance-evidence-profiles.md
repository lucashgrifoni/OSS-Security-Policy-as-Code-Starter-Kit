# ADR-029 - Tighten the CRA profiles from "ready" to "conformance-evidence" (v9.0.0)

- **Status**: accepted (targets v9.0.0, BREAKING) — ratified 2026-06-19; implementation in progress. Sequenced v9 → v10: this CRA tightening/rename + the `reports/1.0` removal (ADR-043) ship in **v9.0.0**; the normalized-finding model (ADR-030) follows in **v10.0.0**. The renamed-profile aliases are deprecated through the v9.x line and removed in v10.0.0.
- **Date**: 2026-05-25
- **Context window**: v9.x roadmap horizon — "EU CRA & regulatory readiness depth"
- **Related**: ADR-020 (CRA Article 13/14 product class), ADR-010 (CRA + EU AI Act Art.11), ADR-019 (EU AI Act Annex IV evidence), ADR-028 (ATTESTED state), `docs/cra-readiness.md`, the maintainer's local roadmap (not published)

## Context

The kit ships `cra-eu-ready-*` profiles (e.g. `cra-eu-ready-2-1`) that surface EU CRA
Article 13/14 *readiness signals*. The EU CRA now has hard, dated obligations:

- **2026-09-11** — reporting obligations: 24h early warning, 72h notification, 14-day
  final report for actively exploited vulnerabilities.
- **2027-12-11** — full obligations: secure-by-design, conformity assessment, technical
  documentation, CE marking, **SBOM generation**, a vulnerability-handling process, and
  security updates across the support period; documentation retained for **10 years**.

The current profiles are framed as "ready" — a soft posture indicator. As the deadlines
approach, adopters need profiles that assert *defensible conformance evidence* (process
existence, support-period declaration, SBOM retention policy, coordinated-disclosure
path), not just readiness hints. Tightening what these profiles require to **pass** is
breaking: a repository that passed `cra-eu-ready-2-1` today may fail the stricter
profile. Renaming a profile is also breaking for anyone referencing it by name in CI.

The hard guard: the kit must continue to **never claim certification**. "CRA
conformance-evidence" means "here is evidence mapped to CRA obligations", not "this
product is CRA certified".

## Decision

In **v9.0.0**, evolve the CRA profiles from "ready" to a stricter
**conformance-evidence** model:

1. **Tighten pass criteria** of the CRA profiles to require evidence for the
   Article-13/14 obligations that are expressible from a clone + evidence files:
   vulnerability-handling process (coordinated disclosure, `security.txt`/contact,
   24h/72h/14d process documentation), support-period declaration, SBOM-retention
   policy. Signals that cannot be proven from a clone stay `signal`/`evidence-backed`,
   never inflated to a pass — and attestation-backed items can resolve to `ATTESTED`
   (ADR-028).
2. **Rename with aliases.** Where a name change communicates the stronger semantics,
   rename the profile and keep the old name as a deprecated **alias for one minor
   cycle**, so existing CI references keep working with a warning.
3. **Sequence reporting before full obligations.** Ship the reporting-process signals
   (2026-09-11 deadline) ahead of the broader obligation evidence (2027-12-11).
4. **No certification claim.** Docs and report copy say "conformance evidence" /
   "mapped to CRA Article …", never "CRA certified". (Reinforces the README non-goal.)

## Alternatives considered

1. **Keep "ready" profiles unchanged.** Rejected — leaves adopters with soft signals as
   real, dated, fineable obligations arrive; the kit's regulatory value erodes.
2. **Add new strict profiles and keep the old ones forever.** Rejected — profile sprawl
   and an indefinite weak/strong split; aliases with a deprecation window are cleaner.
3. **Tighten in a v8.x minor.** Rejected — changing pass criteria flips gate outcomes
   for existing adopters; semver requires a major.
4. **Assert "compliance".** Rejected — violates the no-certification non-goal; the kit
   provides evidence, not a legal verdict.

## Consequences

- CRA profiles assert defensible, obligation-mapped evidence aligned to the 2026/2027
  deadlines, with honest assurance labels.
- Repositories that passed the old "ready" profiles may need additional evidence to
  pass the stricter ones; documented as breaking, with a per-control diff and the alias
  window for renamed profiles.
- The kit stays on the right side of the certification line — evidence, not a claim.
- Trade-off: depends on ADR-028 (`ATTESTED`) for the attestation-backed CRA items;
  some obligations (e.g. actual 10-year retention, validated update channel) remain
  out of scope for a clone-only tool and stay explicitly non-goals.

## References

- EU CRA timeline — <https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act>, <https://www.keysight.com/blogs/en/tech/nwvs/2025/09/11/one-year-countdown-to-eu-cra-compliance-september-11-2026-changes-everything>
- ADR-020, ADR-010, ADR-019, ADR-028; `docs/cra-readiness.md`
- the maintainer's local roadmap (not published) (v9.x horizon); roadmap plan §6, §11.4
