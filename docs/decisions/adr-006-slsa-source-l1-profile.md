# ADR-006 — SLSA Source Track Level 1: first profile in a new `SLSA-SRC-*` family

- **Status**: proposed (v6.0.0)
- **Date**: 2026-05-18
- **Context window**: v6.0.0 planning, Onda 3 (PR-13)
- **Related**: existing `slsa-build-l2-1` (v5.x), SLSA v1.0 Source Track (2024)

## Context

[SLSA v1.0](https://slsa.dev/spec/v1.0/) defines two parallel tracks: **Build** and **Source**. The Build Track was first to ship and is the one most adopters reference today; the kit aligns with it via `slsa-build-l2-1`. The Source Track was formalized later (SLSA 1.0 spec, 2024) and addresses upstream-of-build integrity: who can push to the source repository, what review is required, what audit trail is preserved, and how the source state at build time can be reconstructed.

SLSA Source Level 1 expects:

1. Version-controlled source.
2. Verified history (commits authenticated to the contributor).
3. Branch / tag protection enforced.
4. Two-party review on protected branches (or documented equivalent).
5. Audit log of source-changing events available.

The kit already detects most of these via existing controls (`PLAT-BRPROT-015` for protection, `GH-PLAT-024` for ruleset, `GH-PLAT-025` for actions allowlist, `AUDIT-STREAM-060` for audit log), but it does not present them under a SLSA Source vocabulary, and one signal — "verified history" via commit-signature enforcement — is not currently a first-class control.

The decision is between:

A. **Bundle existing controls under a new profile** `slsa-source-l1-1` (same approach as ADR-005 for S2C2F).

B. **Introduce a `SLSA-SRC-*` family** that exposes SLSA-vocabulary controls and lets the profile compose them. New controls would be `SLSA-SRC-001` (version-controlled source — trivially deterministic), `SLSA-SRC-002` (verified-history — commit signature enforcement; new evaluator), `SLSA-SRC-003` (protection), `SLSA-SRC-004` (two-party review), `SLSA-SRC-005` (audit log), `SLSA-SRC-006` (source-state reconstructability).

Unlike S2C2F (ADR-005), the SLSA Source case has at least one **new signal** that the kit does not detect today (commit-signature enforcement at the platform level), and the profile sits at the start of a planned multi-level ladder (`slsa-source-l2-1`, `slsa-source-l3-1` in v6.1.0+) where named controls give the ladder a clean evolution path.

## Decision

**Choose Option B — introduce a `SLSA-SRC-*` family of 5–6 controls** and ship `slsa-source-l1-1` as the first profile that bundles them. Some controls delegate internally to existing evaluators (`PLAT-BRPROT-015`, `AUDIT-STREAM-060`, `GOV-COWN-001`); `SLSA-SRC-002` (verified-history) is a genuinely new evaluator that detects platform-side commit-signature enforcement (clone-visible signal: repository ruleset requires signed commits, or workflow blocks unsigned commits, or `git log --show-signature` on the most recent N commits shows ≥X% signed).

The profile is `framework-aligned advisory` (`--fail-on degraded`) at GA.

The family name `SLSA-SRC-*` is intentional and parallels the existing `SLSA-*` allusions in the Build Track profile descriptions.

## Alternatives considered

1. **Option A (recomposition only)** — rejected: the signature-enforcement signal is genuinely new, and the ladder will benefit from named controls as L2/L3 profiles arrive.
2. **One mega-control `SLSA-SRC-001` covering all 5 expectations.** Rejected for the same reason ADR-004 rejected a single combined webhook control — trust grading collapses.
3. **Defer to v6.1.0.** Rejected: SLSA Source is the most common gap callout in adopter feedback for `slsa-build-l2-1`; closing it with the major release matches the framework's own ladder structure.

## Consequences

**Positive**

- Source Track gains first-class representation in the catalog with a clean expansion path to L2 / L3.
- One genuinely new signal (commit-signature enforcement) becomes catalog-visible.
- Adopters can now reference `slsa-source-l1-1 + slsa-build-l2-1` as a paired SLSA posture.

**Negative / cost**

- 5–6 new control IDs (some delegating internally) plus one new evaluator. Test cost: hardened + vulnerable fixtures.
- The "verified history" signal is partially platform-side; commit-signature enforcement is most reliably detected via repository ruleset (GitHub-specific), with weaker fallbacks on other platforms.

**Mitigations**

- Controls that delegate internally are documented as such in `controls-catalog.md`.
- `SLSA-SRC-002` ships as `signal` grade initially; promote to `evidence-backed` if a ruleset-aware evidence file lands later.

## References

- v6.0.0 execution plan §5.4 PR-13
- v6.0.0 proposal §4 O-06
- [SLSA v1.0 Source Track](https://slsa.dev/spec/v1.0/requirements#source-track)
- Existing `slsa-build-l2-1` profile
