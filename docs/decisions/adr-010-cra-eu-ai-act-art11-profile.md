# ADR-010 - EU AI Act Article 11 + Annex IV advisory profile

- **Status**: accepted (v6.0.0)
- **Date**: 2026-05-18
- **Context window**: v6.0.0 Cycle 1, PR-11 (expanded in Cycle 2, PR-21 — see ADR-019)
- **Related**: ADR-009 (NIST 218A), ADR-019 (Annex IV evidence schema), `docs/eu-ai-act-readiness.md`

## Context

EU AI Act Article 11 requires technical documentation (detailed in Annex IV) for
high-risk AI systems; the obligation becomes enforceable on **2026-08-02**. Teams
preparing for that window asked for a clone-visible readiness signal set.

Conformity assessment (Article 43) requires a notified body or internal control
under Annex VI. That is firmly outside what a repository-clone policy tool can do.
The kit must surface preparatory documentation signals **without** implying a
CE-marking outcome.

## Decision

Ship the `cra-eu-ai-act-art11-1` advisory profile with the `LLM-AI-ACT-*` family.
Cycle 1 delivered three signal-grade controls mapped to Annex IV:

- `LLM-AI-ACT-001` — intended purpose / users / limitations documented (§1).
- `LLM-AI-ACT-002` — output-filtering / content-moderation pattern detected (§3).
- `LLM-AI-ACT-003` — risk-management documentation present (§5).

The profile bundles `AIBOM-PRESENT-001`, `LLM-218A-*`, and `GOV-DISC-065`. It is
explicitly advisory; recommended `--fail-on degraded`. Every surface repeats the
hard caveat that the kit does NOT substitute for a conformity assessment.

## Alternatives considered

1. **Hard-gate profile.** Rejected — a regulatory readiness signal must never
   masquerade as a compliance verdict.
2. **Wait for harmonised standards (prEN 18286) to stabilise.** Rejected — the
   2026-08-02 window means teams need preparatory signals now; the evidence
   schema is versioned so it can harden later (ADR-019).

## Consequences

- Teams get a documentation-readiness checklist tied to Annex IV sections.
- Cycle 2 expanded coverage to §2/§4/§6/§7/§8 via an evidence schema (ADR-019).
- Heuristic README/SECURITY scanning can miss documentation in other locations;
  the evidence-backed expansion (ADR-019) addresses the gap for teams that adopt it.

## References

- EU AI Act Article 11 + Annex IV (official text)
- v6.0.0 Cycle 1 plan, PR-11; Cycle 2 plan, PR-21
- ADR-009, ADR-019, `docs/eu-ai-act-readiness.md`
