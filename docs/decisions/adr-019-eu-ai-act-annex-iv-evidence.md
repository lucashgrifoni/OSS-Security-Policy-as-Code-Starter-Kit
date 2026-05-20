# ADR-019 - EU AI Act Annex IV evidence schema expansion

- **Status**: proposed (v6.0.0 Cycle 2)
- **Date**: 2026-05-20
- **Context window**: v6.0.0 Cycle 2, PR-21
- **Related**: ADR-010 (Article 11 profile), `docs/eu-ai-act-readiness.md`

## Context

Annex IV of the EU AI Act enumerates nine documentation sections. Cycle 1
(ADR-010) covered three of them with clone-visible README/SECURITY heuristics
(§1, §3, §5). Teams preparing for 2026-08-02 need broader coverage, but the
remaining sections (development/data, performance, cybersecurity, lifecycle,
standards, post-market monitoring) are not reliably detectable from prose.

## Decision

Add an `evidence-ai-system-technical-doc.schema.json` evidence file plus six
evidence-backed controls:

- `LLM-AI-ACT-DEV-002` (§2), `LLM-AI-ACT-PERF-004` (§4),
  `LLM-AI-ACT-CYBER-006` (§6), `LLM-AI-ACT-CHANGE-007` (§7),
  `LLM-AI-ACT-STD-008` (§7 standards), `LLM-AI-ACT-PMM-009` (§8).

Each control reads `.oss-policy-kit/evidence/ai-system-technical-doc.json`:
missing file → manual review; section field populated → PASS; field empty →
FAIL. The schema is `additionalProperties: true` (v1) so it can harden later
without breaking early adopters. These extend `cra-eu-ai-act-art11-1`, which
remains advisory (`--fail-on degraded`).

## Alternatives considered

1. **More README heuristics.** Rejected — the remaining Annex IV sections are
   structured data, not prose; a versioned evidence file is the honest input.
2. **Strict required-fields schema now.** Rejected — harmonised standards
   (prEN 18286, AESIA guidance) are not final; `additionalProperties: true`
   avoids premature rigidity.

## Consequences

- Annex IV coverage rises from 3 to 9 sections for teams that maintain the
  evidence file.
- The kit still does not certify conformity (Article 43); caveat unchanged.

## References

- EU AI Act Annex IV (official text)
- v6.0.0 Cycle 2 plan, PR-21; ADR-010
