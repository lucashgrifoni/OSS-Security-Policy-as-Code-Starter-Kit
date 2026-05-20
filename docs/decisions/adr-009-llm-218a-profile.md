# ADR-009 - NIST SP 800-218A LLM secure-development profile

- **Status**: accepted (v6.0.0)
- **Date**: 2026-05-18
- **Context window**: v6.0.0 Cycle 1, PR-10
- **Related**: ADR-010 (EU AI Act Article 11), `docs/eu-ai-act-readiness.md`

## Context

NIST SP 800-218A (the Generative AI and Dual-Use Foundation Model profile of the
Secure Software Development Framework) extends SSDF practices to AI systems.
Teams shipping software that embeds LLM or foundation-model components asked for a
clone-visible baseline that maps the 218A practices the kit can observe.

The kit cannot inspect model weights, training pipelines, or inference
infrastructure from a repository clone. It can detect documentation and release
discipline signals that 218A expects.

## Decision

Ship the `appsec-llm-ssdf-218a-1` advisory profile and the supporting controls:

- `LLM-218A-PO-001` — an "AI Security Considerations" section is present in
  SECURITY.md or README (218A PO practice family), signal-grade.
- `LLM-218A-PS-001` — an LLM release-integrity evidence file is populated
  (218A PS practice family), evidence-backed.
- `AIBOM-PRESENT-001` — an AI Bill of Materials (CycloneDX ML-BOM or SPDX 3.0 AI
  components) is present, signal-grade.

The profile is advisory; recommended `--fail-on degraded` only. It does not
certify 218A conformance.

## Alternatives considered

1. **Fold 218A signals into the existing AppSec profile.** Rejected — the AI
   audience and caveats differ enough to warrant a dedicated, clearly-labelled
   advisory profile.
2. **Require evidence for every control.** Rejected — most teams have no 218A
   evidence pipeline yet; signal-grade documentation checks lower the adoption
   barrier while `LLM-218A-PS-001` remains evidence-backed for teams that do.

## Consequences

- Teams get an honest, clone-visible 218A starting point without overclaiming.
- The AIBOM control is reused by the EU AI Act Annex IV profile (ADR-010).
- Heuristic documentation checks can false-positive; mitigated by advisory
  posture and explicit caveats.

## References

- NIST SP 800-218A (final)
- v6.0.0 Cycle 1 plan, PR-10
- ADR-010, `docs/eu-ai-act-readiness.md`
