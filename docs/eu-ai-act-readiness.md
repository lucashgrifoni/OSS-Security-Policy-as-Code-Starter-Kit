# EU AI Act readiness — what the kit will help with in v6.0.0, and what it does not

> **In development (v6.0.0)**. This page describes the planned advisory profile `cra-eu-ai-act-art11-1` and the controls in the `LLM-AI-ACT-*` family. **None of them ship in v5.9.x.** They land with PR-11 on the `feat/v6.0.0-evolution` branch. Treat this page as a design statement and adopter guide for what will be available when v6.0.0 GA ships (target: before 2026-08-02).

This page is the AI Act companion to [`cra-readiness.md`](cra-readiness.md). It applies the same posture: the kit produces **technical alignment evidence**, not a conformity assessment.

## Hard caveat — read first

The kit does **not** substitute for an EU AI Act conformity assessment. Conformity assessment for high-risk AI systems under Article 43 requires a notified body (or an internal control procedure under Annex VI, where permitted). No control in this kit produces a conformity verdict, signs CE-marking documentation, or discharges the obligations of a provider, deployer, distributor, or importer as defined in the Act.

What the kit will do in v6.0.0 is detect **clone-visible signals** that an AI system's technical documentation set (Annex IV) is being maintained, and surface gaps before the formal assessment cycle starts. That is a starting point for adopters preparing for a notified-body review, not a substitute for the review.

## The window: 2026-08-02

EU AI Act **Article 11** and **Annex IV** become enforceable on **2026-08-02**. The two together specify the technical documentation a high-risk AI system must maintain:

- Intended purpose, intended users, foreseeable misuse (Annex IV §1).
- Detailed description of the AI system architecture, training data, validation, test data (Annex IV §2).
- Output filtering / content moderation strategy (Annex IV §3).
- Performance metrics and accuracy (Annex IV §4).
- Risk management documentation (Annex IV §5).
- Post-market monitoring plan (Annex IV §8).

The kit's planned coverage targets §1, §3, and §5 — the dimensions most observable from a clone — and bundles in `AIBOM-PRESENT-001` for §2 (training-data composition surfaced via AIBOM presence, not contents).

## Planned coverage in v6.0.0

### Profile `cra-eu-ai-act-art11-1` (advisory, `--fail-on degraded`)

| Annex IV requirement | Kit control | Coverage | Source |
|---|---|---|---|
| §1 Intended purpose / users / limitations | `LLM-AI-ACT-001` | signal | "Intended Purpose / Users / Limitations" section in `README.md` or `SECURITY.md`. |
| §3 Output filtering / content moderation | `LLM-AI-ACT-002` | signal | Pattern match for `output_filter` / `content_moderation` references in test files. |
| §5 Risk management documentation | `LLM-AI-ACT-003` | signal | Presence of `risk-management.md`, `RISKS.md`, or a dedicated section in `SECURITY.md`. |
| §1 (Annex IV "AI Security Considerations") | `LLM-218A-PO-001` (bundled from `appsec-llm-ssdf-218a-1`) | signal | NIST 218A heritage. |
| §2 (training data inventory surface) | `AIBOM-PRESENT-001` | signal | CycloneDX ML-BOM or SPDX 3.0 AI components at `.oss-policy-kit/evidence/aibom/*.json`. |
| §8 (post-market monitoring SLA documentation) | `GOV-DISC-065` | evidence-backed | Reused from v5.9.0 disclosure SLA work. |
| Release change tracking | `REL-CHANGE-012` | signal | Reused from existing release-hardening work. |
| Dependency CVE surface | `SAST-OSV-068` | signal/evidence-backed | OSV-Scanner SARIF ingest. |

### Annex IV expansion (Cycle 2, PR-21 — evidence-backed)

Cycle 2 adds six **evidence-backed** controls that read a structured evidence
file, `.oss-policy-kit/evidence/ai-system-technical-doc.json` (schema:
`evidence-ai-system-technical-doc.schema.json`). Each control checks one Annex IV
section: missing file → manual review; section populated → PASS; empty → FAIL.
See ADR-019.

| Annex IV section | Evidence field | Control |
|---|---|---|
| §2 development / design / training data | `development_design` | `LLM-AI-ACT-DEV-002` |
| §4 performance metrics / accuracy | `performance_metrics` | `LLM-AI-ACT-PERF-004` |
| §6 cybersecurity measures | `cybersecurity_measures` | `LLM-AI-ACT-CYBER-006` |
| §7 lifecycle changes | `lifecycle_changes` | `LLM-AI-ACT-CHANGE-007` |
| §7 applied harmonised standards | `applied_standards` | `LLM-AI-ACT-STD-008` |
| §8 post-market monitoring plan | `post_market_monitoring_plan` | `LLM-AI-ACT-PMM-009` |

These sections require structured artifacts the kit cannot infer from prose, so
they are gated on the evidence file rather than README heuristics. The evidence
schema is `additionalProperties: true` (v1) and will harden in a later release as
harmonised standards (prEN 18286, AESIA guidance) stabilise. The conformity-
assessment boundary is unchanged: a populated field is a documentation-readiness
signal, not a conformity verdict.

## What the kit will not do (and what to do instead)

| You need | Use this instead |
|---|---|
| Conformity assessment for a high-risk AI system | Notified body (Article 43); internal procedure (Annex VI) where permitted |
| CE marking | The conformity-assessment process above |
| Quality-management-system audit (Article 17) | Auditor / certification body |
| Risk-management-system audit (Article 9) | Auditor / certification body, or internal SOC 2 / ISO 42001 work |
| Training-data lineage and bias evaluation | A dedicated AI assurance tool; this kit only checks AIBOM presence, not contents |
| Post-market monitoring runtime evidence | Your observability platform; this kit only checks that an SLA is documented |
| GPAI model card publication | The model provider's own publication process |

## How adopters should use this profile

The advisory posture is intentional. The intended workflow:

1. Run `oss-policy-kit evaluate --target . --profile cra-eu-ai-act-art11-1 --fail-on degraded`.
2. For every `manual-review-required` or `signal fail` result, follow the remediation pointer in the profile README.
3. Fill in the AIBOM at `.oss-policy-kit/evidence/aibom/<artifact>.json` (CycloneDX ML-BOM or SPDX 3.0 AI components).
4. Document intended purpose, output filtering, and risk management in the conventional locations the kit looks for.
5. Run the formal conformity assessment with a notified body — using the kit's output as input evidence, not as the assessment itself.

## What changes when the AI Act enters full force

Article 11 + Annex IV is the documentation obligation. Other AI Act articles enter force later (Articles 26–29 for deployers; Articles 49–51 for high-risk AI registration; etc.). The kit may add advisory profiles for those obligations in v6.1.0+, scoped to clone-visible signals only. The conformity-assessment boundary stays.

## References

- [EU AI Act consolidated text](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) (Regulation (EU) 2024/1689)
- [Annex IV — technical documentation requirements](https://artificialintelligenceact.eu/annex/4/)
- [Article 11 — technical documentation obligation](https://artificialintelligenceact.eu/article/11/)
- ADR-010 (planned) — `cra-eu-ai-act-art11-1` profile design and overclaim mitigation
- [`positioning.md`](positioning.md) → *Roadmap (v6.0.0 — in development)*
- [`framework-alignment.md`](framework-alignment.md) → *EU AI Act — Article 11 + Annex IV (planned v6.0.0)*
