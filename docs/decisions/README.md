# Architecture decision records

45 records. Each one states a decision, what was rejected, and what it costs.

**Read the Status line with a caveat.** It is written when the ADR is drafted and is not
always revisited when the work lands, so a record can say `proposed` about something that
shipped years of releases ago -- 16 of these do. Where the two disagree, the
[CHANGELOG](../../CHANGELOG.md) and the shipped product are authoritative and the Status line
is not. Two were corrected on 2026-09-15 by asking the released CLI whether the command the
ADR proposed exists; the rest are left as written rather than flipped on an assumption.

| ADR | Decision | Status |
|---|---|---|
| [001](adr-001-sca-scanner-choice.md) | ADR-001 — SCA scanner integration: OSV-Scanner v2 primary, Trivy / Gitleaks... | `accepted` |
| [002](adr-002-emit-vex-scope.md) | ADR-002 — `emit-vex` capability: scope and design | `accepted` |
| [003](adr-003-gitlab-ci-support.md) | ADR-003 — GitLab CI support: parser, controls, profile | `accepted` |
| [004](adr-004-webhook-security-baseline-expansion.md) | ADR-004 — Webhook security baseline: expand from 1 advisory profile to a 6-... | `proposed` |
| [005](adr-005-s2c2f-l2-l3-recomposition.md) | ADR-005 — S2C2F Levels 2 and 3: ship as recomposition of existing controls ... | `proposed` |
| [006](adr-006-slsa-source-l1-profile.md) | ADR-006 — SLSA Source Track Level 1: first profile in a new `SLSA-SRC-*` fa... | `proposed` |
| [007](adr-007-gh-prov-023-evidence-backed-promotion.md) | ADR-007 — Promote `GH-PROV-023` from `signal` to `evidence-backed`; CHANGEL... | `proposed` |
| [008](adr-008-recommend-profile-v2-schema-url.md) | ADR-008 — `recommend-profile/v2.schema_version`: absolute URL (breaking) | `proposed` |
| [009](adr-009-llm-218a-profile.md) | ADR-009 - NIST SP 800-218A LLM secure-development profile | `accepted` |
| [010](adr-010-cra-eu-ai-act-art11-profile.md) | ADR-010 - EU AI Act Article 11 + Annex IV advisory profile | `accepted` |
| [011](adr-011-emit-insights-subcommand.md) | ADR-011 — `emit-insights` subcommand: emit OpenSSF Security Insights 1.0 YAML | `proposed` |
| [012](adr-012-export-evidence-chainloop-experimental.md) | ADR-012 — `export-evidence --format chainloop`: experimental Chainloop atte... | `proposed` |
| [013](adr-013-reports-2-0-contract.md) | ADR-013 - reports/2.0 contract with a five-state vocabulary | `accepted` |
| [014](adr-014-oss-publish-readiness.md) | ADR-014 — `oss-publish-readiness-1` profile + `PUBLISH-OIDC-*` family for T... | `proposed` |
| [015](adr-015-worm-aware-publish-defense.md) | ADR-015 - Worm-aware publish defense controls | `proposed` |
| [016](adr-016-ai-agent-baseline-source-side.md) | ADR-016 - AI agent source-side baseline | `accepted` |
| [017](adr-017-source-built-container-release.md) | ADR-017 - Build container images from release source instead of PyPI | `unknown` |
| [018](adr-018-osps-baseline-2026-scorecard-v6.md) | ADR-018 - OSPS Baseline v2026.02.19 + Scorecard v6 conformance | `proposed` |
| [019](adr-019-eu-ai-act-annex-iv-evidence.md) | ADR-019 - EU AI Act Annex IV evidence schema expansion | `proposed` |
| [020](adr-020-cra-article-13-14-product-class.md) | ADR-020 - EU CRA Article 13/14 + product classification signals | `proposed` |
| [021](adr-021-epss-kev-prioritization.md) | ADR-021 - EPSS + CISA KEV prioritization in SCA | `accepted` |
| [022](adr-022-slsa-source-l2.md) | ADR-022 - SLSA v1.2 Source Track Level 2 | `proposed` |
| [023](adr-023-mcp-server-security.md) | ADR-023 - MCP server security profile | `proposed` |
| [024](adr-024-owasp-agentic-asi.md) | ADR-024 - OWASP Top 10 for Agentic Applications (ASI01-10) | `proposed` |
| [025](adr-025-github-2026-container-scanner-signals.md) | ADR-025 - GitHub Actions 2026, distroless, scanner integrity, Rekor v2, Cyc... | `proposed` |
| [026](adr-026-evaluators-package-refactor.md) | ADR-026 - Split `evaluators.py` monolith into an `evaluators/` package | `accepted` |
| [027](adr-027-reports-2-0-default-flip.md) | ADR-027 - Flip the default report contract to reports/2.0 (v7.0.0) | `accepted` |
| [028](adr-028-control-applicability-attested-engine.md) | ADR-028 - Formalize the applicability engine and activate the ATTESTED stat... | `accepted` |
| [029](adr-029-cra-conformance-evidence-profiles.md) | ADR-029 - Tighten the CRA profiles from "ready" to "conformance-evidence" (... | `accepted` |
| [030](adr-030-normalized-finding-correlation-model.md) | ADR-030 - Normalized finding model with cross-scanner correlation (v10.0.0) | `accepted` |
| [031](adr-031-openvex-export.md) | ADR-031 - Add OpenVEX export alongside CycloneDX VEX (v6.6.0) | `accepted` |
| [032](adr-032-ingest-insights.md) | ADR-032 - Ingest a project's OpenSSF Security Insights file (`ingest-insigh... | `accepted` |
| [033](adr-033-ingest-insights-control-evidence-wiring.md) | ADR-033 - Wire ingested Security Insights into controls as self-attested ev... | `accepted` |
| [034](adr-034-spdx-evidence-export.md) | ADR-034 - SPDX evidence export (`export-evidence --format spdx`, v7.0.0) | `accepted` |
| [035](adr-035-cel-rego-policy-export.md) | ADR-035 - CEL / Rego policy export (`export-policy`, v7.0.0) | `accepted` |
| [036](adr-036-oscal-intoto-export-ga.md) | ADR-036 - Promote OSCAL and in-toto-bundle export to GA (`export-evidence`,... | `accepted` |
| [037](adr-037-osps-baseline-coverage-map.md) | ADR-037 - OSPS Baseline v2026.02.19 coverage map (structured + generated) | `accepted` |
| [038](adr-038-immutable-release-actions-policy-signals.md) | ADR-038 - GitHub immutable-release + org-level Actions-policy evidence sign... | `accepted` |
| [039](adr-039-agentic-asi-complete-coverage.md) | ADR-039 - Complete OWASP Agentic ASI coverage (ASI05/08/10 low-confidence s... | `accepted` |
| [040](adr-040-cisa-secure-by-design-signals.md) | ADR-040 - CISA Secure by Design Pledge readiness signals (CISA-SBD-*) | `accepted` |
| [041](adr-041-v8-applicability-attested-default.md) | ADR-041 — v8.0.0: applicability engine and ATTESTED become the default | `unknown` |
| [042](adr-042-gemara-evaluation-log-export.md) | ADR-042 — Gemara Layer 5 Evaluation Log export format | `unknown` |
| [043](adr-043-remove-legacy-report-contracts.md) | ADR-043 — Remove the legacy pre-2.0 report contracts (v9.0.0) | `accepted` |
| [044](adr-044-unreadable-waivers-gate-fails-document-warns.md) | ADR-044 — An unreadable `--waivers` path fails a gate and warns a document | `accepted` |
| [045](adr-045-schema-invalid-evidence-is-manual-review-everywhere.md) | ADR-045 — Evidence that fails schema validation is `manual-review-required`... | `accepted` |

