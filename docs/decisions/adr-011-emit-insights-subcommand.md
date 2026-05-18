# ADR-011 — `emit-insights` subcommand: emit OpenSSF Security Insights 1.0 YAML

- **Status**: proposed (v6.0.0)
- **Date**: 2026-05-18
- **Context window**: v6.0.0 planning, Onda 2 (PR-8)
- **Related**: ADR-002 (`emit-vex` scope), [OpenSSF Security Insights spec](https://security-insights.openssf.org/)

## Context

[OpenSSF Security Insights 1.0](https://security-insights.openssf.org/) is a YAML format that lets an OSS project publish machine-readable security metadata: security contacts, vulnerability reporting process, build provenance posture, dependency policy, distribution points. The format is stable since 2023 and is consumed by Scorecard v6, CLOMonitor, OSPS Baseline Scanner, and several ASPM platforms.

The kit already evaluates most of the signals Insights wants to expose — `SECURITY.md` presence, disclosure SLA, CONTRIBUTING, Dependabot/Renovate config, provenance verification posture. Adopters using the kit who also want to publish a `security-insights.yml` end up duplicating the work: the kit's `evaluation-report.json` says "yes, SECURITY.md is present at `.github/SECURITY.md`", and then a separate script translates that into the Insights vocabulary.

A first-party emitter avoids that duplication. The architectural parallel is `emit-vex` (ADR-002): a subcommand that re-projects evaluator outputs into an external standard format.

## Decision

Ship a new subcommand **`oss-policy-kit emit-insights`** that produces a `security-insights.yml` file conforming to OpenSSF Security Insights 1.0. The subcommand:

- Reuses **existing evaluators read-only** — no new controls are added.
- Outputs YAML validated (optionally) against the Insights 1.0 JSON Schema via `--validate`.
- Defaults the output path to `./security-insights.yml`; `--output <path>` overrides.
- Accepts `--target <path>` like other subcommands.
- Returns exit 0 on successful emission, 1 on validation failure (when `--validate` is passed), 2 on usage errors.

Signal-to-Insights field mapping is documented in the planned `docs/insights-emission.md` (parity with `docs/vex-emission.md`).

## Alternatives considered

1. **Add `security-insights-output` to the `evaluate` subcommand.** Rejected: bundles two concerns (gate evaluation vs. external emission). `emit-vex` set the precedent of dedicated emitters.
2. **Generate the YAML lazily from `evaluation-report.json`.** Rejected: would force adopters to run `evaluate` first; the emitter is conceptually independent of any gate decision.
3. **Defer to v6.1.0.** Rejected: Insights 1.0 is stable and broadly consumed; the emitter is a small, well-bounded addition that fits v6.0.0's market-positioning narrative (kit as local-first emit layer).

## Consequences

**Positive**

- Adopters using the kit gain a one-command Insights emitter that stays in sync with their evaluator outputs.
- Insights consumers (Scorecard v6, CLOMonitor, OSPS Baseline Scanner, ASPM platforms) gain another publisher.
- Architecturally aligned with `emit-vex`: re-projection of existing signals into a stable external format, zero new controls.

**Negative / cost**

- One new CLI subcommand (15 → 16; or 16 → 17 if `export-evidence` also lands per ADR-012).
- One new renderer module (`src/oss_policy_kit/emit/insights.py`).
- Test cost: golden-file snapshot test for `examples/hardened-repo` plus schema validation test.
- External spec dependency: if OpenSSF revises Insights to 2.0, the emitter needs an update path. Mitigation: detect schema version at emit time; ship 1.0 first; add 2.0 when the spec stabilizes.

**Mitigations**

- Schema version detection in the emitter (header field `schema-version: 1.0.0`).
- Golden snapshot test for the hardened example ensures stability across kit changes.
- `--validate` flag opt-in so adopters can choose to fail the emit step when the YAML drifts from the spec.

## References

- v6.0.0 execution plan §4.4 PR-8
- v6.0.0 proposal §3 V6-03
- [OpenSSF Security Insights spec](https://security-insights.openssf.org/) + [GitHub repo](https://github.com/ossf/security-insights)
- ADR-002 (`emit-vex` scope) — architectural precedent
