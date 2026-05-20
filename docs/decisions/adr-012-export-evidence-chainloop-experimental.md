# ADR-012 — `export-evidence --format chainloop`: experimental Chainloop attestation emitter

- **Status**: proposed (v6.0.0, marked experimental)
- **Date**: 2026-05-18
- **Context window**: v6.0.0 planning, Onda 4 (PR-17, carve-out aceito)
- **Related**: ADR-002 (`emit-vex` scope), ADR-011 (`emit-insights`), [Chainloop](https://chainloop.dev/)

## Context

[Chainloop](https://chainloop.dev/) is an open-source evidence platform with controlplane + database. It aggregates attestations, SBOMs, scan results, and policy verdicts emitted from CI pipelines and lets release reviewers query the corpus per artifact and per release. The relationship between Chainloop and this kit is composition, not competition (see [`positioning.md`](../positioning.md) → *Composition with Chainloop*): this kit is a **local-first emit layer**, Chainloop is the **server-side store**.

Adopters running both today end up writing glue code to translate the kit's `evaluation-report.json` + SARIF into the Chainloop attestation envelope. A first-party emitter removes that glue.

Two design tensions:

1. **Chainloop ingest spec may evolve.** Chainloop is pre-1.0; the attestation envelope shape has changed twice since 2024. Pinning to a current spec risks rework if the next breaking change lands during the v6.0.x window.
2. **Multi-format ambition.** Other evidence stores (GUAC, OSCAL-aligned platforms, in-toto-attestation Bundles) might want similar treatment. Building a `--format chainloop` subcommand without a clear pluggable format strategy could lock in a shape that is awkward for the next format.

## Decision

Ship a new subcommand **`oss-policy-kit export-evidence --format chainloop`** in v6.0.0, but **mark it experimental**:

- The subcommand surface (`export-evidence`, `--format`, `--output`, `--target`) is stable.
- The `chainloop` format output **may change** in v6.0.x if Chainloop maintainers revise their ingest spec. The CHANGELOG calls this out explicitly.
- The format is registered in a small registry (`src/oss_policy_kit/emit/exporters.py`) so future formats (`guac`, `oscal`, `in-toto-bundle`) can plug in without changing the CLI shape.
- `--format sarif` is also accepted (re-exports the SARIF the `evaluate` subcommand already produces); this gives format parity day one and exercises the registry with a second format.
- Stabilization commitment: promote `chainloop` from experimental to stable in v6.1.0 based on adopter feedback and Chainloop spec stability.

The `export-evidence` subcommand is a **carve-out candidate** in the v6.0.0 execution plan — if the 2026-08-02 window pressures the release, this PR moves to v6.1.0 without blocking AI-security or breaking-change work.

## Alternatives considered

1. **Ship Chainloop integration as a third-party module outside the kit.** Rejected: the glue is the same regardless of where it lives; first-party gives adopters one place to look.
2. **Pin to current Chainloop spec without "experimental" label.** Rejected: the spec is genuinely pre-1.0; an unmarked emitter would over-promise stability.
3. **Skip Chainloop, support GUAC instead.** Rejected: Chainloop has higher adopter overlap with this kit's audience (small-to-mid OSS teams emitting evidence); GUAC's audience is graph-database tooling for larger supply chains. GUAC is tracked for v6.1.0 if demand surfaces.

## Consequences

**Positive**

- Adopters running the kit + Chainloop gain a one-command bridge.
- Format registry pattern unblocks future emitters without CLI churn.
- "Experimental" label calibrates expectations honestly.

**Negative / cost**

- External spec dependency on Chainloop maintainers' roadmap.
- One new CLI subcommand and one new renderer module.
- Test cost: golden snapshot for the hardened example, plus a contract test against the current Chainloop spec.

**Mitigations**

- Marked experimental in CHANGELOG and `--help` text.
- Format registry isolates the chainloop-specific code from the subcommand shell.
- Tracker for adopter feedback opened separately so spec drift in Chainloop is surfaced early.
- Carve-out criterion documented: if Chainloop ships a breaking change before v6.0.0 GA, the format ships as `chainloop-v2024` for clarity, or moves to v6.1.0.

## References

- v6.0.0 execution plan §6.3 PR-17
- v6.0.0 proposal §5 V6-04
- [Chainloop repo](https://github.com/chainloop-dev/chainloop) + [Chainloop docs](https://chainloop.dev/)
- ADR-002 (`emit-vex`) and ADR-011 (`emit-insights`) — same emit-only pattern
