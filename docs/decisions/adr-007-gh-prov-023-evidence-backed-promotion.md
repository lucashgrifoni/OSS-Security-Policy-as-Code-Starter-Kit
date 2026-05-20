# ADR-007 — Promote `GH-PROV-023` from `signal` to `evidence-backed`; CHANGELOG dedicated for `assurance_mix` shift

- **Status**: proposed (v6.0.0)
- **Date**: 2026-05-18
- **Context window**: v6.0.0 planning, Onda 3 (PR-12)
- **Related**: ADR-006 (SLSA Source Track), existing `PROV-VERIFY-061`, profiles `github-release-hardening-{1,2,3}` and `slsa-build-l2-1`

## Context

`GH-PROV-023` ships in v5.x as a `signal`-grade control that detects in-workflow provenance generation (presence of `actions/attest-build-provenance` or `sigstore/cosign-installer` plus `cosign sign-blob` in a publish workflow). It does not verify that the resulting attestation is well-formed, transparency-log included, or signed by the expected identity. Verification of that kind is the responsibility of the separately-shipped `PROV-VERIFY-061` (v5.1.0), which consumes a `verification:` block in the per-artifact provenance evidence file.

Adopters that ship signed releases today already produce the `verification:` block (it is filled after running `gh attestation verify` or `cosign verify-bundle`). The block contains enough information — `method`, `verified_at`, `transparency_log_inclusion`, optional `issuer` / `subject_alternative_name` / `bundle_digest` / `tool_version` — to upgrade `GH-PROV-023` from "the workflow generates provenance" to "the workflow generates provenance, and the most recent release attestation was independently verified".

The trade-off:

- **Upgrade**: `GH-PROV-023` consumes the same evidence file as `PROV-VERIFY-061` and projects an additional check (workflow-side generation + verification-side outcome). Profiles that bundle `GH-PROV-023` get stronger assurance per release.
- **Cost**: the upgrade changes the profile-level `assurance_mix` for any profile that bundles `GH-PROV-023`. Adopters who parse `assurance_mix` (some dashboards do) will see a shift in the next minor without a feature flag.

## Decision

**Promote `GH-PROV-023` from `signal` to `evidence-backed`** in v6.0.0. The control continues to detect the in-workflow generation signal (the signal-grade dimension is preserved as input), and additionally requires a fillable `verification:` block in the per-artifact provenance evidence file. When the block is present and valid, the control returns `evidence-backed pass`. When the block is absent, the control returns `manual-review-required` (does not regress to fail — adopters who relied on the signal-only behavior still get a non-blocking outcome until they add evidence).

A **dedicated CHANGELOG section** documents the `assurance_mix` shift for each affected profile and lists the new minimum evidence file requirement. Profiles affected: `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `slsa-build-l2-1`.

## Alternatives considered

1. **Leave `GH-PROV-023` as signal-grade and add a new `GH-PROV-VERIFY-024` evidence-backed control.** Rejected: duplicates `PROV-VERIFY-061` (which already consumes the verification block). Two controls on one evidence file is the duplication ADR-005 explicitly avoided.
2. **Promote without `manual-review-required` fallback.** Rejected: would silently change pass/fail outcomes for adopters who never created the evidence file. The fallback preserves the v5.x behavior at the gate level.
3. **Defer to v6.1.0.** Rejected: the `verification:` block already exists; the cost of waiting is artificially keeping `assurance_mix` lower than the underlying evidence justifies.

## Consequences

**Positive**

- Release-hardening ladders gain stronger per-release assurance evidence.
- The kit's evidence-backed control coverage grows without a new evidence schema.
- Single source of truth for the verification outcome (`verification:` block) — `GH-PROV-023` and `PROV-VERIFY-061` read the same file.

**Negative / cost**

- `assurance_mix` of four profiles shifts. Adopters that parse the JSON shape may need to refresh expectations.
- Adopters who never created the evidence file see `manual-review-required` instead of the previous `signal pass` — a documentation shift, not a gate regression.

**Mitigations**

- Dedicated CHANGELOG section enumerates the profiles affected and the `assurance_mix` delta.
- Migration note in `v6.0.0-migration-guide.md` describes how to populate the `verification:` block (one command: `gh attestation verify <artifact> --format json > tmp.json && jq '...'`).
- The `manual-review-required` fallback ensures CI gates do not regress silently.

## References

- v6.0.0 execution plan §5.3 PR-12
- v6.0.0 proposal §4 O-05
- Existing `PROV-VERIFY-061` evidence schema: `src/oss_policy_kit/data/schema/evidence-github-provenance-artifact.schema.json`
- ADR-002 (emit-vex scope) — related discussion of `assurance_mix`
